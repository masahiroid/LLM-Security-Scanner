import type { Node } from 'web-tree-sitter';
import { KIND_META, ruleIdFor, severityFor } from './rules';
import type { CallInfo, FileContext, LanguageSpec } from './languages/spec';
import type { Confidence, Finding, LanguageId, OriginKind, Range, SinkKind, TraceStep } from './types';

/** 汚染された値の情報。null は「汚染されていない」 */
interface Taint {
  origin: OriginKind;
  trace: TraceStep[];
  /** この種類の危険な処理に対しては無害化済み */
  sanitized: ReadonlySet<SinkKind>;
  /** 文字列の連結・埋め込みで組み立てられた値か */
  built: boolean;
  /** 無害化の有無が分からない関数を経由したか（確信度を下げる） */
  uncertain: boolean;
}
type T = Taint | null;

const ORIGIN_PRIORITY: Record<OriginKind, number> = { param: 0, user: 1, llm: 2 };
const MAX_TRACE = 12;
const NO_SANITIZE: ReadonlySet<SinkKind> = new Set();

const FUNCTION_TYPES = new Set([
  // Python
  'function_definition', 'lambda',
  // JS / TS
  'function_declaration', 'function_expression', 'function', 'arrow_function', 'method_definition',
  'generator_function_declaration', 'generator_function',
  // PHP（function_definition は Python と共通）
  'method_declaration', 'anonymous_function', 'anonymous_function_creation_expression',
]);

const CALL_TYPES = new Set([
  'call', 'call_expression', 'new_expression', 'function_call_expression', 'member_call_expression',
  'nullsafe_member_call_expression', 'scoped_call_expression', 'object_creation_expression',
]);

const MEMBER_TYPES = new Set([
  'attribute', 'member_expression', 'member_access_expression', 'nullsafe_member_access_expression',
  'scoped_property_access_expression', 'subscript', 'subscript_expression',
]);

/** 汚染しない（真偽値・数値を返す）式 */
const CLEAN_TYPES = new Set([
  'comparison_operator', 'not_operator', 'integer', 'float', 'number', 'true', 'false', 'none', 'null',
  'boolean', 'type_annotation', 'type', 'comment', 'decorator', 'import_statement', 'import_from_statement',
  'import_declaration', 'namespace_use_declaration', 'instanceof_expression', 'type_alias_declaration',
  'interface_declaration', 'enum_declaration',
]);

function short(node: Node): string {
  const text = node.text.replace(/\s+/g, ' ');
  return text.length > 60 ? text.slice(0, 57) + '...' : text;
}

function rangeOf(node: Node): Range {
  return {
    start: { line: node.startPosition.row, column: node.startPosition.column },
    end: { line: node.endPosition.row, column: node.endPosition.column },
  };
}

function step(node: Node, message: string): TraceStep {
  return { range: rangeOf(node), message };
}

function named(node: Node): Node[] {
  return node.namedChildren.filter((n): n is Node => n !== null && n.type !== 'comment');
}

function union(a: T, b: T, built = false): T {
  if (!a && !b) return null;
  if (!a || !b) {
    const t = (a ?? b)!;
    return built && !t.built ? { ...t, built: true } : t;
  }
  const primary = ORIGIN_PRIORITY[b.origin] > ORIGIN_PRIORITY[a.origin] ? b : a;
  const sanitized = new Set([...a.sanitized].filter((k) => b.sanitized.has(k)));
  return { ...primary, sanitized, built: built || a.built || b.built };
}

function addStep(t: T, s: TraceStep): T {
  if (!t) return null;
  const trace = t.trace.length >= MAX_TRACE ? [...t.trace.slice(0, 1), ...t.trace.slice(-(MAX_TRACE - 2)), s] : [...t.trace, s];
  return { ...t, trace };
}

/** 呼び出し先などを "a.b.c" 形式に正規化する */
export function calleePath(node: Node | null): string {
  if (!node) return '?';
  switch (node.type) {
    case 'identifier':
    case 'property_identifier':
    case 'private_property_identifier':
    case 'shorthand_property_identifier':
    case 'name':
    case 'this':
    case 'super':
    case 'type_identifier':
      return node.text;
    case 'variable_name':
      return node.text.replace(/^\$/, '');
    case 'qualified_name':
    case 'relative_name':
      return node.text.replace(/^\\/, '').replace(/\\/g, '.');
    case 'attribute':
      return `${calleePath(node.childForFieldName('object'))}.${node.childForFieldName('attribute')?.text ?? '?'}`;
    case 'member_expression':
      return `${calleePath(node.childForFieldName('object'))}.${node.childForFieldName('property')?.text ?? '?'}`;
    case 'member_access_expression':
    case 'nullsafe_member_access_expression':
    case 'member_call_expression':
    case 'nullsafe_member_call_expression':
      return `${calleePath(node.childForFieldName('object'))}.${calleePath(node.childForFieldName('name'))}`;
    case 'scoped_call_expression':
    case 'scoped_property_access_expression':
    case 'class_constant_access_expression': {
      const scope = node.childForFieldName('scope') ?? named(node)[0] ?? null;
      const name = node.childForFieldName('name') ?? named(node)[1] ?? null;
      return `${calleePath(scope)}.${calleePath(name)}`;
    }
    case 'subscript':
      return `${calleePath(node.childForFieldName('value'))}[]`;
    case 'subscript_expression':
      return `${calleePath(node.childForFieldName('object') ?? named(node)[0] ?? null)}[]`;
    case 'call':
    case 'call_expression':
      return calleePath(node.childForFieldName('function'));
    case 'function_call_expression':
      return calleePath(node.childForFieldName('function'));
    case 'new_expression':
      return calleePath(node.childForFieldName('constructor'));
    case 'parenthesized_expression':
    case 'await_expression':
    case 'non_null_expression':
    case 'as_expression':
    case 'satisfies_expression':
      return calleePath(named(node)[0] ?? null);
    default:
      return '?';
  }
}

/** 変数のスコープ。内側の関数は外側を parent として参照する（コピーしない） */
class Scope {
  private readonly vars = new Map<string, T>();

  constructor(
    readonly functionName: string,
    private readonly parent: Scope | null = null,
  ) {}

  has(name: string): boolean {
    return this.vars.has(name) || (this.parent?.has(name) ?? false);
  }

  get(name: string): T {
    if (this.vars.has(name)) return this.vars.get(name) ?? null;
    return this.parent ? this.parent.get(name) : null;
  }

  set(name: string, t: T): void {
    this.vars.set(name, t);
  }
}

/**
 * 同じファイル内で定義された関数の要約（引数 → 戻り値）
 * - clean: 戻り値は汚染されない
 * - sanitizes: 指定の種類について無害化して返す（自作のエスケープ関数など）
 * - keep: 引数の汚染をそのまま返す
 * - source: 関数内で外部入力・LLM 応答を取得して返す
 * - unknown: 判断できない
 */
type Summary =
  | { type: 'clean' }
  | { type: 'sanitizes'; kinds: SinkKind[]; built: boolean }
  | { type: 'keep'; built: boolean }
  | { type: 'source'; origin: 'user' | 'llm' }
  | { type: 'unknown' };

interface SharedState {
  summaries: Map<number, Summary | 'pending'>;
  functions?: Map<string, Node | null>;
}

const SUMMARY_FUNCTION_TYPES = new Set([
  'function_definition', 'function_declaration', 'generator_function_declaration', 'method_definition',
  'method_declaration',
]);

export interface AnalyzeInput {
  root: Node;
  file: string;
  language: LanguageId;
  spec: LanguageSpec;
  ctx: FileContext;
}

/** 1 ファイルを解析して指摘を返す（指紋・抑制は呼び出し側で付与） */
export function analyze(input: AnalyzeInput): Omit<Finding, 'fingerprint'>[] {
  return new Analyzer(input).run();
}

class Analyzer {
  private readonly findings: Omit<Finding, 'fingerprint'>[] = [];
  private readonly reported = new Set<string>();
  private readonly memo = new Map<number, T>();
  private scope = new Scope('<module>');
  /** 解析中の関数 */
  private currentFn: Node | null = null;
  /** 要約対象の関数の return で返る値 */
  private readonly returns: T[] = [];

  constructor(
    private readonly input: AnalyzeInput,
    private readonly shared: SharedState = { summaries: new Map() },
    private readonly summaryTarget: Node | null = null,
  ) {}

  run(): Omit<Finding, 'fingerprint'>[] {
    this.ev(this.input.root);
    return this.findings;
  }

  private get spec(): LanguageSpec {
    return this.input.spec;
  }

  // ---------------------------------------------------------------- 式の評価

  private ev(node: Node | null): T {
    if (!node) return null;
    if (this.memo.has(node.id)) return this.memo.get(node.id) ?? null;
    const result = this.evInner(node);
    this.memo.set(node.id, result);
    return result;
  }

  private evAll(nodes: Node[], built = false): T {
    let t: T = null;
    for (const n of nodes) t = union(t, this.ev(n), built);
    return t;
  }

  private evInner(node: Node): T {
    const type = node.type;
    if (CLEAN_TYPES.has(type)) return null;
    if (FUNCTION_TYPES.has(type)) {
      this.analyzeFunction(node);
      return null;
    }
    if (CALL_TYPES.has(type)) return this.evCall(node);
    if (MEMBER_TYPES.has(type)) return this.evMember(node);

    switch (type) {
      case 'decorated_definition':
        return this.evDecorated(node);
      case 'class_definition':
      case 'class_declaration':
      case 'class':
        // クラス本体のメソッドはそれぞれ独立した関数として解析する
        this.evAll(named(node));
        return null;

      case 'return_statement': {
        const t = this.evAll(named(node));
        if (this.summaryTarget && this.currentFn?.id === this.summaryTarget.id) this.returns.push(t);
        return t;
      }

      case 'identifier':
      case 'shorthand_property_identifier':
        return this.lookup(node.text);
      case 'variable_name': {
        const name = node.text.replace(/^\$/, '');
        const src = this.spec.sourceForPath(name);
        if (src) return this.sourceTaint(node, src.kind, src.label);
        return this.lookup(node.text);
      }

      // 代入
      case 'assignment':
      case 'variable_declarator':
      case 'assignment_expression':
      case 'reference_assignment_expression':
        return this.evAssign(node, false);
      case 'augmented_assignment':
      case 'augmented_assignment_expression':
        return this.evAssign(node, true);
      case 'named_expression': {
        const t = this.ev(node.childForFieldName('value'));
        this.bindPattern(node.childForFieldName('name'), t);
        return t;
      }

      // ループ変数
      case 'for_statement':
      case 'for_in_statement':
      case 'for_in_clause':
        return this.evFor(node);
      case 'foreach_statement':
        return this.evForeach(node);

      // 文字列の組み立て
      case 'string':
        return this.evAll(named(node).filter((n) => n.type === 'interpolation'), true);
      case 'concatenated_string':
      case 'template_string':
      case 'encapsed_string':
      case 'heredoc':
      case 'heredoc_body':
        return this.evAll(named(node), true);
      case 'binary_operator':
      case 'binary_expression':
        return this.evBinary(node);
      case 'boolean_operator':
        return this.evAll(named(node));

      case 'conditional_expression':
      case 'ternary_expression':
        return this.evConditional(node);

      case 'cast_expression': {
        const castType = node.childForFieldName('type')?.text ?? '';
        const value = this.ev(node.childForFieldName('value'));
        return /int|float|double|bool/i.test(castType) ? null : value;
      }

      // JS: dangerouslySetInnerHTML={{ __html: x }}
      case 'pair': {
        const key = node.childForFieldName('key');
        const value = node.childForFieldName('value');
        const t = this.ev(value);
        this.ev(key);
        if (this.spec.family === 'javascript' && key && /^['"]?__html['"]?$/.test(key.text) && value) {
          this.checkSink('xss', value, node, 'dangerouslySetInnerHTML');
        }
        return t;
      }

      // PHP の出力・シェル・インクルード
      case 'echo_statement':
      case 'print_intrinsic': {
        for (const arg of named(node)) this.checkSink('xss', arg, node, type === 'echo_statement' ? 'echo' : 'print');
        return null;
      }
      case 'expression_statement': {
        if (this.spec.family === 'php' && isShortEcho(node)) {
          for (const arg of named(node)) this.checkSink('xss', arg, node, '<?=');
          return null;
        }
        return this.evAll(named(node));
      }
      case 'shell_command_expression':
        this.checkSink('cmdi', node, node, 'バッククォート（シェル実行）', this.evAll(named(node), true));
        return null;
      case 'include_expression':
      case 'include_once_expression':
      case 'require_expression':
      case 'require_once_expression': {
        const target = named(node)[0];
        if (target) this.checkSink('fileinc', target, node, node.text.split(/[\s(]/)[0]);
        return null;
      }

      default:
        return this.evAll(named(node));
    }
  }

  private evBinary(node: Node): T {
    const op = node.childForFieldName('operator')?.text ?? '';
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');
    if (op === '+' || op === '%' || op === '.') return union(this.ev(left), this.ev(right), true);
    if (op === '||' || op === '&&' || op === '??' || op === '?:' || op === 'or' || op === 'and') {
      return union(this.ev(left), this.ev(right));
    }
    // 比較・算術は真偽値・数値になるため汚染を伝えない（内部の危険な処理の検査のため評価だけはする）
    this.ev(left);
    this.ev(right);
    return null;
  }

  /**
   * 三項演算子。`in_array($x, LIST) ? $x : 既定値` / `x if x in LIST else 既定値` /
   * `LIST.includes(x) ? x : 既定値` のような許可リスト検証は、検証した値を安全とみなす。
   */
  private evConditional(node: Node): T {
    let condition = node.childForFieldName('condition');
    let consequence = node.childForFieldName('consequence') ?? node.childForFieldName('body');
    let alternative = node.childForFieldName('alternative');
    if (node.type === 'conditional_expression' && this.spec.family === 'python') {
      // Python: <body> if <condition> else <alternative>
      [consequence, condition, alternative] = named(node);
    }
    this.ev(condition);
    const thenTaint = this.ev(consequence);
    const elseTaint = this.ev(alternative);
    if (condition && consequence && isAllowlistCheck(condition, consequence.text)) return elseTaint;
    return union(thenTaint, elseTaint);
  }

  private evMember(node: Node): T {
    const path = calleePath(node);
    const src = this.spec.sourceForPath(path);
    // 内側の式は評価しておく（入れ子の危険な処理の検査のため）
    const object =
      node.childForFieldName('object') ?? node.childForFieldName('value') ?? named(node)[0] ?? null;
    const objectTaint = this.ev(object);
    for (const child of named(node)) if (child !== object) this.ev(child);
    if (src) return this.sourceTaint(node, src.kind, src.label);
    if (this.scope.has(path)) return this.scope.get(path);
    return objectTaint;
  }

  private evDecorated(node: Node): T {
    const def = node.childForFieldName('definition');
    const isRoute = named(node).some(
      (d) =>
        d.type === 'decorator' &&
        /\.(get|post|put|delete|patch|route|api_route|websocket|head|options)\s*\(/.test(d.text),
    );
    if (def && def.type === 'function_definition') {
      this.analyzeFunction(def, isRoute);
      this.memo.set(def.id, null);
      return null;
    }
    return this.ev(def);
  }

  private evAssign(node: Node, augmented: boolean): T {
    const left = node.childForFieldName('left') ?? node.childForFieldName('name');
    const right = node.childForFieldName('right') ?? node.childForFieldName('value');
    let t = this.ev(right);

    // JS: el.innerHTML = x
    if (this.spec.family === 'javascript' && left?.type === 'member_expression' && right) {
      const prop = left.childForFieldName('property')?.text ?? '';
      if (prop === 'innerHTML' || prop === 'outerHTML') this.checkSink('xss', right, node, prop);
      if (prop === 'srcdoc') this.checkSink('xss', right, node, prop);
    }

    if (augmented && left) t = union(this.ev(left), t, true);
    if (left) {
      const name = this.bindingName(left);
      t = t && name ? addStep(t, step(node, `${name} に代入`)) : t;
      this.bindPattern(left, t, augmented);
    }
    return t;
  }

  private evFor(node: Node): T {
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');
    const t = this.ev(right);
    if (left) this.bindPattern(left, t ? addStep(t, step(left, `ループ変数 ${short(left)}`)) : null);
    for (const child of named(node)) if (child !== left && child !== right) this.ev(child);
    return null;
  }

  private evForeach(node: Node): T {
    const parts = named(node);
    const iterable = parts[0];
    const t = this.ev(iterable ?? null);
    const binding = parts[1];
    if (binding) {
      const targets = binding.type === 'pair' ? named(binding) : [binding];
      for (const target of targets) this.bindPattern(target, t);
    }
    for (const child of parts.slice(2)) this.ev(child);
    return null;
  }

  // ---------------------------------------------------------------- 呼び出し

  private callInfo(node: Node): CallInfo {
    let callee: Node | null = null;
    let receiverNode: Node | null = null;
    let argsNode: Node | null = node.childForFieldName('arguments');
    let path: string;
    let name: string;
    let receiver = '';

    switch (node.type) {
      case 'member_call_expression':
      case 'nullsafe_member_call_expression':
      case 'scoped_call_expression': {
        receiverNode = node.childForFieldName('object') ?? node.childForFieldName('scope');
        receiver = calleePath(receiverNode);
        name = node.childForFieldName('name')?.text ?? '?';
        path = `${receiver}.${name}`;
        if (node.type === 'scoped_call_expression') receiverNode = null;
        break;
      }
      case 'object_creation_expression': {
        callee = named(node).find((n) => n.type !== 'arguments') ?? null;
        argsNode = named(node).find((n) => n.type === 'arguments') ?? null;
        path = calleePath(callee);
        name = path.split('.').pop() ?? path;
        break;
      }
      default: {
        callee = node.childForFieldName('function') ?? node.childForFieldName('constructor');
        path = calleePath(callee);
        name = path.split('.').pop() ?? path;
        if (callee && (callee.type === 'attribute' || callee.type === 'member_expression')) {
          receiverNode = callee.childForFieldName('object');
          receiver = path.slice(0, path.length - name.length - 1);
        }
      }
    }

    const args: Node[] = [];
    const kwargs = new Map<string, Node>();
    if (argsNode && argsNode.type !== 'template_string') {
      for (const arg of named(argsNode)) {
        if (arg.type === 'keyword_argument') {
          const k = arg.childForFieldName('name')?.text;
          const v = arg.childForFieldName('value');
          if (k && v) kwargs.set(k, v);
        } else if (arg.type === 'argument') {
          const inner = named(arg);
          const value = inner[inner.length - 1];
          const argName = arg.childForFieldName('name');
          if (value && argName && value !== argName) kwargs.set(argName.text, value);
          else if (value) args.push(value);
        } else if (arg.type === 'list_splat' || arg.type === 'dictionary_splat' || arg.type === 'spread_element') {
          const inner = named(arg)[0];
          if (inner) args.push(inner);
        } else {
          args.push(arg);
        }
      }
    }
    return { node, path, name, receiver, receiverNode, args, kwargs, isNew: node.type === 'new_expression' || node.type === 'object_creation_expression' };
  }

  private evCall(node: Node): T {
    const call = this.callInfo(node);
    const receiverTaint = this.ev(call.receiverNode);
    // 呼び出し先の式の中（a(b).c() の a(b) 等）も評価する
    const callee = node.childForFieldName('function');
    if (callee && callee !== call.receiverNode) this.ev(callee);

    // JS のタグ付きテンプレート（sql`...`、Prisma.$queryRaw`...`）はライブラリ側でエスケープされる
    const argsNode = node.childForFieldName('arguments');
    if (argsNode?.type === 'template_string') {
      this.evAll(named(argsNode));
      return null;
    }

    const argTaints = call.args.map((a) => this.ev(a));
    const kwTaints = [...call.kwargs.values()].map((a) => this.ev(a));
    const allArgs = [...argTaints, ...kwTaints].reduce<T>((acc, t) => union(acc, t), null);

    const sink = this.spec.sinkForCall(call, this.input.ctx);
    if (sink) {
      for (const arg of sink.args) this.checkSink(sink.kind, arg, node, call.path);
    }

    const src = this.spec.sourceForCall(call, this.input.ctx);
    if (src) return this.sourceTaint(node, src.kind, src.label);
    // SQL・コマンドの実行結果は引数の汚染を引き継がない（取得したデータは別途検査対象外）
    if (sink && (sink.kind === 'sqli' || sink.kind === 'cmdi' || sink.kind === 'fileinc')) return null;

    const sanitize = this.spec.sanitizerForCall(call, this.input.ctx);
    if (sanitize === 'all') return null;
    if (sanitize) {
      const t = union(receiverTaint, allArgs);
      if (!t) return null;
      return addStep({ ...t, sanitized: new Set([...t.sanitized, ...sanitize]) }, step(node, `${call.path}(...) で無害化（${sanitize.map((k) => KIND_META[k].title).join('・')}）`));
    }

    const combined = union(receiverTaint, allArgs);
    const prop = this.spec.propagator(call);
    const summary = prop ? null : this.summaryFor(call);
    if (summary?.type === 'source') {
      return this.sourceTaint(node, summary.origin, `${call.path}()（関数内で取得）`);
    }
    if (!combined) return null;
    if (prop === 'keep') return combined;
    if (prop === 'built') return union(combined, null, true);
    if (summary) {
      switch (summary.type) {
        case 'clean':
          return null;
        case 'keep':
          return union(combined, null, summary.built);
        case 'sanitizes':
          return addStep(
            { ...combined, built: combined.built || summary.built, sanitized: new Set([...combined.sanitized, ...summary.kinds]) },
            step(node, `${call.path}(...) で無害化（${summary.kinds.map((k) => KIND_META[k].title).join('・')}）`),
          );
      }
    }
    // 無害化するか分からない関数を経由：汚染は伝えるが確信度を下げる
    return addStep({ ...combined, uncertain: true }, step(node, `${call.path}(...) を経由（無害化の有無は不明）`));
  }

  // ---------------------------------------------------------------- 関数

  private analyzeFunction(node: Node, isRoute = false): void {
    const outer = this.scope;
    const outerFn = this.currentFn;
    this.currentFn = node;
    const name = this.functionName(node);
    // PHP の関数・メソッドは外側の変数を参照しない（クロージャは use 句の変数のみ）
    const isolated = this.spec.family === 'php' && node.type !== 'arrow_function';
    this.scope = new Scope(name, isolated ? null : outer);
    if (isolated) {
      for (const use of named(node).filter((n) => n.type === 'anonymous_function_use_clause')) {
        for (const v of this.collectNames(use)) this.scope.set(v, outer.get(v));
      }
    }
    try {
      const params =
        node.childForFieldName('parameters') ?? node.childForFieldName('parameter') ?? null;
      if (params) this.bindParams(params, isRoute);
      const body = node.childForFieldName('body');
      const bodyTaint = this.ev(body);
      // 式本体のアロー関数（x => x.trim()）は本体の値が戻り値
      if (body && node.type === 'arrow_function' && body.type !== 'statement_block' && this.summaryTarget?.id === node.id) {
        this.returns.push(bodyTaint);
      }
      for (const child of named(node)) {
        if (child !== params && child !== body && child.type !== 'decorator') this.ev(child);
      }
    } finally {
      this.scope = outer;
      this.currentFn = outerFn;
    }
  }

  // ---------------------------------------------------------------- 関数の要約

  /** 同じファイル内の関数を名前で引けるようにする（同名が複数ある場合は使わない） */
  private functionIndex(): Map<string, Node | null> {
    if (this.shared.functions) return this.shared.functions;
    const index = new Map<string, Node | null>();
    const add = (name: string, fn: Node) => index.set(name, index.has(name) ? null : fn);
    const visit = (n: Node) => {
      if (SUMMARY_FUNCTION_TYPES.has(n.type)) {
        const name = n.childForFieldName('name')?.text;
        if (name) add(name, n);
      } else if (n.type === 'variable_declarator') {
        const value = n.childForFieldName('value');
        const name = n.childForFieldName('name');
        if (value && name?.type === 'identifier' && (value.type === 'arrow_function' || value.type === 'function_expression')) {
          add(name.text, value);
        }
      }
      for (const c of named(n)) visit(c);
    };
    visit(this.input.root);
    this.shared.functions = index;
    return index;
  }

  private summaryFor(call: CallInfo): Summary | null {
    const m = /^(?:(?:this|self|static|parent|cls)\.)?([A-Za-z_$][\w$]*)$/.exec(call.path);
    if (!m) return null;
    const fn = this.functionIndex().get(m[1]);
    if (!fn) return null;
    const cached = this.shared.summaries.get(fn.id);
    if (cached === 'pending') return { type: 'unknown' };
    if (cached) return cached;

    this.shared.summaries.set(fn.id, 'pending');
    const sub = new Analyzer(this.input, this.shared, fn);
    sub.analyzeFunction(fn);
    let t: T = null;
    for (const r of sub.returns) t = union(t, r);
    let summary: Summary;
    if (!t) summary = { type: 'clean' };
    else if (t.origin !== 'param') summary = { type: 'source', origin: t.origin };
    else if (t.uncertain) summary = { type: 'unknown' };
    else if (t.sanitized.size > 0) summary = { type: 'sanitizes', kinds: [...t.sanitized], built: t.built };
    else summary = { type: 'keep', built: t.built };
    this.shared.summaries.set(fn.id, summary);
    return summary;
  }

  private functionName(node: Node): string {
    const own = node.childForFieldName('name');
    if (own) return own.text;
    const parent = node.parent;
    if (parent?.type === 'variable_declarator' || parent?.type === 'assignment_expression' || parent?.type === 'pair') {
      const n = parent.childForFieldName('name') ?? parent.childForFieldName('left') ?? parent.childForFieldName('key');
      if (n) return n.text;
    }
    return `<anonymous@${node.startPosition.row + 1}>`;
  }

  private bindParams(params: Node, isRoute: boolean): void {
    const nodes = params.type === 'identifier' || params.type === 'variable_name' ? [params] : named(params);
    for (const p of nodes) {
      const typeText = p.childForFieldName('type')?.text ?? '';
      const defaultValue = p.childForFieldName('value') ?? p.childForFieldName('default_value');
      const names = this.collectNames(p);
      const safe =
        /^\??(int|float|bool|number|boolean|double|UUID|uuid\.UUID|datetime|date)\??$/i.test(typeText.replace(/^:\s*/, '')) ||
        (defaultValue !== null && /^(Depends|Security|BackgroundTasks)\(/.test(defaultValue.text));
      for (const n of names) {
        if (safe) {
          // 外側の同名変数を隠す
          this.scope.set(n, null);
          continue;
        }
        const bare = n.replace(/^\$/, '');
        if (/^(self|cls|this|res|response|next|db|session)$/.test(bare)) continue;
        const kind: OriginKind = isRoute && !/^(request|req)$/.test(bare) ? 'user' : 'param';
        const label = isRoute ? `ルートの引数 ${bare}` : `関数の引数 ${bare}`;
        this.scope.set(n, {
          origin: kind,
          trace: [step(p, label)],
          sanitized: NO_SANITIZE,
          built: false,
          uncertain: false,
        });
      }
    }
  }

  /** 引数・分割代入のパターンから束縛される名前を集める */
  private collectNames(node: Node): string[] {
    switch (node.type) {
      case 'identifier':
      case 'shorthand_property_identifier_pattern':
      case 'variable_name':
        return [node.text];
      case 'this':
        return [];
    }
    const out: string[] = [];
    const skip = new Set<number>();
    for (const field of ['type', 'value', 'right', 'key', 'default_value', 'attribute']) {
      const f = node.childForFieldName(field);
      if (f && !(node.type === 'pair_pattern' && field === 'value')) skip.add(f.id);
    }
    if (node.type === 'assignment_pattern' || node.type === 'object_assignment_pattern') {
      const left = node.childForFieldName('left');
      return left ? this.collectNames(left) : [];
    }
    for (const child of named(node)) {
      if (skip.has(child.id)) continue;
      out.push(...this.collectNames(child));
    }
    return out;
  }

  // ---------------------------------------------------------------- 変数

  private lookup(name: string): T {
    return this.scope.get(name);
  }

  private bindingName(left: Node): string | null {
    if (left.type === 'identifier' || left.type === 'variable_name') return left.text;
    if (MEMBER_TYPES.has(left.type)) return calleePath(left);
    return null;
  }

  private bindPattern(left: Node | null, t: T, augmented = false): void {
    if (!left) return;
    switch (left.type) {
      case 'identifier':
      case 'variable_name':
        this.scope.set(left.text, t);
        return;
      case 'attribute':
      case 'member_expression':
      case 'member_access_expression':
      case 'scoped_property_access_expression':
        this.scope.set(calleePath(left), t);
        return;
      case 'subscript':
      case 'subscript_expression': {
        // d["k"] = x は d 全体を汚染されたものとして扱う
        const base = left.childForFieldName('value') ?? left.childForFieldName('object') ?? named(left)[0];
        if (base && t) {
          const key = base.type === 'identifier' || base.type === 'variable_name' ? base.text : calleePath(base);
          this.scope.set(key, union(this.scope.get(key), t));
        }
        return;
      }
      default:
        for (const n of this.collectNames(left)) {
          this.scope.set(n, augmented ? union(this.scope.get(n), t) : t);
        }
    }
  }

  // ---------------------------------------------------------------- 出どころ・危険な処理

  private sourceTaint(node: Node, kind: 'user' | 'llm', label: string): T {
    const what = kind === 'llm' ? 'LLM の応答' : 'ユーザー入力';
    return { origin: kind, trace: [step(node, `${what}: ${label}`)], sanitized: NO_SANITIZE, built: false, uncertain: false };
  }

  private checkSink(kind: SinkKind, arg: Node, anchor: Node, label: string, precomputed?: T): void {
    const t = precomputed !== undefined ? precomputed : this.ev(arg);
    if (!t || t.sanitized.has(kind)) return;
    const confidence = confidenceOf(t, kind);
    const meta = KIND_META[kind];
    const ruleId = ruleIdFor(kind, t.origin, this.spec.rulePrefix);
    const key = `${ruleId}:${arg.startIndex}:${arg.endIndex}`;
    if (this.reported.has(key)) return;
    this.reported.add(key);

    const subject =
      t.origin === 'llm' ? 'LLM の応答' : t.origin === 'user' ? 'ユーザー入力' : '関数の引数';
    const how = t.built ? 'を組み立てた文字列' : '';
    const prefix = t.origin === 'llm' ? `[LLM05 不適切な出力処理 / ${meta.title}]` : `[${meta.title}]`;
    const tail =
      t.origin === 'param' ? '。呼び出し元で外部入力が渡ると危険です' : t.uncertain ? '（途中の関数で無害化されていれば問題ありません）' : '';

    this.findings.push({
      ruleId,
      kind,
      severity: severityFor(kind, t.origin),
      confidence,
      origin: t.origin,
      message: `${prefix} ${subject}${how}が ${label} に渡されています${tail}`,
      file: this.input.file,
      language: this.input.language,
      range: rangeOf(arg),
      trace: [...t.trace, step(anchor, `危険な処理: ${label}`)],
      functionName: this.scope.functionName,
    });
  }
}

const ALLOWLIST_CALL = /^(in_array|array_key_exists|isset)\s*\(|\.(includes|has|hasOwnProperty)\s*\(/;

/** 条件が value を許可リストと照合しているか */
function isAllowlistCheck(condition: Node, value: string): boolean {
  const text = condition.text.replace(/\s+/g, ' ');
  if (!value || !/^[$\w.]+$/.test(value)) return false;
  const escaped = value.replace(/[$.]/g, (c) => '\\' + c);
  // Python: x in ALLOWED
  if (new RegExp(`^${escaped} in \\w`).test(text)) return true;
  if (!ALLOWLIST_CALL.test(text)) return false;
  // in_array($x, ...) / array_key_exists($x, ...) / LIST.includes(x)
  return new RegExp(`(\\(|, ?)${escaped}\\s*[,)]`).test(text);
}

/** PHP の <?= ... ?> の式か */
function isShortEcho(node: Node): boolean {
  let prev = node.previousSibling;
  if (prev?.type === 'text_interpolation') prev = prev.lastChild;
  return prev?.type === 'php_tag' && prev.text.startsWith('<?=');
}

function confidenceOf(t: Taint, kind: SinkKind): Confidence {
  if (t.origin === 'param') {
    // 引数から HTML を組み立てるのはよくある書き方で、多くは信頼できるデータのため low に留める
    if (!t.built || kind === 'xss') return 'low';
    return t.uncertain ? 'low' : 'medium';
  }
  return t.uncertain ? 'medium' : 'high';
}
