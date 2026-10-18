import type { Node } from 'web-tree-sitter';
import { type CallInfo, type FileContext, type LanguageSpec, matchesCustom } from '../languages/spec';
import { KIND_META } from '../rules';
import { CLEAN_UNARY_OPERATORS } from '../constants';
import type { Finding, LanguageId, OriginKind } from '../types';
import {
  CALL_TYPES,
  CLEAN_TYPES,
  FUNCTION_TYPES,
  MEMBER_TYPES,
  SUMMARY_FUNCTION_TYPES,
  calleePath,
  isAllowlistCheck,
  isShortEcho,
  named,
  short,
  step,
} from './ast-utils';
import { detectHardcodedSecret, extractSystemPromptTargets } from './llm-detectors';
import { Scope } from './scope';
import { type SinkOverrides, SinkReporter } from './sink-reporter';
import { type SharedState, type Summary } from './summary';
import { type T, addStep, createSourceTaint, union } from './taint';

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

export class Analyzer {
  private readonly reporter: SinkReporter;
  private readonly memo = new Map<number, T>();
  private scope = new Scope('<module>');
  private currentFn: Node | null = null;
  private readonly returns: T[] = [];

  constructor(
    private readonly input: AnalyzeInput,
    private readonly shared: SharedState = { summaries: new Map() },
    private readonly summaryTarget: Node | null = null,
  ) {
    this.reporter = new SinkReporter({
      file: input.file,
      language: input.language,
      rulePrefix: input.spec.rulePrefix,
    });
  }

  run(): Omit<Finding, 'fingerprint'>[] {
    this.ev(this.input.root);
    return this.reporter.getFindings();
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
        this.evAll(named(node));
        return null;

      case 'return_statement': {
        const t = this.evAll(named(node));
        if (this.summaryTarget && this.currentFn?.id === this.summaryTarget.id) {
          this.returns.push(t);
        }
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
      case 'string': {
        const secret = detectHardcodedSecret(node);
        if (secret) this.reporter.reportSecret(node, secret, this.scope.functionName);
        return this.evAll(
          named(node).filter((n) => n.type === 'interpolation'),
          true,
        );
      }
      case 'concatenated_string':
      case 'template_string':
      case 'encapsed_string':
      case 'heredoc':
      case 'heredoc_body': {
        const secret = detectHardcodedSecret(node);
        if (secret) this.reporter.reportSecret(node, secret, this.scope.functionName);
        return this.evAll(named(node), true);
      }
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

      case 'unary_expression':
      case 'unary_operator': {
        const op = node.childForFieldName('operator')?.text ?? node.children[0]?.text ?? '';
        if (CLEAN_UNARY_OPERATORS.has(op)) {
          return null;
        }
        return this.evAll(named(node));
      }
      case 'update_expression':
        return null;

      // JS: dangerouslySetInnerHTML={{ __html: x }}
      case 'pair': {
        const key = node.childForFieldName('key');
        const value = node.childForFieldName('value');
        const t = this.ev(value);
        this.ev(key);
        if (
          this.spec.family === 'javascript' &&
          key &&
          /^['"]?__html['"]?$/.test(key.text) &&
          value
        ) {
          this.checkSink('xss', value, node, 'dangerouslySetInnerHTML');
        }
        return t;
      }

      // PHP の出力・シェル・インクルード
      case 'echo_statement':
      case 'print_intrinsic': {
        for (const arg of named(node)) {
          this.checkSink('xss', arg, node, type === 'echo_statement' ? 'echo' : 'print');
        }
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
        this.checkSink(
          'cmdi',
          node,
          node,
          'バッククォート（シェル実行）',
          this.evAll(named(node), true),
        );
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
    if (op === '+' || op === '%' || op === '.') {
      return union(this.ev(left), this.ev(right), true);
    }
    if (op === '||' || op === '&&' || op === '??' || op === '?:' || op === 'or' || op === 'and') {
      return union(this.ev(left), this.ev(right));
    }
    this.ev(left);
    this.ev(right);
    return null;
  }

  private evConditional(node: Node): T {
    let condition = node.childForFieldName('condition');
    let consequence = node.childForFieldName('consequence') ?? node.childForFieldName('body');
    let alternative = node.childForFieldName('alternative');
    if (node.type === 'conditional_expression' && this.spec.family === 'python') {
      [consequence, condition, alternative] = named(node);
    }
    this.ev(condition);
    const thenTaint = this.ev(consequence);
    const elseTaint = this.ev(alternative);
    if (condition && consequence && isAllowlistCheck(condition, consequence.text)) {
      return elseTaint;
    }
    return union(thenTaint, elseTaint);
  }

  private evMember(node: Node): T {
    const path = calleePath(node);
    const src = this.spec.sourceForPath(path) ?? this.matchCustomSource(path);
    const object =
      node.childForFieldName('object') ?? node.childForFieldName('value') ?? named(node)[0] ?? null;
    const objectTaint = this.ev(object);
    for (const child of named(node)) if (child !== object) this.ev(child);
    if (src) return this.sourceTaint(node, src.kind, src.label);
    if (this.scope.has(path)) return this.scope.get(path);
    return objectTaint;
  }

  private matchCustomSource(path: string): { kind: 'user' | 'llm'; label: string } | null {
    for (const rule of this.input.ctx.customSources ?? []) {
      if (matchesCustom(path, [rule.pattern])) {
        return { kind: rule.kind ?? 'user', label: rule.label ?? rule.pattern };
      }
    }
    return null;
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

    if (this.spec.family === 'javascript' && left?.type === 'member_expression' && right) {
      const prop = left.childForFieldName('property')?.text ?? '';
      if (prop === 'innerHTML' || prop === 'outerHTML' || prop === 'srcdoc') {
        this.checkSink('xss', right, node, prop);
      }
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
    if (left) {
      this.bindPattern(left, t ? addStep(t, step(left, `ループ変数 ${short(left)}`)) : null);
    }
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
        } else if (
          arg.type === 'list_splat' ||
          arg.type === 'dictionary_splat' ||
          arg.type === 'spread_element'
        ) {
          const inner = named(arg)[0];
          if (inner) args.push(inner);
        } else {
          args.push(arg);
        }
      }
    }
    return {
      node,
      path,
      name,
      receiver,
      receiverNode,
      args,
      kwargs,
      isNew: node.type === 'new_expression' || node.type === 'object_creation_expression',
    };
  }

  private evCall(node: Node): T {
    const call = this.callInfo(node);
    const receiverTaint = this.ev(call.receiverNode);
    const callee = node.childForFieldName('function');
    if (callee && callee !== call.receiverNode) this.ev(callee);

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
    for (const sysTarget of extractSystemPromptTargets(call, this.spec, this.input.ctx)) {
      this.checkSink('prompti', sysTarget, node, `${call.path}（システムプロンプト）`);
    }
    for (const rule of this.input.ctx.customSinks ?? []) {
      if (matchesCustom(call.path, [rule.pattern])) {
        const targetArgs =
          rule.argIndex !== undefined
            ? call.args[rule.argIndex]
              ? [call.args[rule.argIndex]]
              : []
            : [...call.args, ...call.kwargs.values()];
        for (const arg of targetArgs) {
          this.checkSink(rule.category, arg, node, call.path, undefined, {
            ruleId: rule.ruleId,
            severity: rule.severity,
          });
        }
      }
    }

    const src = this.spec.sourceForCall(call, this.input.ctx) ?? this.matchCustomSource(call.path);
    if (src) return this.sourceTaint(node, src.kind, src.label);
    if (sink && (sink.kind === 'sqli' || sink.kind === 'cmdi' || sink.kind === 'fileinc')) {
      return null;
    }

    const sanitize = this.spec.sanitizerForCall(call, this.input.ctx);
    if (sanitize === 'all') return null;
    if (sanitize) {
      const t = union(receiverTaint, allArgs);
      if (!t) return null;
      return addStep(
        { ...t, sanitized: new Set([...t.sanitized, ...sanitize]) },
        step(
          node,
          `${call.path}(...) で無害化（${sanitize.map((k) => KIND_META[k].title).join('・')}）`,
        ),
      );
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
            {
              ...combined,
              built: combined.built || summary.built,
              sanitized: new Set([...combined.sanitized, ...summary.kinds]),
            },
            step(
              node,
              `${call.path}(...) で無害化（${summary.kinds.map((k) => KIND_META[k].title).join('・')}）`,
            ),
          );
      }
    }
    return addStep(
      { ...combined, uncertain: true },
      step(node, `${call.path}(...) を経由（無害化の有無は不明）`),
    );
  }

  // ---------------------------------------------------------------- 関数

  private analyzeFunction(node: Node, isRoute = false): void {
    const outer = this.scope;
    const outerFn = this.currentFn;
    this.currentFn = node;
    const name = this.functionName(node);
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
      if (
        body &&
        node.type === 'arrow_function' &&
        body.type !== 'statement_block' &&
        this.summaryTarget?.id === node.id
      ) {
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
        if (
          value &&
          name?.type === 'identifier' &&
          (value.type === 'arrow_function' || value.type === 'function_expression')
        ) {
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
    else if (t.sanitized.size > 0) {
      summary = { type: 'sanitizes', kinds: [...t.sanitized], built: t.built };
    } else {
      summary = { type: 'keep', built: t.built };
    }
    this.shared.summaries.set(fn.id, summary);
    return summary;
  }

  private functionName(node: Node): string {
    const own = node.childForFieldName('name');
    if (own) return own.text;
    const parent = node.parent;
    if (
      parent?.type === 'variable_declarator' ||
      parent?.type === 'assignment_expression' ||
      parent?.type === 'pair'
    ) {
      const n =
        parent.childForFieldName('name') ??
        parent.childForFieldName('left') ??
        parent.childForFieldName('key');
      if (n) return n.text;
    }
    return `<anonymous@${node.startPosition.row + 1}>`;
  }

  private bindParams(params: Node, isRoute: boolean): void {
    const nodes =
      params.type === 'identifier' || params.type === 'variable_name' ? [params] : named(params);
    for (const p of nodes) {
      const typeText = p.childForFieldName('type')?.text ?? '';
      const defaultValue = p.childForFieldName('value') ?? p.childForFieldName('default_value');
      const names = this.collectNames(p);
      const safe =
        /^\??(int|float|bool|number|boolean|double|UUID|uuid\.UUID|datetime|date)\??$/i.test(
          typeText.replace(/^:\s*/, ''),
        ) ||
        (defaultValue !== null &&
          /^(Depends|Security|BackgroundTasks)\(/.test(defaultValue.text));
      for (const n of names) {
        if (safe) {
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
          sanitized: new Set(),
          built: false,
          uncertain: false,
        });
      }
    }
  }

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
        const base =
          left.childForFieldName('value') ??
          left.childForFieldName('object') ??
          named(left)[0];
        if (base && t) {
          const key =
            base.type === 'identifier' || base.type === 'variable_name'
              ? base.text
              : calleePath(base);
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
    return createSourceTaint(kind, step(node, `${what}: ${label}`));
  }

  private checkSink(
    kind: Parameters<SinkReporter['checkSink']>[0],
    arg: Node,
    anchor: Node,
    label: string,
    precomputed?: T,
    overrides?: SinkOverrides,
  ): void {
    const t = precomputed !== undefined ? precomputed : this.ev(arg);
    this.reporter.checkSink(kind, arg, anchor, label, t, this.scope.functionName, overrides);
  }
}

