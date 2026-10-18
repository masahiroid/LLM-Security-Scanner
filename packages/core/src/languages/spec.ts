import type { Node } from 'web-tree-sitter';
import type { CustomSinkRule, CustomSourceRule, LanguageId, SinkKind } from '../types';

export type Family = 'python' | 'javascript' | 'php';

export function getLanguageFamily(lang: LanguageId): Family {
  return lang === 'python' ? 'python' : lang === 'php' ? 'php' : 'javascript';
}

export interface CallInfo {
  node: Node;
  /** 正規化した呼び出し先。例: "cursor.execute"、"client.chat.completions.create" */
  path: string;
  /** 最後の要素。例: "execute" */
  name: string;
  /** 最後の要素を除いた部分。例: "conn.cursor" */
  receiver: string;
  /** レシーバ式（メソッド呼び出しのとき） */
  receiverNode: Node | null;
  /** 位置引数 */
  args: Node[];
  /** キーワード引数（Python / PHP の名前付き引数） */
  kwargs: Map<string, Node>;
  isNew: boolean;
}

export interface SinkMatch {
  kind: SinkKind;
  /** 検査する引数 */
  args: Node[];
}

export interface SourceMatch {
  kind: 'user' | 'llm';
  label: string;
}

/** 無害化：'all' はすべての種類に対して安全、配列はその種類に対してのみ安全 */
export type SanitizeResult = 'all' | SinkKind[];

export interface FileContext {
  /** ソース全体に正規表現が一致するか（import の有無などの簡易判定。結果はファイルごとにキャッシュ） */
  mentions(re: RegExp): boolean;
  /** 設定ファイルで追加された無害化関数 */
  customSanitizers: string[];
  /** 設定ファイルで追加された汚染源 */
  customSources?: CustomSourceRule[];
  /** 設定ファイルで追加された危険なシンク関数 */
  customSinks?: CustomSinkRule[];
}

export interface LanguageSpec {
  family: Family;
  rulePrefix: string;
  commentPrefix: string;
  /** 呼び出しが入力の出どころか */
  sourceForCall(call: CallInfo, ctx: FileContext): SourceMatch | null;
  /** 属性アクセス・変数参照のパスが入力の出どころか（例: request.args、$_GET） */
  sourceForPath(path: string): SourceMatch | null;
  sinkForCall(call: CallInfo, ctx: FileContext): SinkMatch | null;
  sanitizerForCall(call: CallInfo, ctx: FileContext): SanitizeResult | null;
  /**
   * 汚染をそのまま伝える既知の関数か。
   * 'built' は文字列の組み立て（format / join 等）として扱う。
   */
  propagator(call: CallInfo): 'keep' | 'built' | null;
}

export function lastSegment(path: string): string {
  const i = path.lastIndexOf('.');
  return i < 0 ? path : path.slice(i + 1);
}

/** 設定の無害化関数（"app.security.escape" 等）と呼び出しパスを末尾一致で照合 */
export function matchesCustom(path: string, entries: string[]): boolean {
  for (const entry of entries) {
    const e = entry.replace(/\\/g, '.').replace(/::|->/g, '.').replace(/^\.+/, '');
    if (path === e || path.endsWith('.' + e) || e.endsWith('.' + path)) return true;
  }
  return false;
}
