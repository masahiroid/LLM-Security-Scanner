import type { Node } from 'web-tree-sitter';
import type { SinkKind } from '../types';

/**
 * 関数内部で引数が到達する危険な処理（Sink）の要約情報
 */
export interface FunctionSinkTarget {
  kind: SinkKind;
  sinkLabel: string;
}

/**
 * 関数の要約（引数 → 戻り値、および引数 → 内部Sink到達）
 * - clean: 戻り値は汚染されない
 * - sanitizes: 指定の種類について無害化して返す（自作のエスケープ関数など）
 * - keep: 引数の汚染をそのまま返す
 * - source: 関数内で外部入力・LLM 応答を取得して返す
 * - unknown: 判断できない
 */
export type Summary = (
  | { type: 'clean' }
  | { type: 'sanitizes'; kinds: SinkKind[]; built: boolean }
  | { type: 'keep'; built: boolean }
  | { type: 'source'; origin: 'user' | 'llm' }
  | { type: 'unknown' }
) & {
  sinks?: FunctionSinkTarget[];
};

export interface SharedState {
  summaries: Map<number, Summary | 'pending'>;
  functions?: Map<string, Node | null>;
  externalSummaries?: ReadonlyMap<string, Summary>;
}
