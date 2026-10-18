export type LanguageId = 'python' | 'javascript' | 'typescript' | 'tsx' | 'php';

/** 危険な処理（sink）および検出ルールの種類 */
export type SinkKind =
  | 'sqli'
  | 'cmdi'
  | 'codei'
  | 'deser'
  | 'xss'
  | 'ssti'
  | 'fileinc'
  | 'ssrf'
  | 'pathtrav'
  | 'prompti'
  | 'secret';

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Confidence = 'high' | 'medium' | 'low';

/**
 * 汚染の出どころ
 * - user: HTTP リクエスト等の外部入力（確定）
 * - llm: LLM の応答（LLM05: 不適切な出力処理）
 * - param: 関数の引数（呼び出し元が不明なため推定）
 */
export type OriginKind = 'user' | 'llm' | 'param';

export interface Position {
  /** 0 始まり */
  line: number;
  /** 0 始まり */
  column: number;
}

export interface Range {
  start: Position;
  end: Position;
}

export interface TraceStep {
  range: Range;
  /** 例: 「ユーザー入力 request.args.get(...)」「変数 q に代入」 */
  message: string;
}

export interface Finding {
  ruleId: string;
  kind: SinkKind | 'suppression';
  severity: Severity;
  confidence: Confidence;
  origin: OriginKind | 'none';
  /** 1 行の要約 */
  message: string;
  file: string;
  language: LanguageId;
  range: Range;
  /** 出どころ → 経由 → 危険な処理 の経路 */
  trace: TraceStep[];
  /** 囲んでいる関数名（ベースラインの指紋に使う） */
  functionName: string;
  /** 行番号に依存しない指紋。ベースライン照合に使う */
  fingerprint: string;
}

export interface SanitizerConfig {
  python?: string[];
  javascript?: string[];
  php?: string[];
}

export interface CustomSourceRule {
  pattern: string;
  kind?: 'user' | 'llm';
  label?: string;
}

export interface CustomSinkRule {
  pattern: string;
  category: SinkKind;
  ruleId?: string;
  severity?: Severity;
  argIndex?: number;
}

export interface CustomSourceConfig {
  python?: CustomSourceRule[];
  javascript?: CustomSourceRule[];
  php?: CustomSourceRule[];
}

export interface CustomSinkConfig {
  python?: CustomSinkRule[];
  javascript?: CustomSinkRule[];
  php?: CustomSinkRule[];
}

export interface ScanConfig {
  minConfidence: Confidence;
  failOn: Severity | 'none';
  baseline: string;
  exclude: string[];
  sanitizers: SanitizerConfig;
  sources?: CustomSourceConfig;
  sinks?: CustomSinkConfig;
}
