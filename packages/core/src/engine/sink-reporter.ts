import type { Node } from 'web-tree-sitter';
import { KIND_META, ruleIdFor, severityFor } from '../rules';
import type { Finding, LanguageId, Severity, SinkKind } from '../types';
import { rangeOf, step } from './ast-utils';
import { confidenceOf } from './confidence';
import type { Taint } from './taint';

export interface SinkReportTarget {
  file: string;
  language: LanguageId;
  rulePrefix: string;
}

export interface SinkOverrides {
  ruleId?: string;
  severity?: Severity;
}

/**
 * 脆弱性（Sink到達）の検査と指摘生成・重複抑止を担当するレポーター
 */
export class SinkReporter {
  private readonly findings: Omit<Finding, 'fingerprint'>[] = [];
  private readonly reported = new Set<string>();

  constructor(private readonly target: SinkReportTarget) {}

  getFindings(): Omit<Finding, 'fingerprint'>[] {
    return this.findings;
  }

  checkSink(
    kind: SinkKind,
    arg: Node,
    anchor: Node,
    label: string,
    t: Taint | null,
    currentFunctionName: string,
    overrides?: SinkOverrides,
  ): void {
    if (!t || t.sanitized.has(kind)) return;

    const ruleId = overrides?.ruleId ?? ruleIdFor(kind, t.origin, this.target.rulePrefix);
    const dedupeKey = `${ruleId}:${arg.startIndex}:${arg.endIndex}`;
    if (this.reported.has(dedupeKey)) return;
    this.reported.add(dedupeKey);

    const confidence = confidenceOf(t, kind);
    const meta = KIND_META[kind];

    const subject =
      t.origin === 'llm' ? 'LLM の応答' : t.origin === 'user' ? 'ユーザー入力' : '関数の引数';
    const how = t.built ? 'を組み立てた文字列' : '';
    const prefix =
      kind === 'prompti'
        ? `[LLM01 プロンプトインジェクション / ${meta.title}]`
        : t.origin === 'llm'
          ? `[LLM05 不適切な出力処理 / ${meta.title}]`
          : `[${meta.title}]`;
    const tail =
      t.origin === 'param'
        ? '。呼び出し元で外部入力が渡ると危険です'
        : t.uncertain
          ? '（途中の関数で無害化されていれば問題ありません）'
          : '';

    this.findings.push({
      ruleId,
      kind,
      severity: overrides?.severity ?? severityFor(kind, t.origin),
      confidence,
      origin: t.origin,
      message: `${prefix} ${subject}${how}が ${label} に渡されています${tail}`,
      file: this.target.file,
      language: this.target.language,
      range: rangeOf(arg),
      trace: [...t.trace, step(anchor, `危険な処理: ${label}`)],
      functionName: currentFunctionName,
    });
  }

  /**
   * ハードコードされた API キー・シークレット（OWASP LLM02）を報告する
   */
  reportSecret(node: Node, maskedKey: string, currentFunctionName: string): void {
    const kind: SinkKind = 'secret';
    const ruleId = ruleIdFor(kind, 'user', this.target.rulePrefix);
    const dedupeKey = `${ruleId}:${node.startIndex}:${node.endIndex}`;
    if (this.reported.has(dedupeKey)) return;
    this.reported.add(dedupeKey);

    const meta = KIND_META[kind];
    this.findings.push({
      ruleId,
      kind,
      severity: meta.baseSeverity,
      confidence: 'high',
      origin: 'user',
      message: `[LLM02 機密情報の漏洩 / ${meta.title}] ソースコード内に API キー（${maskedKey}）が直接記述されています`,
      file: this.target.file,
      language: this.target.language,
      range: rangeOf(node),
      trace: [step(node, `ハードコードされた機密情報: ${maskedKey}`)],
      functionName: currentFunctionName,
    });
  }
}

