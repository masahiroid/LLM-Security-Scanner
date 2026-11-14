import { triageContextBounds } from './triage-context';
import type { Finding, TriageRequestInput } from './types';

/** 静的解析の指摘から AI トリアージ入力を組み立てる（ファイルパスは含めない） */
export async function triageInputForFinding(finding: Finding, sourceText: string, isJa = true): Promise<TriageRequestInput> {
  const bounds = await triageContextBounds(sourceText, finding.language, finding.range.start.line, finding.range.start.column);
  return {
    ruleId: finding.ruleId,
    severity: finding.severity,
    message: finding.message,
    filePath: '',
    language: finding.language,
    startLine: finding.range.start.line + 1,
    endLine: finding.range.end.line + 1,
    trace: finding.trace.map((step) => step.message),
    sourceText,
    isJa,
    ...bounds,
  };
}
