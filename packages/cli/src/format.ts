import { LLMSCAN_VERSION, toSarif, type Severity, type TriageVerdict } from '@llmscan/core';
import type { OutputFormat } from './constants';
import type { Item } from './types';

const SEV_LABEL: Record<Severity, string> = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };
const VERDICT_LABEL: Record<TriageVerdict, string> = {
  true_positive: 'AI: 脆弱性あり',
  false_positive: 'AI: 誤検知の可能性',
  needs_review: 'AI: 要確認',
};

function formatText(items: Item[], baselined: number, scanned: number): string {
  const lines: string[] = [];
  for (const { finding: f, relativePath, triage } of items) {
    const ai = triage ? `  [${VERDICT_LABEL[triage.verdict]} / 確信度: ${triage.confidence}]` : '';
    lines.push(`${relativePath}:${f.range.start.line + 1}:${f.range.start.column + 1}  ${SEV_LABEL[f.severity]}  ${f.ruleId}  (確信度: ${f.confidence})${ai}`);
    lines.push(`  ${f.message}`);
    for (const s of f.trace) lines.push(`    ${s.range.start.line + 1}行目: ${s.message}`);
    if (triage) lines.push(`  AI 判定理由: ${triage.reasoning}`);
    lines.push('');
  }
  const counts = (['critical', 'high', 'medium', 'low'] as Severity[])
    .map((s) => `${SEV_LABEL[s]} ${items.filter((i) => i.finding.severity === s).length}`)
    .join(' / ');
  lines.push(`${scanned} ファイルを解析: 指摘 ${items.length} 件（${counts}）` + (baselined > 0 ? `、ベースラインで除外 ${baselined} 件` : ''));
  return lines.join('\n') + '\n';
}

export function formatReport(format: OutputFormat, items: Item[], baselined: number, scanned: number): string {
  if (format === 'json') {
    return JSON.stringify({ version: LLMSCAN_VERSION, findings: items.map((i) => ({ ...i.finding, file: i.relativePath, ...(i.triage ? { triage: i.triage } : {}) })) }, null, 2) + '\n';
  }
  if (format === 'sarif') return JSON.stringify(toSarif(items, LLMSCAN_VERSION), null, 2) + '\n';
  return formatText(items, baselined, scanned);
}
