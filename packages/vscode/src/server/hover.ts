import {
  CONFIDENCE_LABEL,
  CONFIDENCE_LABEL_EN,
  type Finding,
  KIND_META,
  OWASP_A05,
  OWASP_LLM05,
  getLanguageFamily,
} from '@llmscan/core';

import { translateTraceStep } from './diagnostics';

export { getLanguageFamily };

export function createHoverMarkdown(f: Finding, isJa = true): string {
  if (f.kind === 'suppression') return `**LLMScan** \`${f.ruleId}\`\n\n${f.message}`;
  const meta = KIND_META[f.kind];
  const isLlm = f.ruleId.startsWith('LLM05');
  const owasp = isLlm ? OWASP_LLM05 : OWASP_A05;
  const family = getLanguageFamily(f.language);

  if (isJa) {
    const lines = [
      `**LLMScan** \`${f.ruleId}\` — ${isLlm ? 'LLM05 不適切な出力処理 / ' : ''}${meta.title}`,
      '',
      `重大度: **${f.severity}** ｜ 確信度: **${CONFIDENCE_LABEL[f.confidence]}**`,
      '',
      f.message,
      '',
      '**危険な理由:**',
      meta.why,
    ];
    if (isLlm) {
      lines.push(
        '',
        '> **LLM の応答はプロンプトインジェクションで外部から操作できるため、ユーザー入力と同じく信頼できない値として扱ってください。**',
      );
    }
    lines.push(
      '',
      '**安全な書き方:**',
      meta.fix[family],
      '',
      '**経路:**',
    );
    for (const s of f.trace) {
      lines.push(`1. ${s.range.start.line + 1} 行目: ${s.message.replace(/[*_`[\]]/g, '\\$&')}`);
    }
    lines.push('', `[${owasp.id} ${owasp.title}](${owasp.url}) ｜ ${meta.cwe}`);
    return lines.join('\n');
  }

  // Pure English
  const originLabel =
    f.origin === 'llm'
      ? 'LLM output'
      : f.origin === 'user'
        ? 'Untrusted user input'
        : 'Function parameter';
  const lines = [
    `**LLMScan** \`${f.ruleId}\` — ${isLlm ? 'LLM05 Insecure Output Handling / ' : ''}${meta.titleEn}`,
    '',
    `Severity: **${f.severity.toUpperCase()}** ｜ Confidence: **${CONFIDENCE_LABEL_EN[f.confidence]}**`,
    '',
    `${originLabel} flows into dangerous sink without sanitization.`,
    '',
    '**Why this is dangerous:**',
    meta.whyEn,
  ];
  if (isLlm) {
    lines.push(
      '',
      '> **Treat LLM output as untrusted input as it can be manipulated via prompt injection.**',
    );
  }
  lines.push(
    '',
    '**Recommended Fix:**',
    meta.fixEn[family],
    '',
    '**Dataflow Trace:**',
  );
  for (const s of f.trace) {
    lines.push(`1. Line ${s.range.start.line + 1}: ${translateTraceStep(s.message).replace(/[*_`[\]]/g, '\\$&')}`);
  }
  lines.push('', `[${owasp.id} ${owasp.titleEn}](${owasp.url}) ｜ ${meta.cwe}`);
  return lines.join('\n');
}

