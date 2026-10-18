import {
  CONFIDENCE_LABEL,
  CONFIDENCE_LABEL_EN,
  type Finding,
  KIND_META,
  getLanguageFamily,
  owaspForRuleId,
} from '@llmscan/core';

import { translateTraceStep } from './diagnostics';

export { getLanguageFamily };

export function createHoverMarkdown(f: Finding, isJa = true): string {
  if (f.kind === 'suppression') return `**LLMScan** \`${f.ruleId}\`\n\n${f.message}`;
  const meta = KIND_META[f.kind];
  const isLlm05 = f.ruleId.startsWith('LLM05');
  const isLlm01 = f.ruleId.startsWith('LLM01');
  const isLlm02 = f.ruleId.startsWith('LLM02');
  const owasp = owaspForRuleId(f.ruleId);
  const family = getLanguageFamily(f.language);

  if (isJa) {
    const llmPrefixJa = isLlm05
      ? 'LLM05 不適切な出力処理 / '
      : isLlm01
        ? 'LLM01 プロンプトインジェクション / '
        : isLlm02
          ? 'LLM02 機密情報の漏洩 / '
          : '';
    const lines = [
      `**LLMScan** \`${f.ruleId}\` — ${llmPrefixJa}${meta.title}`,
      '',
      `重大度: **${f.severity}** ｜ 確信度: **${CONFIDENCE_LABEL[f.confidence]}**`,
      '',
      f.message,
      '',
      '**危険な理由:**',
      meta.why,
    ];
    if (isLlm05) {
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
  const llmPrefixEn = isLlm05
    ? 'LLM05 Insecure Output Handling / '
    : isLlm01
      ? 'LLM01 Prompt Injection / '
      : isLlm02
        ? 'LLM02 Sensitive Information Disclosure / '
        : '';
  const originLabel =
    f.origin === 'llm'
      ? 'LLM output'
      : f.origin === 'user'
        ? 'Untrusted user input'
        : 'Function parameter';
  const summaryEn =
    f.kind === 'secret'
      ? 'Hardcoded API key or secret detected in source code.'
      : `${originLabel} flows into dangerous sink without sanitization.`;
  const lines = [
    `**LLMScan** \`${f.ruleId}\` — ${llmPrefixEn}${meta.titleEn}`,
    '',
    `Severity: **${f.severity.toUpperCase()}** ｜ Confidence: **${CONFIDENCE_LABEL_EN[f.confidence]}**`,
    '',
    summaryEn,
    '',
    '**Why this is dangerous:**',
    meta.whyEn,
  ];
  if (isLlm05) {
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

