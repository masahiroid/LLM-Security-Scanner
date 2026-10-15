import { CONFIDENCE_LABEL, CONFIDENCE_LABEL_EN, type Finding, KIND_META, type LanguageId, OWASP_A05, OWASP_LLM05 } from '@llmscan/core';

export function getLanguageFamily(lang: LanguageId): 'python' | 'javascript' | 'php' {
  return lang === 'python' ? 'python' : lang === 'php' ? 'php' : 'javascript';
}

export function createHoverMarkdown(f: Finding): string {
  if (f.kind === 'suppression') return `**LLMScan** \`${f.ruleId}\`\n\n${f.message}`;
  const meta = KIND_META[f.kind];
  const isLlm = f.ruleId.startsWith('LLM05');
  const owasp = isLlm ? OWASP_LLM05 : OWASP_A05;
  const family = getLanguageFamily(f.language);
  const lines = [
    `**LLMScan** \`${f.ruleId}\` — ${isLlm ? 'LLM05 不適切な出力処理 (Insecure Output Handling) / ' : ''}${meta.title} (${meta.titleEn})`,
    '',
    `重大度 / Severity: **${f.severity}** ｜ 確信度 / Confidence: **${CONFIDENCE_LABEL[f.confidence]} (${CONFIDENCE_LABEL_EN[f.confidence]})**`,
    '',
    f.message,
    '',
    `**なぜ危険か / Why this is dangerous:**`,
    `- ${meta.why}`,
    `- _${meta.whyEn}_`,
  ];
  if (isLlm) {
    lines.push(
      '',
      '> **LLM の応答はプロンプトインジェクションで外部から操作できるため、ユーザー入力と同じく信頼できない値として扱ってください。**',
      '> _Treat LLM output as untrusted input as it can be manipulated via prompt injection._',
    );
  }
  lines.push(
    '',
    `**安全な書き方 / Safe Practice:**`,
    `- ${meta.fix[family]}`,
    `- _${meta.fixEn[family]}_`,
    '',
    '**経路 / Dataflow:**',
  );
  for (const s of f.trace) {
    lines.push(`1. ${s.range.start.line + 1} 行目: ${s.message.replace(/[*_`[\]]/g, '\\$&')}`);
  }
  lines.push('', `[${owasp.id} ${owasp.title}](${owasp.url}) ｜ ${meta.cwe}`);
  return lines.join('\n');
}

