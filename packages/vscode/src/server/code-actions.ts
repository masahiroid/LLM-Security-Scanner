import { SUPPRESSION_RULE_ID, type LanguageId } from '@llmscan/core';
import { type CodeAction, CodeActionKind, type Diagnostic } from 'vscode-languageserver/node';
import type { TextDocument } from 'vscode-languageserver-textdocument';

export function createSuppressionEdit(
  doc: TextDocument,
  line: number,
  ruleId: string,
  lang: LanguageId,
) {
  const text = doc.getText({
    start: { line, character: 0 },
    end: { line, character: Number.MAX_SAFE_INTEGER },
  });
  const indent = /^\s*/.exec(text)?.[0] ?? '';
  const body = `llmscan-ignore[${ruleId}]: TODO 理由を記入`;
  let comment: string;
  if (lang === 'python') comment = `# ${body}`;
  else if (lang === 'php' && text.trimStart().startsWith('<')) comment = `<?php // ${body} ?>`;
  else comment = `// ${body}`;
  return {
    range: { start: { line, character: 0 }, end: { line, character: 0 } },
    newText: `${indent}${comment}\n`,
  };
}

export function buildCodeActions(
  doc: TextDocument,
  diagnostics: Diagnostic[],
  lang: LanguageId,
): CodeAction[] {
  const actions: CodeAction[] = [];

  for (const d of diagnostics) {
    if (d.source !== 'llmscan' || !d.data || d.code === SUPPRESSION_RULE_ID) continue;
    const { ruleId, anchorLine } = d.data as { ruleId: string; anchorLine: number };

    actions.push({
      title: `LLMScan: ${ruleId} をこの箇所で抑制する（理由の記入が必要） / Suppress finding at this line`,
      kind: CodeActionKind.QuickFix,
      diagnostics: [d],
      edit: {
        changes: {
          [doc.uri]: [createSuppressionEdit(doc, anchorLine, ruleId, lang)],
        },
      },
    });
  }

  return actions;
}
