import { SUPPRESSION_RULE_ID, type LanguageId } from '@llmscan/core';
import { type CodeAction, CodeActionKind, type Diagnostic, type TextEdit } from 'vscode-languageserver/node';
import type { TextDocument } from 'vscode-languageserver-textdocument';

export function createSuppressionEdit(
  doc: TextDocument,
  line: number,
  ruleId: string,
  lang: LanguageId,
  isJa = true,
): TextEdit {
  const text = doc.getText({
    start: { line, character: 0 },
    end: { line, character: Number.MAX_SAFE_INTEGER },
  });
  const indent = /^\s*/.exec(text)?.[0] ?? '';
  const todoReason = isJa ? 'TODO 理由を記入' : 'TODO Add reason';
  const body = `llmscan-ignore[${ruleId}]: ${todoReason}`;
  let comment: string;
  if (lang === 'python') comment = `# ${body}`;
  else if (lang === 'php' && text.trimStart().startsWith('<')) comment = `<?php // ${body} ?>`;
  else comment = `// ${body}`;
  return {
    range: { start: { line, character: 0 }, end: { line, character: 0 } },
    newText: `${indent}${comment}\n`,
  };
}

interface RefactorRule {
  langs: LanguageId[];
  ruleSubstr: string;
  pattern: RegExp;
  replacement: string;
  titleJa: string;
  titleEn: string;
}

const REFACTOR_RULES: RefactorRule[] = [
  {
    langs: ['python'],
    ruleSubstr: 'CMDI',
    pattern: /\bshell\s*=\s*True\b/,
    replacement: 'shell=False',
    titleJa: 'LLMScan: shell=True を shell=False に変更する（安全な修正）',
    titleEn: 'LLMScan: Replace shell=True with shell=False (Safe Fix)',
  },
  {
    langs: ['python'],
    ruleSubstr: 'CODEI',
    pattern: /\beval\s*\(/,
    replacement: 'ast.literal_eval(',
    titleJa: 'LLMScan: eval() を ast.literal_eval() に変更する（安全な修正）',
    titleEn: 'LLMScan: Replace eval() with ast.literal_eval() (Safe Fix)',
  },
  {
    langs: ['javascript', 'typescript', 'tsx'],
    ruleSubstr: 'CODEI',
    pattern: /\beval\s*\(/,
    replacement: 'JSON.parse(',
    titleJa: 'LLMScan: eval() を JSON.parse() に変更する（安全な修正）',
    titleEn: 'LLMScan: Replace eval() with JSON.parse() (Safe Fix)',
  },
  {
    langs: ['python'],
    ruleSubstr: 'DESER',
    pattern: /\byaml\.(?:unsafe_)?load\s*\(/,
    replacement: 'yaml.safe_load(',
    titleJa: 'LLMScan: yaml.safe_load() に変更する（安全な修正）',
    titleEn: 'LLMScan: Replace with yaml.safe_load() (Safe Fix)',
  },
  {
    langs: ['javascript', 'typescript', 'tsx'],
    ruleSubstr: 'XSS',
    pattern: /\.innerHTML\b/,
    replacement: '.textContent',
    titleJa: 'LLMScan: .innerHTML を .textContent に変更する（安全な修正）',
    titleEn: 'LLMScan: Replace .innerHTML with .textContent (Safe Fix)',
  },
];

function createRefactorActions(
  doc: TextDocument,
  diagnostic: Diagnostic,
  ruleId: string,
  line: number,
  lang: LanguageId,
  isJa: boolean,
): CodeAction[] {
  const lineText = doc.getText({
    start: { line, character: 0 },
    end: { line, character: Number.MAX_SAFE_INTEGER },
  });
  const out: CodeAction[] = [];

  for (const r of REFACTOR_RULES) {
    if (!r.langs.includes(lang) || !ruleId.includes(r.ruleSubstr)) continue;
    const m = r.pattern.exec(lineText);
    if (!m) continue;
    const startChar = m.index;
    const endChar = m.index + m[0].length;
    out.push({
      title: isJa ? r.titleJa : r.titleEn,
      kind: CodeActionKind.QuickFix,
      isPreferred: true,
      diagnostics: [diagnostic],
      edit: {
        changes: {
          [doc.uri]: [
            {
              range: {
                start: { line, character: startChar },
                end: { line, character: endChar },
              },
              newText: r.replacement,
            },
          ],
        },
      },
    });
  }
  return out;
}

export function buildCodeActions(
  doc: TextDocument,
  diagnostics: Diagnostic[],
  lang: LanguageId,
  isJa = true,
): CodeAction[] {
  const actions: CodeAction[] = [];

  for (const d of diagnostics) {
    if (d.source !== 'llmscan' || !d.data || d.code === SUPPRESSION_RULE_ID) continue;
    const { ruleId, anchorLine } = d.data as { ruleId: string; anchorLine: number };

    actions.push(...createRefactorActions(doc, d, ruleId, anchorLine, lang, isJa));

    actions.push({
      title: isJa
        ? `LLMScan: ${ruleId} をこの箇所で抑制する（理由の記入が必要）`
        : `LLMScan: Suppress ${ruleId} at this line (reason required)`,
      kind: CodeActionKind.QuickFix,
      diagnostics: [d],
      edit: {
        changes: {
          [doc.uri]: [createSuppressionEdit(doc, anchorLine, ruleId, lang, isJa)],
        },
      },
    });
  }

  return actions;
}
