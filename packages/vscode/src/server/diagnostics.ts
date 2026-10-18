import { CONFIDENCE_LABEL, CONFIDENCE_LABEL_EN, type Finding, KIND_META, owaspForRuleId } from '@llmscan/core';
import { type Diagnostic, DiagnosticSeverity } from 'vscode-languageserver/node';

const SEVERITY_MAP: Record<Finding['severity'], DiagnosticSeverity> = {
  critical: DiagnosticSeverity.Error,
  high: DiagnosticSeverity.Error,
  medium: DiagnosticSeverity.Warning,
  low: DiagnosticSeverity.Information,
};

export function translateTraceStep(msg: string): string {
  return msg
    .replace(/^(\d+\/\d+):\s*入力源:\s*/, '$1: Source: ')
    .replace(/^(\d+\/\d+):\s*危険な処理:\s*/, '$1: Dangerous sink: ')
    .replace(/ハードコードされた機密情報:\s*/, 'Hardcoded secret: ')
    .replace(/（システムプロンプト）/, ' (system prompt)')
    .replace(/変数\s+([a-zA-Z0-9_$]+)\s+に代入/, 'Assigned to variable $1')
    .replace(/ユーザー入力/, 'User input')
    .replace(/関数の引数/, 'Function parameter')
    .replace(/LLM の応答/, 'LLM model output')
    .replace(/を代入/, 'assigned')
    .replace(/経由/, 'via');
}

export function toDiagnostic(f: Finding, uri: string, isJa = true): Diagnostic {
  const owasp = owaspForRuleId(f.ruleId);
  const meta = f.kind !== 'suppression' ? KIND_META[f.kind] : undefined;

  let msg = f.message;
  if (!isJa && meta) {
    if (f.kind === 'secret') {
      msg = `[LLM02 Sensitive Information Disclosure / ${meta.titleEn}] Hardcoded API key or secret detected in source code (Confidence: ${CONFIDENCE_LABEL_EN[f.confidence]})`;
    } else {
      const originLabel =
        f.origin === 'llm'
          ? 'LLM output'
          : f.origin === 'user'
            ? 'Untrusted user input'
            : 'Function parameter';
      const prefix =
        f.kind === 'prompti'
          ? `[LLM01 Prompt Injection / ${meta.titleEn}]`
          : f.origin === 'llm'
            ? `[LLM05 Insecure Output Handling / ${meta.titleEn}]`
            : `[${meta.titleEn}]`;
      const tail =
        f.origin === 'param'
          ? '. Dangerous if caller passes external data.'
          : '';
      msg = `${prefix} ${originLabel} flows into dangerous sink without sanitization${tail} (Confidence: ${CONFIDENCE_LABEL_EN[f.confidence]})`;
    }
  } else if (f.kind !== 'suppression') {
    msg = `${f.message}（確信度: ${CONFIDENCE_LABEL[f.confidence]}）`;
  }

  return {
    range: {
      start: { line: f.range.start.line, character: f.range.start.column },
      end: { line: f.range.end.line, character: f.range.end.column },
    },
    severity: SEVERITY_MAP[f.severity],
    source: 'llmscan',
    code: f.ruleId,
    codeDescription: f.kind === 'suppression' ? undefined : { href: owasp.url },
    message: msg,
    relatedInformation: f.trace.map((s) => ({
      location: {
        uri,
        range: {
          start: { line: s.range.start.line, character: s.range.start.column },
          end: { line: s.range.end.line, character: s.range.end.column },
        },
      },
      message: !isJa ? translateTraceStep(s.message) : s.message,
    })),
    data: {
      ruleId: f.ruleId,
      fingerprint: f.fingerprint,
      anchorLine: f.trace[f.trace.length - 1]?.range.start.line ?? f.range.start.line,
    },
  };
}

