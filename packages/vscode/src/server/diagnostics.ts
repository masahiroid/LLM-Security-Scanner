import { CONFIDENCE_LABEL, type Finding, OWASP_A05, OWASP_LLM05 } from '@llmscan/core';
import { type Diagnostic, DiagnosticSeverity } from 'vscode-languageserver/node';

const SEVERITY_MAP: Record<Finding['severity'], DiagnosticSeverity> = {
  critical: DiagnosticSeverity.Error,
  high: DiagnosticSeverity.Error,
  medium: DiagnosticSeverity.Warning,
  low: DiagnosticSeverity.Information,
};

export function toDiagnostic(f: Finding, uri: string): Diagnostic {
  const owasp = f.ruleId.startsWith('LLM05') ? OWASP_LLM05 : OWASP_A05;
  return {
    range: {
      start: { line: f.range.start.line, character: f.range.start.column },
      end: { line: f.range.end.line, character: f.range.end.column },
    },
    severity: SEVERITY_MAP[f.severity],
    source: 'llmscan',
    code: f.ruleId,
    codeDescription: f.kind === 'suppression' ? undefined : { href: owasp.url },
    message:
      f.kind === 'suppression'
        ? f.message
        : `${f.message}（確信度: ${CONFIDENCE_LABEL[f.confidence]}）`,
    relatedInformation: f.trace.map((s) => ({
      location: {
        uri,
        range: {
          start: { line: s.range.start.line, character: s.range.start.column },
          end: { line: s.range.end.line, character: s.range.end.column },
        },
      },
      message: s.message,
    })),
    data: {
      ruleId: f.ruleId,
      fingerprint: f.fingerprint,
      anchorLine: f.trace[f.trace.length - 1]?.range.start.line ?? f.range.start.line,
    },
  };
}

