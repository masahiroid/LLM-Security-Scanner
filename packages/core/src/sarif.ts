import { KIND_META, OWASP_A05, OWASP_LLM05, SUPPRESSION_RULE_ID } from './rules';
import type { Finding, Severity } from './types';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0' };

interface SarifFinding {
  finding: Finding;
  relativePath: string;
}

function ruleDescriptor(f: Finding) {
  if (f.kind === 'suppression') {
    return {
      id: SUPPRESSION_RULE_ID,
      name: 'SuppressionWithoutReason',
      shortDescription: { text: '理由のない抑制コメント' },
      fullDescription: { text: '抑制コメントには理由を書く必要があります。' },
      defaultConfiguration: { level: 'note' },
      properties: { tags: ['maintainability'] },
    };
  }
  const meta = KIND_META[f.kind];
  const fix = meta.fix[f.language === 'python' ? 'python' : f.language === 'php' ? 'php' : 'javascript'];
  const llm = f.ruleId.startsWith('LLM05');
  const owasp = llm ? OWASP_LLM05 : OWASP_A05;
  return {
    id: f.ruleId,
    name: llm ? `LLM05 ${meta.title}` : meta.title,
    shortDescription: { text: llm ? `LLM の応答が危険な処理に渡されている（${meta.title}）` : meta.title },
    fullDescription: { text: meta.why },
    help: { text: fix, markdown: fix },
    helpUri: owasp.url,
    defaultConfiguration: { level: LEVEL[f.severity] },
    properties: {
      tags: ['security', meta.cwe, owasp.id],
      'security-severity': SECURITY_SEVERITY[f.severity],
    },
  };
}

function region(f: { range: Finding['range'] }) {
  return {
    startLine: f.range.start.line + 1,
    startColumn: f.range.start.column + 1,
    endLine: f.range.end.line + 1,
    endColumn: f.range.end.column + 1,
  };
}

export function toSarif(items: SarifFinding[], toolVersion: string): object {
  const rules = new Map<string, object>();
  for (const { finding } of items) if (!rules.has(finding.ruleId)) rules.set(finding.ruleId, ruleDescriptor(finding));
  const ruleIndex = new Map([...rules.keys()].map((id, i) => [id, i]));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'LLM Security Scanner',
            informationUri: 'https://github.com/masahiroid/LLM-Security-Scanner',
            version: toolVersion,
            rules: [...rules.values()],
          },
        },
        results: items.map(({ finding: f, relativePath }) => {
          const uri = relativePath.replace(/\\/g, '/');
          return {
            ruleId: f.ruleId,
            ruleIndex: ruleIndex.get(f.ruleId),
            level: LEVEL[f.severity],
            message: { text: f.message },
            locations: [{ physicalLocation: { artifactLocation: { uri }, region: region(f) } }],
            partialFingerprints: { llmscanFingerprint: f.fingerprint },
            properties: { confidence: f.confidence, severity: f.severity, origin: f.origin },
            ...(f.trace.length > 0
              ? {
                  codeFlows: [
                    {
                      threadFlows: [
                        {
                          locations: f.trace.map((s) => ({
                            location: {
                              physicalLocation: { artifactLocation: { uri }, region: region(s) },
                              message: { text: s.message },
                            },
                          })),
                        },
                      ],
                    },
                  ],
                }
              : {}),
          };
        }),
      },
    ],
  };
}
