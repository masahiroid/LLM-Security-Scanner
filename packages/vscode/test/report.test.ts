import { describe, expect, it } from 'vitest';
import { URI } from 'vscode-uri';
import { type FindingReportItem, generateAiRemediationPrompt } from '../src/report';

describe('Report & AI Remediation Prompt Generator', () => {
  const sampleItems: FindingReportItem[] = [
    {
      uri: URI.file('/workspace/src/agent.ts') as any,
      relativePath: 'src/agent.ts',
      line: 25,
      column: 10,
      ruleCode: 'LLM05-CODEI-001',
      severity: 'Critical',
      message: 'コードインジェクション: 外部から来た値が eval 等に渡っています',
      trace: [
        '1/2: 入力源: request.params.arguments (mcp.ts:10)',
        '2/2: 危険な処理: eval(code) (agent.ts:25)',
      ],
      codeSnippet: '  24 | const code = request.params.arguments.script;\n> 25 | eval(code);',
      language: 'typescript',
      recommendation: 'eval / new Function を使わない設計にします。',
      cwe: 'CWE-94',
    },
    {
      uri: URI.file('/workspace/src/db.py') as any,
      relativePath: 'src/db.py',
      line: 42,
      column: 5,
      ruleCode: 'PY-SQLI-001',
      severity: 'High',
      message: 'SQL インジェクション: 外部から来た値が SQL 文の一部として解釈されます',
      trace: [
        '1/2: 入力源: request.args["id"] (api.py:12)',
        '2/2: 危険な処理: cur.execute(...) (db.py:42)',
      ],
      language: 'python',
      recommendation: 'プレースホルダを使い、値は別引数で渡します。',
      cwe: 'CWE-89',
    },
  ];

  it('AI 修正プロンプトの Markdown が正しく生成される', () => {
    const md = generateAiRemediationPrompt(sampleItems);
    expect(md).toContain('LLMScan');
    expect(md).toContain('LLM05-CODEI-001');
    expect(md).toContain('src/agent.ts:25:10');
    expect(md).toContain('CWE-94');
    expect(md).toContain('request.params.arguments');
    expect(md).toContain('eval(code)');
    expect(md).toContain('PY-SQLI-001');
    expect(md).toContain('src/db.py:42:5');
  });

  it('指摘が空の場合は空メッセージを返す', () => {
    const md = generateAiRemediationPrompt([]);
    expect(md).toContain('LLMScan');
  });
});
