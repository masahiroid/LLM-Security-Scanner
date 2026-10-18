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

  it('v1.6: データフローグラフ Webview HTML が日英両対応で正しく生成される', async () => {
    const { renderDataflowGraphHtml } = await import('../src/dataflow-webview');
    const htmlJa = renderDataflowGraphHtml(
      {
        ruleCode: 'LLM05-SQLI-001',
        title: 'SQL インジェクション',
        severity: 'Critical',
        cwe: 'CWE-89',
        owaspId: 'LLM05:2025',
        owaspTitle: '不適切な出力処理',
        owaspUrl: 'https://genai.owasp.org/',
        relativePath: 'src/handler.py',
        message: 'LLM の応答が SQL に渡されています',
        why: 'SQL 文が改ざんされます',
        recommendation: 'プレースホルダを使用します',
        nodes: [
          {
            stepIndex: 1,
            totalSteps: 2,
            role: 'source',
            line: 10,
            column: 5,
            message: 'LLM の応答: ask_llm_service()',
            codeLine: 'llm_sql = ask_llm_service(client, q)',
          },
          {
            stepIndex: 2,
            totalSteps: 2,
            role: 'sink',
            line: 11,
            column: 5,
            message: '危険な処理: run_Unsafe_sql(...) -> conn.execute',
            codeLine: 'run_Unsafe_sql(llm_sql)',
          },
        ],
      },
      true,
    );
    expect(htmlJa).toContain('LLM05-SQLI-001');
    expect(htmlJa).toContain('汚染源 (Source)');
    expect(htmlJa).toContain('危険な処理 (Sink)');
    expect(htmlJa).toContain('data-line="10"');
    expect(htmlJa).toContain('data-line="11"');
  });
});

