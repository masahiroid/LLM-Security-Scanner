import { describe, expect, it } from 'vitest';
import {
  DEFAULT_CONFIG,
  ProjectIndex,
  indexFileSummaries,
  meetsConfidence,
  parseConfig,
  parseSuppressions,
  scanSource,
  toSarif,
} from '../src';

const vulnerable = `from flask import request
import sqlite3

def view():
    q = request.args["q"]
    sqlite3.connect("a.db").execute("SELECT * FROM t WHERE name = '" + q + "'")
`;

describe('抑制コメント', () => {
  it('理由のあるものだけ有効、TODO は理由とみなさない', () => {
    const s = parseSuppressions([
      'x  # llmscan-ignore[PY-SQLI-001]: 許可リストで検証済み',
      'x  // llmscan-ignore: 全ルール対象の理由',
      'x  # llmscan-ignore[PY-SQLI-001]',
      'x  # llmscan-ignore[PY-SQLI-001]: TODO 理由を記入',
      'x  /* llmscan-ignore[JS-XSS-001, JS-SQLI-001]: 定数のみ */',
    ]);
    expect(s.map((x) => [x.line, x.valid, x.rules])).toEqual([
      [0, true, ['PY-SQLI-001']],
      [1, true, 'all'],
      [2, false, ['PY-SQLI-001']],
      [3, false, ['PY-SQLI-001']],
      [4, true, ['JS-XSS-001', 'JS-SQLI-001']],
    ]);
  });

  it('別のルール ID の抑制では消えない', async () => {
    const text = vulnerable.replace(
      '    sqlite3.connect',
      '    # llmscan-ignore[PY-CMDI-001]: 無関係\n    sqlite3.connect',
    );
    const ids = (await scanSource(text, 'a.py')).map((f) => f.ruleId);
    expect(ids).toEqual(['PY-SQLI-001']);
  });
});

describe('指紋（ベースライン照合用）', () => {
  it('上に行が増えても変わらない', async () => {
    const [a] = await scanSource(vulnerable, 'a.py');
    const [b] = await scanSource('# 先頭にコメントを追加\n\n' + vulnerable, 'a.py');
    expect(a.range.start.line).not.toBe(b.range.start.line);
    expect(a.fingerprint).toBe(b.fingerprint);
  });

  it('ファイルが違えば変わる', async () => {
    const [a] = await scanSource(vulnerable, 'a.py', { relativePath: 'app/a.py' });
    const [b] = await scanSource(vulnerable, 'a.py', { relativePath: 'app/b.py' });
    expect(a.fingerprint).not.toBe(b.fingerprint);
  });
});

describe('経路（trace）', () => {
  it('出どころ → 代入 → 危険な処理 の順に記録される', async () => {
    const [f] = await scanSource(vulnerable, 'a.py');
    expect(f.trace.map((s) => s.range.start.line + 1)).toEqual([5, 5, 6]);
    expect(f.trace[0].message).toContain('ユーザー入力');
    expect(f.trace[f.trace.length - 1].message).toContain('危険な処理');
    expect(f.confidence).toBe('high');
    expect(f.severity).toBe('high');
  });
});

describe('確信度', () => {
  it('引数をそのまま渡すだけなら low、連結していれば medium', async () => {
    const text = `def a(q):\n    cur.execute(q)\n\ndef b(q):\n    cur.execute("SELECT " + q)\n`;
    const findings = await scanSource(text, 'x.py');
    expect(findings.map((f) => [f.range.start.line + 1, f.confidence])).toEqual([
      [2, 'low'],
      [5, 'medium'],
    ]);
    expect(findings.filter((f) => meetsConfidence(f, DEFAULT_CONFIG.minConfidence))).toHaveLength(1);
  });

  it('無害化の有無が分からない関数を経由すると一段下がる', async () => {
    const text = `from flask import request\ndef v():\n    q = normalize(request.args["q"])\n    cur.execute("SELECT " + q)\n`;
    const [f] = await scanSource(text, 'x.py');
    expect(f.confidence).toBe('medium');
  });
});

describe('設定で追加した無害化関数', () => {
  it('別ファイルで定義した自作のエスケープ関数を登録できる', async () => {
    const text = `<?php\n$n = $_GET['n'];\necho '<p>' . h($n) . '</p>';\n`;
    const before = (await scanSource(text, 'x.php')).filter((f) => meetsConfidence(f, 'medium'));
    expect(before.map((f) => f.ruleId)).toEqual(['PHP-XSS-001']);
    const config = parseConfig('sanitizers:\n  php: ["h"]\n');
    expect(await scanSource(text, 'x.php', { config })).toEqual([]);
  });
});

describe('設定ファイル', () => {
  it('既定値を上書きできる', () => {
    const c = parseConfig('minConfidence: high\nfailOn: critical\nexclude: ["**/tests/**"]\n');
    expect(c).toMatchObject({ minConfidence: 'high', failOn: 'critical', exclude: ['**/tests/**'] });
  });

  it('不正な値はエラーにする', () => {
    expect(() => parseConfig('minConfidence: maybe\n')).toThrow(/minConfidence/);
    expect(() => parseConfig('exclude: "x"\n')).toThrow(/exclude/);
  });

  it('空のファイルは既定値', () => {
    expect(parseConfig('')).toEqual({ ...DEFAULT_CONFIG, sanitizers: {} });
  });
});

describe('SARIF', () => {
  it('ルール・位置・経路・指紋を出力する', async () => {
    const findings = await scanSource(vulnerable, '/abs/app/a.py');
    const sarif = toSarif(findings.map((finding) => ({ finding, relativePath: 'app/a.py' })), '0.1.0') as any;
    const run = sarif.runs[0];
    expect(sarif.version).toBe('2.1.0');
    expect(run.tool.driver.rules[0].id).toBe('PY-SQLI-001');
    expect(run.tool.driver.rules[0].properties.tags).toContain('CWE-89');
    const result = run.results[0];
    expect(result.locations[0].physicalLocation).toMatchObject({
      artifactLocation: { uri: 'app/a.py' },
      region: { startLine: 6 },
    });
    expect(result.codeFlows[0].threadFlows[0].locations).toHaveLength(3);
    expect(result.partialFingerprints.llmscanFingerprint).toBe(findings[0].fingerprint);
  });
});

describe('対象外', () => {
  it('対象外の拡張子・型定義ファイルは解析しない', async () => {
    expect(await scanSource('eval(x)', 'a.rb')).toEqual([]);
    expect(await scanSource('declare function eval(x: string): void;', 'a.d.ts')).toEqual([]);
  });
});

describe('Phase 1: ORM・バリデータ拡充', () => {
  it('TypeScript: TypeORM dataSource.query を検出する', async () => {
    const code = `
      import express from 'express';
      const app = express();
      app.get('/test', async (req, res) => {
        const id = req.query.id as string;
        await dataSource.query("SELECT * FROM users WHERE id = " + id);
      });
    `;
    const findings = await scanSource(code, 'test.ts');
    expect(findings.some((f) => f.ruleId === 'JS-SQLI-001')).toBe(true);
  });

  it('TypeScript: BigInt や validator での検証後は無害化と判定する', async () => {
    const code = `
      import express from 'express';
      import validator from 'validator';
      const app = express();
      app.get('/test', async (req, res) => {
        const id = req.query.id as string;
        await dataSource.query("SELECT * FROM users WHERE id = " + BigInt(id));
        const safeId = validator.isUUID(id);
        await dataSource.query("SELECT * FROM users WHERE id = " + safeId);
      });
    `;
    const findings = await scanSource(code, 'test.ts');
    expect(findings.filter((f) => f.ruleId === 'JS-SQLI-001')).toHaveLength(0);
  });

  it('Python: Django Model.objects.extra() を検出する', async () => {
    const code = `
      from flask import request
      def search(user):
        q = request.args["q"]
        User.objects.extra(where=["name = '" + q + "'"])
    `;
    const findings = await scanSource(code, 'search.py');
    expect(findings.some((f) => f.ruleId === 'PY-SQLI-001')).toBe(true);
  });

  it('PHP: Laravel Eloquent joinRaw() を検出する', async () => {
    const code = `<?php
      $table = $_GET['t'];
      DB::table('users')->joinRaw("INNER JOIN " . $table . " ON users.id = t.user_id");
    `;
    const findings = await scanSource(code, 'index.php');
    expect(findings.some((f) => f.ruleId === 'PHP-SQLI-001')).toBe(true);
  });

  it('TypeScript: Zod スキーマ検証 (z.number, z.coerce.number) や単項 + による数値化は無害化と判定する', async () => {
    const code = `
      import express from 'express';
      import { z } from 'zod';
      const app = express();
      app.get('/test', async (req, res) => {
        const numId = z.number().parse(req.query.id);
        await dataSource.query("SELECT * FROM users WHERE id = " + numId);
        const unaryId = +req.query.id;
        await dataSource.query("SELECT * FROM users WHERE id = " + unaryId);
      });
    `;
    const findings = await scanSource(code, 'test.ts');
    expect(findings.filter((f) => f.ruleId === 'JS-SQLI-001')).toHaveLength(0);
  });

  it('Python: hashlib.hexdigest や datetime 変換後は無害化と判定する', async () => {
    const code = `
      from flask import request
      import hashlib
      import sqlite3
      def view():
        h = hashlib.sha256(request.args["q"].encode()).hexdigest()
        sqlite3.connect("a.db").execute("SELECT * FROM t WHERE hash = '" + h + "'")
    `;
    const findings = await scanSource(code, 'hash.py');
    expect(findings.filter((f) => f.ruleId === 'PY-SQLI-001')).toHaveLength(0);
  });

  it('PHP: filter_var(FILTER_VALIDATE_INT) や hash() は無害化と判定する', async () => {
    const code = `<?php
      $id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
      $h = hash('sha256', $_GET['token']);
      $pdo->query("SELECT * FROM users WHERE id = " . $id . " AND token = '" . $h . "'");
    `;
    const findings = await scanSource(code, 'clean.php');
    expect(findings.filter((f) => f.ruleId === 'PHP-SQLI-001')).toHaveLength(0);
  });

  it('Phase 2: LLM ツール呼び出し・関数引数を追跡し、危険な処理に渡すコードを LLM05 として検出する (TS)', async () => {
    const code = `
      export async function handleTool(toolCall: any) {
        const query = toolCall.function.arguments;
        await dataSource.query("SELECT * FROM users WHERE " + query);
      }
    `;
    const findings = await scanSource(code, 'agent.ts');
    expect(findings.some((f) => f.ruleId === 'LLM05-SQLI-001')).toBe(true);
  });

  it('Phase 2: Agent tool_input がコマンド実行に渡るコードを LLM05 として検出する (Python)', async () => {
    const code = `
      import subprocess
      def execute_agent_step(action):
        cmd = action.tool_input
        subprocess.run(cmd, shell=True)
    `;
    const findings = await scanSource(code, 'agent.py');
    expect(findings.some((f) => f.ruleId === 'LLM05-CMDI-001')).toBe(true);
  });

  it('Phase 2: MCP (Model Context Protocol) ツール引数が eval に渡るコードを検出する (TS)', async () => {
    const code = `
      export function onCallTool(request: any) {
        const code = request.params.arguments.script;
        eval(code);
      }
    `;
    const findings = await scanSource(code, 'mcp-server.ts');
    expect(findings.some((f) => f.ruleId === 'LLM05-CODEI-001')).toBe(true);
  });

  it('v1.4: .llmscan.yml のカスタム sources と sinks を検出する', async () => {
    const config = parseConfig(`
sources:
  python:
    - pattern: "my_llm.ask"
      kind: llm
      label: "社内LLM応答"
sinks:
  python:
    - pattern: "legacy_db.run_raw"
      category: sqli
      ruleId: "CUSTOM-SQLI-001"
      severity: critical
`);
    const code = `
def handle(prompt):
    ans = my_llm.ask(prompt)
    legacy_db.run_raw("SELECT * FROM items WHERE name = '" + ans + "'")
`;
    const findings = await scanSource(code, 'custom.py', { config });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('CUSTOM-SQLI-001');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].origin).toBe('llm');
    expect(findings[0].trace[0].message).toContain('社内LLM応答');
  });

  it('v1.5: SSRF (PY-SSRF-001, JS-SSRF-001, LLM05-SSRF-001) を検出する', async () => {
    const pyCode = `
import requests
def fetch_webhook():
    target = request.args.get("url")
    requests.get(target)
`;
    const pyFindings = await scanSource(pyCode, 'webhook.py');
    expect(pyFindings.some((f) => f.ruleId === 'PY-SSRF-001')).toBe(true);

    const jsLlmCode = `
export async function runAgent(client: any, prompt: string) {
  const res = await client.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: prompt }],
  });
  const url = res.choices[0].message.content;
  await fetch(url);
}
`;
    const jsFindings = await scanSource(jsLlmCode, 'agent.ts');
    expect(jsFindings.some((f) => f.ruleId === 'LLM05-SSRF-001')).toBe(true);
  });

  it('v1.5: パストラバーサル (PY-PATH-001, JS-PATH-001) の検出と basename 無害化', async () => {
    const pyCode = `
import os
def read_doc():
    name = request.args.get("file")
    open("/var/data/" + name).read()
    safe_name = os.path.basename(name)
    open("/var/data/" + safe_name).read()
`;
    const pyFindings = await scanSource(pyCode, 'docs.py');
    const pathFindings = pyFindings.filter((f) => f.ruleId === 'PY-PATH-001');
    expect(pathFindings).toHaveLength(1);
    expect(pathFindings[0].range.start.line).toBe(4);
  });

  it('v1.5: OWASP LLM01 システムプロンプトインジェクション (LLM01-PROMPTI-001) を検出する', async () => {
    const pyCode = `
def ask_ai(client):
    role_instruction = request.args.get("persona")
    res = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": f"You are {role_instruction}"},
            {"role": "user", "content": "Hello"},
        ],
    )
    return res
`;
    const pyFindings = await scanSource(pyCode, 'chat.py');
    expect(pyFindings.some((f) => f.ruleId === 'LLM01-PROMPTI-001')).toBe(true);

    const tsCode = `
export async function generate(ai: any, req: any) {
  const customSys = req.query.sys;
  await ai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "developer", content: "Instruction: " + customSys },
    ],
  });
}
`;
    const tsFindings = await scanSource(tsCode, 'chat.ts');
    expect(tsFindings.some((f) => f.ruleId === 'LLM01-PROMPTI-001')).toBe(true);
  });

  it('v1.5: OWASP LLM02 ハードコードされた API キー (LLM02-SECRET-001) を検出する', async () => {
    const code = `
const apiKey = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz";
`;
    const findings = await scanSource(code, 'config.ts');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('LLM02-SECRET-001');
    expect(findings[0].severity).toBe('high');
  });

  it('v1.6: ProjectIndex を用いて複数ファイルをまたぐ Source -> Helper -> Sink / Sanitizer を追跡する', async () => {
    const aiServicePy = `
def ask_llm_service(client, prompt: str):
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content
`;
    const dbHelperPy = `
import sqlite3
def run_Unsafe_sql(query: str):
    conn = sqlite3.connect("app.db")
    conn.execute("SELECT * FROM items WHERE " + query)
`;
    const sanitizerPy = `
import bleach
def clean_user_html(raw: str):
    return bleach.clean(raw)
`;
    const handlerPy = `
from flask import Markup, request
from ai_service import ask_llm_service
from db_helper import run_Unsafe_sql
from sanitizer import clean_user_html

def handle_request(client):
    q = request.args.get("q")
    llm_sql = ask_llm_service(client, q)
    run_Unsafe_sql(llm_sql)
    safe_out = clean_user_html(q)
    return Markup(safe_out)
`;

    const projectIndex = new ProjectIndex();
    await indexFileSummaries(aiServicePy, 'ai_service.py', projectIndex);
    await indexFileSummaries(dbHelperPy, 'db_helper.py', projectIndex);
    await indexFileSummaries(sanitizerPy, 'sanitizer.py', projectIndex);
    await indexFileSummaries(handlerPy, 'handler.py', projectIndex);

    const findings = await scanSource(handlerPy, 'handler.py', { projectIndex });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('LLM05-SQLI-001');
    expect(findings[0].origin).toBe('llm');
    expect(findings[0].confidence).toBe('high');
  });
});


