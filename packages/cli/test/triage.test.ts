import { spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

const CLI_DIR = path.join(__dirname, '..');
const CLI = path.join(CLI_DIR, 'dist', 'cli.js');
const SECRET = 'sk-' + 'q'.repeat(30);
const VULN_PY = `from flask import request
import sqlite3

def view():
    token = "${SECRET}"
    q = request.args["q"]
    sqlite3.connect("a.db").execute("SELECT * FROM t WHERE name = '" + q + "'")
`;

function project(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'llmscan-triage-'));
  fs.writeFileSync(path.join(dir, 'app.py'), VULN_PY);
  return dir;
}

/** サーバーと同じイベントループを塞がないよう非同期で起動する */
function run(cwd: string, args: string[], env: NodeJS.ProcessEnv = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env: { PATH: process.env.PATH, ...env } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

let server: http.Server | undefined;
const bodies: string[] = [];
function fakeOllama(verdict: string): Promise<string> {
  bodies.length = 0;
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      bodies.push(body);
      const content = JSON.stringify({ verdict, confidence: 'high', reasoning: 'parameterized elsewhere', patchedCode: 'x', explanation: '' });
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ message: { content } }));
    });
  });
  return new Promise((resolve) => server!.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(server!.address() as AddressInfo).port}/api/chat`)));
}

beforeAll(() => {
  const r = spawnSync(process.execPath, ['build.mjs'], { cwd: CLI_DIR, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
}, 60_000);
afterEach(() => new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve())).then(() => (server = undefined)));

describe('llmscan scan --triage', () => {
  it('プロバイダ未指定・API キー未設定は送信前にエラー（キーは引数で受け付けない）', async () => {
    const dir = project();
    expect((await run(dir, ['scan', '--triage'])).code).toBe(2);
    const noKey = await run(dir, ['scan', '--triage', '--triage-provider', 'openai']);
    expect(noKey.code).toBe(2);
    expect(noKey.stderr).toContain('LLMSCAN_TRIAGE_API_KEY');
    expect((await run(dir, ['scan', '--triage-ignore-false-positives'])).code).toBe(2);
  });

  it('dry-run は通信せず、マスク済みでファイルパスを含まない送信内容を表示する', async () => {
    const url = await fakeOllama('true_positive');
    const dir = project();
    const r = await run(dir, ['scan', '--triage-dry-run', '--triage-provider', 'ollama', '--triage-endpoint', url]);
    expect(r.code).toBe(1);
    expect(bodies).toHaveLength(0);
    expect(r.stderr).toContain('[dry-run] AI トリアージ対象 2 件');
    expect(r.stderr).not.toContain(SECRET);
    for (const user of r.stderr.split('--- user ---').slice(1)) expect(user.split('=====')[0]).not.toContain('app.py');
  });

  it('判定を SARIF / JSON に載せ、誤検知は underReview の外部抑制にし、キャッシュで再送信しない', async () => {
    const url = await fakeOllama('false_positive');
    const dir = project();
    const args = ['scan', '--triage', '--triage-provider', 'ollama', '--triage-endpoint', url, '--format', 'sarif'];
    const first = await run(dir, args);
    expect(first.code).toBe(1);
    // SQLi とハードコード API キー（LLM02）の 2 件
    expect(bodies).toHaveLength(2);
    for (const b of bodies) expect(b).not.toContain(SECRET);
    const result = JSON.parse(first.stdout).runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'PY-SQLI-001');
    expect(result.properties.llmscanTriage).toMatchObject({ verdict: 'false_positive', provider: 'ollama' });
    expect(result.suppressions[0]).toMatchObject({ kind: 'external', status: 'underReview' });

    const second = await run(dir, [...args, '--triage-ignore-false-positives']);
    expect(bodies).toHaveLength(2);
    expect(second.stderr).toContain('キャッシュ 2 件');
    expect(second.code).toBe(0);

    const json = await run(dir, ['scan', '--triage', '--triage-provider', 'ollama', '--triage-endpoint', url, '--format', 'json', '--no-triage-cache']);
    expect(bodies).toHaveLength(4);
    expect(JSON.parse(json.stdout).findings[0].triage).toMatchObject({ verdict: 'false_positive', cached: false });
  });

  it('送信失敗は件数のみ報告し、スキャン結果の終了コードは維持する', async () => {
    const dir = project();
    const r = await run(dir, ['scan', '--triage', '--triage-provider', 'ollama', '--triage-endpoint', 'http://127.0.0.1:9/api/chat', '--no-triage-cache']);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('失敗 2 件');
  });

  it('リモートの平文 HTTP エンドポイントは拒否する', async () => {
    const r = await run(project(), ['scan', '--triage', '--triage-provider', 'ollama', '--triage-endpoint', 'http://example.com/api/chat']);
    expect(r.code).toBe(2);
  });
});
