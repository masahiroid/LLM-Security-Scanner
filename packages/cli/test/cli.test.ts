import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';

const CLI_DIR = path.join(__dirname, '..');
const CLI = path.join(CLI_DIR, 'dist', 'cli.js');

function run(cwd: string, ...args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'llmscan-'));
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

const VULN_PY = `from flask import request
import sqlite3

def view():
    q = request.args["q"]
    sqlite3.connect("a.db").execute("SELECT * FROM t WHERE name = '" + q + "'")
`;

beforeAll(() => {
  // バンドル版（WASM 同梱）を検証する
  const r = spawnSync(process.execPath, ['build.mjs'], { cwd: CLI_DIR, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
}, 60_000);

describe('llmscan scan', () => {
  it('指摘があれば終了コード 1、テキストで経路を表示する', () => {
    const dir = project({ 'app/views.py': VULN_PY });
    const r = run(dir, 'scan');
    expect(r.code).toBe(1);
    expect(r.stdout).toContain('app/views.py:6:');
    expect(r.stdout).toContain('PY-SQLI-001');
    expect(r.stdout).toContain('5行目: ユーザー入力: request.args[]');
  });

  it('問題がなければ終了コード 0', () => {
    const dir = project({ 'ok.py': 'print("hello")\n' });
    expect(run(dir, 'scan').code).toBe(0);
  });

  it('ベースラインに登録した既存の指摘は除外し、新規の指摘だけで失敗する', () => {
    const dir = project({ 'old.py': VULN_PY });
    const update = run(dir, 'scan', '--update-baseline');
    expect(update.code).toBe(0);
    expect(fs.existsSync(path.join(dir, '.llmscan-baseline.json'))).toBe(true);

    // 既存ファイルの上に行が増えても、既存の指摘として扱われる
    fs.writeFileSync(path.join(dir, 'old.py'), '# 追記\n' + VULN_PY);
    const again = run(dir, 'scan');
    expect(again.code).toBe(0);
    expect(again.stdout).toContain('ベースラインで除外 1 件');

    fs.writeFileSync(path.join(dir, 'new.py'), VULN_PY);
    const withNew = run(dir, 'scan');
    expect(withNew.code).toBe(1);
    expect(withNew.stdout).toContain('new.py:6:');
    expect(withNew.stdout).not.toContain('old.py:');
  });

  it('SARIF を出力できる', () => {
    const dir = project({ 'a.py': VULN_PY });
    const r = run(dir, 'scan', '--format', 'sarif', '--fail-on', 'none');
    expect(r.code).toBe(0);
    const sarif = JSON.parse(r.stdout);
    expect(sarif.runs[0].results[0]).toMatchObject({ ruleId: 'PY-SQLI-001', level: 'error' });
  });

  it('設定ファイルの exclude と failOn を使う', () => {
    const dir = project({
      '.llmscan.yml': 'exclude: ["tests/**"]\nfailOn: critical\n',
      'tests/test_x.py': VULN_PY,
      'src/a.py': VULN_PY,
    });
    const r = run(dir, 'scan', '--format', 'json');
    // SQLi は high のため failOn: critical では失敗しない
    expect(r.code).toBe(0);
    const files = JSON.parse(r.stdout).findings.map((f: { file: string }) => f.file);
    expect(files).toEqual(['src/a.py']);
  });

  it('不正な引数は終了コード 2', () => {
    const dir = project({});
    expect(run(dir, 'scan', '--format', 'xml').code).toBe(2);
    expect(run(dir, 'unknown').code).toBe(2);
  });
});
