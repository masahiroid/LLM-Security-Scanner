import { type ChildProcess, spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type MessageConnection, StreamMessageReader, StreamMessageWriter, createMessageConnection } from 'vscode-jsonrpc/node';
import { URI } from 'vscode-uri';

const EXT_DIR = path.join(__dirname, '..');

interface Diag {
  range: { start: { line: number; character: number } };
  code: string;
  message: string;
  severity: number;
  data: unknown;
  relatedInformation: { message: string }[];
  source: string;
}

let proc: ChildProcess;
let conn: MessageConnection;
let workspace: string;
const diagnostics = new Map<string, Diag[]>();
const waiters: { uri: string; pred: (d: Diag[]) => boolean; resolve: (d: Diag[]) => void }[] = [];

/** 条件を満たす診断が publish されるまで待つ */
function waitFor(uri: string, pred: (d: Diag[]) => boolean): Promise<Diag[]> {
  return new Promise((resolve) => waiters.push({ uri, pred, resolve }));
}
const nonEmpty = (d: Diag[]) => d.length > 0;
const empty = (d: Diag[]) => d.length === 0;

const VULN = `from flask import request
import sqlite3

def view():
    q = request.args["q"]
    sqlite3.connect("a.db").execute("SELECT * FROM t WHERE name = '" + q + "'")
`;

beforeAll(async () => {
  const build = spawnSync(process.execPath, ['build.mjs'], { cwd: EXT_DIR, encoding: 'utf8' });
  if (build.status !== 0) throw new Error(build.stderr);

  workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'llmscan-ws-'));
  fs.writeFileSync(path.join(workspace, '.llmscan.yml'), 'exclude: ["generated/**"]\n');

  proc = spawn(process.execPath, [path.join(EXT_DIR, 'dist', 'server.js'), '--stdio'], { stdio: 'pipe' });
  conn = createMessageConnection(new StreamMessageReader(proc.stdout!), new StreamMessageWriter(proc.stdin!));
  conn.onNotification('textDocument/publishDiagnostics', (p: { uri: string; diagnostics: Diag[] }) => {
    diagnostics.set(p.uri, p.diagnostics);
    for (const w of [...waiters]) {
      if (w.uri === p.uri && w.pred(p.diagnostics)) {
        waiters.splice(waiters.indexOf(w), 1);
        w.resolve(p.diagnostics);
      }
    }
  });
  conn.onNotification('window/showMessage', () => {});
  conn.onRequest('workspace/configuration', () => [{ enable: true, minConfidence: '', showBaselined: false }]);
  conn.listen();
  await conn.sendRequest('initialize', {
    processId: process.pid,
    rootUri: URI.file(workspace).toString(),
    workspaceFolders: [{ uri: URI.file(workspace).toString(), name: 'ws' }],
    capabilities: { workspace: { configuration: true } },
    locale: 'ja',
  });
  await conn.sendNotification('initialized', {});
}, 60_000);

afterAll(() => {
  conn?.dispose();
  proc?.kill();
});

function open(
  rel: string,
  text: string,
  languageId = 'python',
  pred: (d: Diag[]) => boolean = nonEmpty,
): { uri: string; diags: Promise<Diag[]> } {
  const file = path.join(workspace, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  const uri = URI.file(file).toString();
  const diags = waitFor(uri, pred);
  void conn.sendNotification('textDocument/didOpen', { textDocument: { uri, languageId, version: 1, text } });
  return { uri, diags };
}

describe('Language Server', () => {
  it('開いたファイルの指摘を経路付きの診断として返す', async () => {
    const { diags } = open('app/views.py', VULN);
    const [d] = await diags;
    expect(d.code).toBe('PY-SQLI-001');
    expect(d.source).toBe('llmscan');
    expect(d.severity).toBe(1);
    expect(d.range.start.line).toBe(5);
    expect(d.message).toContain('確信度: 高');
    expect(d.relatedInformation.map((r) => r.message)).toEqual([
      'ユーザー入力: request.args[]',
      'q に代入',
      '危険な処理: sqlite3.connect.execute',
    ]);
  });

  it('編集すると再解析される', async () => {
    const uri = URI.file(path.join(workspace, 'app/views.py')).toString();
    const diags = waitFor(uri, empty);
    const fixed = VULN.replace(`"SELECT * FROM t WHERE name = '" + q + "'"`, '"SELECT * FROM t WHERE name = ?", (q,)');
    void conn.sendNotification('textDocument/didChange', {
      textDocument: { uri, version: 2 },
      contentChanges: [{ text: fixed }],
    });
    expect(await diags).toEqual([]);
    const back = waitFor(uri, nonEmpty);
    void conn.sendNotification('textDocument/didChange', { textDocument: { uri, version: 3 }, contentChanges: [{ text: VULN }] });
    expect(await back).toHaveLength(1);
  });

  it('ホバーで理由・安全な書き方・経路を表示する', async () => {
    const uri = URI.file(path.join(workspace, 'app/views.py')).toString();
    const hover = (await conn.sendRequest('textDocument/hover', {
      textDocument: { uri },
      position: { line: 5, character: 40 },
    })) as { contents: { value: string } };
    expect(hover.contents.value).toContain('SQL インジェクション');
    expect(hover.contents.value).toContain('安全な書き方');
    expect(hover.contents.value).toContain('5 行目: ユーザー入力');
  });

  it('クイックフィックスで理由欄つきの抑制コメントを挿入できる', async () => {
    const uri = URI.file(path.join(workspace, 'app/views.py')).toString();
    const d = diagnostics.get(uri)![0];
    const actions = (await conn.sendRequest('textDocument/codeAction', {
      textDocument: { uri },
      range: d.range,
      context: { diagnostics: [d] },
    })) as { title: string; edit: { changes: Record<string, { newText: string; range: { start: { line: number } } }[]> } }[];
    expect(actions).toHaveLength(1);
    const [edit] = actions[0].edit.changes[uri];
    expect(edit.range.start.line).toBe(5);
    expect(edit.newText).toBe('    # llmscan-ignore[PY-SQLI-001]: TODO 理由を記入\n');
  });

  it('除外パターンに一致するファイルは解析しない', async () => {
    const { diags } = open('generated/gen.py', VULN, 'python', () => true);
    expect(await diags).toEqual([]);
  });

  it('LLM の応答を危険な処理に渡すコードを LLM05 として報告する（TypeScript）', async () => {
    const { diags } = open(
      'web/ai.ts',
      `import OpenAI from 'openai';
const openai = new OpenAI();
export async function render(q: string) {
  const r = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: q }] });
  document.body.innerHTML = r.choices[0].message.content ?? '';
}
`,
      'typescript',
    );
    const [d] = await diags;
    expect(d.code).toBe('LLM05-XSS-001');
  });

  it('ベースラインを作成すると既存の指摘は表示されなくなる', async () => {
    const uri = URI.file(path.join(workspace, 'app/views.py')).toString();
    const cleared = waitFor(uri, empty);
    const result = (await conn.sendRequest('workspace/executeCommand', { command: 'llmscan.createBaseline', arguments: [] })) as {
      written: string[];
    };
    expect(result.written).toEqual([path.join(workspace, '.llmscan-baseline.json')]);
    expect(await cleared).toEqual([]);
    const baseline = JSON.parse(fs.readFileSync(result.written[0], 'utf8'));
    expect(baseline.findings.map((f: { file: string }) => f.file).sort()).toEqual(['app/views.py', 'web/ai.ts']);
  });
});
