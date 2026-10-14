import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG, meetsConfidence, parseConfig, parseSuppressions, scanSource, toSarif } from '../src';

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
