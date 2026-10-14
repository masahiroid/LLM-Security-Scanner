import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { meetsConfidence, scanSource } from '../src';

const FIXTURES = path.join(__dirname, 'fixtures');

/** 「expect: ルールID」のコメントがある行（1 始まり）と期待するルール ID の組 */
function expectations(text: string): string[] {
  const out: string[] = [];
  text.split(/\r?\n/).forEach((line, i) => {
    for (const m of line.matchAll(/expect:\s*([A-Z0-9-]+)/g)) out.push(`${i + 1}:${m[1]}`);
  });
  return out.sort();
}

describe.each(['app.py', 'server.ts', 'index.php', 'llm-clients.ts'])('フィクスチャ %s', (name) => {
  it('期待した行に期待したルールの指摘が出て、それ以外には出ない（確信度 medium 以上）', async () => {
    const file = path.join(FIXTURES, name);
    const text = fs.readFileSync(file, 'utf8');
    const findings = (await scanSource(text, file)).filter((f) => meetsConfidence(f, 'medium'));
    const actual = findings.map((f) => `${f.range.start.line + 1}:${f.ruleId}`).sort();
    expect(actual).toEqual(expectations(text));
  });
});
