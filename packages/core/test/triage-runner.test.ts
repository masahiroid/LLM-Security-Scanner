import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { planBatchTriage, readTriageCache, runBatchTriage, toSarif, writeTriageCache, type Finding, type Severity, type TriageCache } from '../src';

const source = 'function run(value) {\n  eval(value);\n}';
const finding = (severity: Severity, kind: Finding['kind'] = 'codei'): Finding => ({
  ruleId: 'JS-CODEI-001', kind, severity, confidence: 'high', origin: 'user', message: `m-${severity}`, file: '/secret/path/app.ts',
  language: 'typescript', range: { start: { line: 1, column: 2 }, end: { line: 1, column: 13 } }, trace: [], functionName: 'run', fingerprint: severity,
});
const answer = JSON.stringify({ verdict: 'false_positive', confidence: 'medium', reasoning: 'r', patchedCode: 'p', explanation: '' });
const ok = () => vi.fn(async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ message: { content: answer } }), json: async () => ({}) }));
const config = { provider: 'ollama' as const };

describe('batch triage', () => {
  it('重大度順に選び、最小重大度・件数上限・抑制を除外する', async () => {
    const targets = (['low', 'critical', 'medium', 'high'] as Severity[]).map((s) => ({ finding: finding(s), sourceText: source }));
    targets.push({ finding: finding('critical', 'suppression'), sourceText: source });
    const plan = await planBatchTriage(targets, { config, minSeverity: 'medium', maxFindings: 2 });
    expect(plan.planned.map((p) => p.index)).toEqual([1, 3]);
    expect(Object.fromEntries(plan.skipped.map((s) => [s.index, s.reason]))).toEqual({ 0: 'below_severity', 2: 'over_limit', 4: 'suppression' });
    expect(plan.planned[0].userPrompt).not.toContain('/secret/path');
  });

  it('合計サイズ上限を超える分は送らない', async () => {
    const targets = [finding('high'), finding('high')].map((f) => ({ finding: f, sourceText: source }));
    const plan = await planBatchTriage(targets, { config, maxTotalInputChars: 1 });
    expect(plan.planned).toHaveLength(0);
  });

  it('キャッシュ済みは送信せず、新しい判定はキャッシュに入る', async () => {
    const targets = [{ finding: finding('high'), sourceText: source }];
    const cache: TriageCache = new Map();
    const fetchImpl = ok();
    const plan = await planBatchTriage(targets, { config, cache });
    const first = await runBatchTriage(plan, { config, cache, fetchImpl });
    expect(first.results.get(0)).toMatchObject({ verdict: 'false_positive', cached: false });
    const second = await runBatchTriage(plan, { config, cache, fetchImpl });
    expect(second.results.get(0)?.cached).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('個別の失敗は errors に入り、他の判定は続行する', async () => {
    let n = 0;
    const fetchImpl = vi.fn(async () => (n++ === 0
      ? { ok: false, status: 500, text: async () => 'leaked body', json: async () => ({}) }
      : { ok: true, status: 200, text: async () => JSON.stringify({ message: { content: answer } }), json: async () => ({}) }));
    const targets = [finding('high'), finding('critical')].map((f) => ({ finding: f, sourceText: source }));
    const plan = await planBatchTriage(targets, { config });
    const r = await runBatchTriage(plan, { config, fetchImpl, concurrency: 1 });
    expect(r.results.size).toBe(1);
    expect([...r.errors.values()][0]).toBe('LLM API Error (HTTP 500)');
  });

  it('キャッシュは往復でき、壊れたファイルや不正な項目は無視する', () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'llmscan-cache-')), 'sub', 'c.json');
    const cache: TriageCache = new Map([['k', { verdict: 'needs_review', confidence: 'low', reasoning: 'x', provider: 'ollama', model: 'm' }]]);
    writeTriageCache(file, cache);
    expect(readTriageCache(file).get('k')?.verdict).toBe('needs_review');
    fs.writeFileSync(file, JSON.stringify({ version: 1, entries: { bad: { verdict: 'safe' } } }));
    expect(readTriageCache(file).size).toBe(0);
    fs.writeFileSync(file, 'not json');
    expect(readTriageCache(file).size).toBe(0);
  });

  it('SARIF: 判定は properties に入り、誤検知のみ suppressions を付ける', () => {
    const triage = { verdict: 'false_positive' as const, confidence: 'high' as const, reasoning: 'r', provider: 'ollama' as const, model: 'm', cached: false };
    const sarif = toSarif([
      { finding: finding('high'), relativePath: 'a.ts', triage },
      { finding: finding('low'), relativePath: 'b.ts', triage: { ...triage, verdict: 'true_positive' } },
      { finding: finding('low'), relativePath: 'c.ts' },
    ], '0') as { runs: { results: Record<string, any>[] }[] };
    const [a, b, c] = sarif.runs[0].results;
    expect(a.suppressions[0]).toMatchObject({ kind: 'external', status: 'underReview' });
    expect(b.suppressions).toBeUndefined();
    expect(b.properties.llmscanTriage.verdict).toBe('true_positive');
    expect(c.properties.llmscanTriage).toBeUndefined();
  });
});
