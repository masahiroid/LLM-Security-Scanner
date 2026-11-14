import {
  planBatchTriage, readTriageCache, runBatchTriage, writeTriageCache,
  type BatchTriageOptions, type TriageSkipReason, type TriageSummary,
} from '@llmscan/core';
import type { TriageCliOptions } from './triage-options';
import type { Item } from './types';

const SKIP_LABEL: Record<TriageSkipReason, string> = {
  below_severity: '重大度が対象外',
  over_limit: '件数・サイズ上限',
  too_large: 'スニペットが大きすぎる',
  suppression: '抑制コメント',
};

function summarizeSkips(skipped: { reason: TriageSkipReason }[]): string {
  const counts = new Map<TriageSkipReason, number>();
  for (const s of skipped) counts.set(s.reason, (counts.get(s.reason) ?? 0) + 1);
  return [...counts].map(([r, n]) => `${SKIP_LABEL[r]} ${n}`).join(' / ');
}

/**
 * 指摘を AI で判定し、items[i].triage に結果を付ける。
 * dry-run では送信予定のマスク済みプロンプトを stderr に出すだけで通信しない。
 */
export async function applyTriage(
  items: Item[],
  texts: Map<string, string>,
  opts: TriageCliOptions,
  log: (s: string) => void,
): Promise<void> {
  const targets = items.map((i) => ({ finding: i.finding, sourceText: texts.get(i.relativePath) ?? '' }));
  const cache = opts.cacheFile ? readTriageCache(opts.cacheFile) : undefined;
  const batch: BatchTriageOptions = {
    config: opts.config, minSeverity: opts.minSeverity, maxFindings: opts.maxFindings, concurrency: opts.concurrency, cache,
  };
  const plan = await planBatchTriage(targets, batch);

  if (opts.dryRun) {
    for (const p of plan.planned) {
      const it = items[p.index];
      log(`===== [dry-run] ${it.relativePath}:${p.input.startLine} ${it.finding.ruleId}（このファイルパスは送信されません）${cache?.has(p.cacheKey) ? ' ※キャッシュ済み・送信なし' : ''}\n--- system ---\n${p.systemPrompt}\n--- user ---\n${p.userPrompt}\n`);
    }
    log(`[dry-run] AI トリアージ対象 ${plan.planned.length} 件（送信していません）` + (plan.skipped.length ? `、対象外: ${summarizeSkips(plan.skipped)}` : '') + '\n');
    return;
  }

  const { results, errors } = await runBatchTriage(plan, batch);
  for (const [index, summary] of results) items[index].triage = summary;
  if (cache && opts.cacheFile) writeTriageCache(opts.cacheFile, cache);

  const cached = [...results.values()].filter((r: TriageSummary) => r.cached).length;
  log(`AI トリアージ: 判定 ${results.size} 件（うちキャッシュ ${cached} 件）、失敗 ${errors.size} 件` + (plan.skipped.length ? `、対象外: ${summarizeSkips(plan.skipped)}` : '') + '\n');
  for (const [index, message] of errors) log(`  失敗: ${items[index].relativePath}:${items[index].finding.range.start.line + 1} ${message}\n`);
}
