import {
  DEFAULT_TRIAGE_MODELS, SEVERITY_ORDER, TRIAGE_DEFAULT_CONCURRENCY, TRIAGE_DEFAULT_MAX_FINDINGS,
  TRIAGE_MAX_CONCURRENCY, TRIAGE_MAX_TOTAL_INPUT_CHARS,
} from './constants';
import { buildTriagePrompt, triageFindingWithLlm, type FetchLike } from './triage';
import { triageCacheKey, type TriageCache } from './triage-cache';
import { triageInputForFinding } from './triage-input';
import type { Finding, Severity, TriageConfig, TriageRequestInput, TriageSummary } from './types';

export interface BatchTriageTarget {
  finding: Finding;
  sourceText: string;
}

export interface BatchTriageOptions {
  config: TriageConfig;
  isJa?: boolean;
  minSeverity?: Severity;
  maxFindings?: number;
  concurrency?: number;
  maxTotalInputChars?: number;
  cache?: TriageCache;
  fetchImpl?: FetchLike;
}

export type TriageSkipReason = 'below_severity' | 'over_limit' | 'too_large' | 'suppression';

/** 送信計画の 1 件。index は呼び出し側の targets の位置 */
export interface PlannedTriage {
  index: number;
  input: TriageRequestInput;
  systemPrompt: string;
  userPrompt: string;
  cacheKey: string;
}

export interface TriagePlan {
  planned: PlannedTriage[];
  skipped: { index: number; reason: TriageSkipReason }[];
}

export interface BatchTriageResult {
  results: Map<number, TriageSummary>;
  errors: Map<number, string>;
  skipped: TriagePlan['skipped'];
}

/** 送信対象の選定（重大度順・件数上限・合計サイズ上限）とプロンプト構築。通信はしない */
export async function planBatchTriage(targets: BatchTriageTarget[], options: BatchTriageOptions): Promise<TriagePlan> {
  const minOrder = SEVERITY_ORDER[options.minSeverity ?? 'low'];
  const maxFindings = options.maxFindings ?? TRIAGE_DEFAULT_MAX_FINDINGS;
  const maxChars = options.maxTotalInputChars ?? TRIAGE_MAX_TOTAL_INPUT_CHARS;
  const model = options.config.model?.trim() || DEFAULT_TRIAGE_MODELS[options.config.provider];
  const plan: TriagePlan = { planned: [], skipped: [] };

  const order = targets
    .map((t, index) => ({ t, index }))
    .sort((a, b) => SEVERITY_ORDER[b.t.finding.severity] - SEVERITY_ORDER[a.t.finding.severity] || a.index - b.index);

  let totalChars = 0;
  for (const { t, index } of order) {
    if (t.finding.kind === 'suppression') { plan.skipped.push({ index, reason: 'suppression' }); continue; }
    if (SEVERITY_ORDER[t.finding.severity] < minOrder) { plan.skipped.push({ index, reason: 'below_severity' }); continue; }
    if (plan.planned.length >= maxFindings) { plan.skipped.push({ index, reason: 'over_limit' }); continue; }
    const input = await triageInputForFinding(t.finding, t.sourceText, options.isJa ?? true);
    let prompt: ReturnType<typeof buildTriagePrompt>;
    try {
      prompt = buildTriagePrompt(input);
    } catch {
      plan.skipped.push({ index, reason: 'too_large' });
      continue;
    }
    const size = prompt.systemPrompt.length + prompt.userPrompt.length;
    if (totalChars + size > maxChars) { plan.skipped.push({ index, reason: 'over_limit' }); continue; }
    totalChars += size;
    plan.planned.push({
      index, input, systemPrompt: prompt.systemPrompt, userPrompt: prompt.userPrompt,
      cacheKey: triageCacheKey(prompt.systemPrompt, prompt.userPrompt, options.config.provider, model),
    });
  }
  return plan;
}

/** 計画に沿って送信する。キャッシュ済みは送らない。個別の失敗は errors に入れて続行する */
export async function runBatchTriage(plan: TriagePlan, options: BatchTriageOptions): Promise<BatchTriageResult> {
  const results = new Map<number, TriageSummary>();
  const errors = new Map<number, string>();
  const pending: PlannedTriage[] = [];
  for (const p of plan.planned) {
    const hit = options.cache?.get(p.cacheKey);
    if (hit) results.set(p.index, { ...hit, cached: true });
    else pending.push(p);
  }

  const concurrency = Math.min(Math.max(1, options.concurrency ?? TRIAGE_DEFAULT_CONCURRENCY), TRIAGE_MAX_CONCURRENCY);
  let next = 0;
  const worker = async () => {
    while (next < pending.length) {
      const p = pending[next++];
      try {
        const r = await triageFindingWithLlm(p.input, options.config, options.fetchImpl);
        const summary: TriageSummary = { verdict: r.verdict, confidence: r.confidence, reasoning: r.reasoning, provider: r.provider, model: r.model, cached: false };
        results.set(p.index, summary);
        options.cache?.set(p.cacheKey, { verdict: r.verdict, confidence: r.confidence, reasoning: r.reasoning, provider: r.provider, model: r.model });
      } catch (e) {
        // 応答本文や API キーを含まない既存のエラーメッセージのみを保持する
        errors.set(p.index, e instanceof Error ? e.message : 'Unknown error');
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, pending.length) }, worker));
  return { results, errors, skipped: plan.skipped };
}
