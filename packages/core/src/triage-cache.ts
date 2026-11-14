import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TRIAGE_CACHE_FORMAT_VERSION, TRIAGE_CACHE_MAX_REASONING_CHARS } from './constants';
import type { Confidence, TriageProvider, TriageSummary, TriageVerdict } from './types';

export type CachedTriage = Omit<TriageSummary, 'cached'>;
export type TriageCache = Map<string, CachedTriage>;

const VERDICTS: TriageVerdict[] = ['true_positive', 'false_positive', 'needs_review'];
const CONFIDENCES: Confidence[] = ['high', 'medium', 'low'];
const PROVIDERS: TriageProvider[] = ['openai', 'anthropic', 'ollama'];

/** 送信内容そのもの（マスク済みプロンプト）とモデルからキーを作る。ファイルパスは含めない */
export function triageCacheKey(systemPrompt: string, userPrompt: string, provider: TriageProvider, model: string): string {
  return createHash('sha256').update(JSON.stringify([provider, model, systemPrompt, userPrompt])).digest('hex');
}

function isCachedTriage(value: unknown): value is CachedTriage {
  const v = value as Record<string, unknown> | null;
  return !!v && typeof v === 'object' &&
    VERDICTS.includes(v.verdict as TriageVerdict) &&
    CONFIDENCES.includes(v.confidence as Confidence) &&
    PROVIDERS.includes(v.provider as TriageProvider) &&
    typeof v.reasoning === 'string' && typeof v.model === 'string';
}

/** 壊れた・形式違いのキャッシュは空として扱う（再判定されるだけで安全側） */
export function readTriageCache(file: string): TriageCache {
  const cache: TriageCache = new Map();
  let data: { version?: unknown; entries?: unknown };
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return cache;
  }
  if (data?.version !== TRIAGE_CACHE_FORMAT_VERSION || !data.entries || typeof data.entries !== 'object') return cache;
  for (const [key, value] of Object.entries(data.entries as Record<string, unknown>)) {
    if (isCachedTriage(value)) cache.set(key, value);
  }
  return cache;
}

export function writeTriageCache(file: string, cache: TriageCache): void {
  const entries: Record<string, CachedTriage> = {};
  for (const [key, v] of cache) {
    entries[key] = { verdict: v.verdict, confidence: v.confidence, reasoning: v.reasoning.slice(0, TRIAGE_CACHE_MAX_REASONING_CHARS), provider: v.provider, model: v.model };
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ version: TRIAGE_CACHE_FORMAT_VERSION, entries }, null, 2) + '\n');
}
