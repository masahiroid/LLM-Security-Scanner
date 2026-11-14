import * as path from 'node:path';
import {
  DEFAULT_TRIAGE_CACHE_FILE, TRIAGE_API_KEY_ENV, TRIAGE_DEFAULT_CONCURRENCY, TRIAGE_DEFAULT_MAX_FINDINGS,
  TRIAGE_MAX_CONCURRENCY, validateTriageEndpoint, type Severity, type TriageConfig, type TriageProvider,
} from '@llmscan/core';
import { DEFAULT_TRIAGE_MIN_SEVERITY, SUPPORTED_PROVIDERS, SUPPORTED_SEVERITIES } from './constants';

export const TRIAGE_PARSE_OPTIONS = {
  triage: { type: 'boolean', default: false },
  'triage-dry-run': { type: 'boolean', default: false },
  'triage-provider': { type: 'string' },
  'triage-model': { type: 'string' },
  'triage-endpoint': { type: 'string' },
  'triage-min-severity': { type: 'string' },
  'triage-max-findings': { type: 'string' },
  'triage-concurrency': { type: 'string' },
  'triage-cache': { type: 'string' },
  'no-triage-cache': { type: 'boolean', default: false },
  'triage-ignore-false-positives': { type: 'boolean', default: false },
} as const;

export interface TriageCliOptions {
  dryRun: boolean;
  config: TriageConfig;
  minSeverity: Severity;
  maxFindings: number;
  concurrency: number;
  cacheFile?: string;
  ignoreFalsePositives: boolean;
}

type RawValues = Partial<Record<keyof typeof TRIAGE_PARSE_OPTIONS, string | boolean>>;

function positiveInt(raw: string | boolean | undefined, name: string, fallback: number, max = Number.MAX_SAFE_INTEGER): number {
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > max) throw new Error(`${name} は 1〜${max} の整数で指定してください`);
  return n;
}

/**
 * --triage / --triage-dry-run が無ければ undefined（通信しない）。
 * API キーは環境変数からのみ読み、引数では受け付けない。
 */
export function resolveTriageOptions(v: RawValues, root: string, env: NodeJS.ProcessEnv): TriageCliOptions | undefined {
  const dryRun = v['triage-dry-run'] === true;
  if (v.triage !== true && !dryRun) {
    if (v['triage-ignore-false-positives']) throw new Error('--triage-ignore-false-positives は --triage と併用してください');
    return undefined;
  }
  const provider = v['triage-provider'] as TriageProvider | undefined;
  if (!provider || !SUPPORTED_PROVIDERS.includes(provider)) {
    throw new Error(`--triage-provider を指定してください（${SUPPORTED_PROVIDERS.join(' / ')}）`);
  }
  const minSeverity = (v['triage-min-severity'] as Severity | undefined) ?? DEFAULT_TRIAGE_MIN_SEVERITY;
  if (!SUPPORTED_SEVERITIES.includes(minSeverity)) throw new Error('--triage-min-severity が不正です');
  const endpoint = v['triage-endpoint'] as string | undefined;
  if (endpoint) validateTriageEndpoint(endpoint, provider);

  const apiKey = env[TRIAGE_API_KEY_ENV]?.trim() || undefined;
  if (!dryRun && provider !== 'ollama' && !apiKey) {
    throw new Error(`${provider} の API キーを環境変数 ${TRIAGE_API_KEY_ENV} に設定してください`);
  }
  return {
    dryRun,
    config: { provider, apiKey, model: v['triage-model'] as string | undefined, endpoint },
    minSeverity,
    maxFindings: positiveInt(v['triage-max-findings'], '--triage-max-findings', TRIAGE_DEFAULT_MAX_FINDINGS),
    concurrency: positiveInt(v['triage-concurrency'], '--triage-concurrency', TRIAGE_DEFAULT_CONCURRENCY, TRIAGE_MAX_CONCURRENCY),
    cacheFile: v['no-triage-cache'] ? undefined : path.resolve(root, (v['triage-cache'] as string | undefined) ?? DEFAULT_TRIAGE_CACHE_FILE),
    ignoreFalsePositives: v['triage-ignore-false-positives'] === true,
  };
}
