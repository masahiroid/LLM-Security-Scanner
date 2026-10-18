import * as fs from 'node:fs';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { KIND_META } from './rules';
import type { Confidence, CustomSinkRule, CustomSourceRule, ScanConfig, Severity, SinkKind } from './types';

export const CONFIG_FILES = ['.llmscan.yml', '.llmscan.yaml'];

export const DEFAULT_EXCLUDES = [
  '**/node_modules/**',
  '**/vendor/**',
  '**/.venv/**',
  '**/venv/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/__pycache__/**',
  '**/site-packages/**',
];

export const DEFAULT_CONFIG: ScanConfig = {
  minConfidence: 'medium',
  failOn: 'high',
  baseline: '.llmscan-baseline.json',
  exclude: [],
  sanitizers: {},
  sources: {},
  sinks: {},
};

const CONFIDENCES: Confidence[] = ['low', 'medium', 'high'];
const SEVERITIES: (Severity | 'none')[] = ['low', 'medium', 'high', 'critical', 'none'];
const SINK_KINDS = Object.keys(KIND_META) as SinkKind[];

function stringList(value: unknown, key: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string')) {
    throw new Error(`設定 ${key} は文字列の配列で指定してください`);
  }
  return value as string[];
}

function sourceList(value: unknown, key: string): CustomSourceRule[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new Error(`設定 ${key} は配列で指定してください`);
  return value.map((item, idx) => {
    if (typeof item === 'string') {
      return { pattern: item, kind: 'user', label: item };
    }
    if (!item || typeof item !== 'object' || typeof (item as Record<string, unknown>).pattern !== 'string') {
      throw new Error(`設定 ${key}[${idx}] には pattern (文字列) が必要です`);
    }
    const obj = item as Record<string, unknown>;
    const kind = obj.kind === 'llm' ? 'llm' : 'user';
    const label = typeof obj.label === 'string' ? obj.label : (obj.pattern as string);
    return { pattern: obj.pattern as string, kind, label };
  });
}

function sinkList(value: unknown, key: string): CustomSinkRule[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new Error(`設定 ${key} は配列で指定してください`);
  return value.map((item, idx) => {
    if (!item || typeof item !== 'object') {
      throw new Error(`設定 ${key}[${idx}] はオブジェクトで指定してください`);
    }
    const obj = item as Record<string, unknown>;
    if (typeof obj.pattern !== 'string') {
      throw new Error(`設定 ${key}[${idx}] には pattern (文字列) が必要です`);
    }
    const category = (obj.category ?? obj.kind) as SinkKind;
    if (!SINK_KINDS.includes(category)) {
      throw new Error(`設定 ${key}[${idx}].category は ${SINK_KINDS.join(' / ')} のいずれかです`);
    }
    const rule: CustomSinkRule = { pattern: obj.pattern, category };
    if (typeof obj.ruleId === 'string') rule.ruleId = obj.ruleId;
    if (typeof obj.severity === 'string' && obj.severity !== 'none' && SEVERITIES.includes(obj.severity as Severity)) {
      rule.severity = obj.severity as Severity;
    }
    if (typeof obj.argIndex === 'number') rule.argIndex = obj.argIndex;
    return rule;
  });
}

/** 設定ファイルの内容（YAML 文字列）を検証して ScanConfig にする */
export function parseConfig(text: string): ScanConfig {
  const raw = (parseYaml(text) ?? {}) as Record<string, unknown>;
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new Error('設定ファイルの形式が正しくありません');
  const config: ScanConfig = { ...DEFAULT_CONFIG, sanitizers: {}, sources: {}, sinks: {} };

  if (raw.minConfidence !== undefined) {
    if (!CONFIDENCES.includes(raw.minConfidence as Confidence)) {
      throw new Error(`minConfidence は ${CONFIDENCES.join(' / ')} のいずれかです`);
    }
    config.minConfidence = raw.minConfidence as Confidence;
  }
  if (raw.failOn !== undefined) {
    if (!SEVERITIES.includes(raw.failOn as Severity)) throw new Error(`failOn は ${SEVERITIES.join(' / ')} のいずれかです`);
    config.failOn = raw.failOn as Severity | 'none';
  }
  if (raw.baseline !== undefined) {
    if (typeof raw.baseline !== 'string') throw new Error('baseline はファイルパスで指定してください');
    config.baseline = raw.baseline;
  }
  config.exclude = stringList(raw.exclude, 'exclude');
  const san = raw.sanitizers as Record<string, unknown> | undefined;
  if (san) {
    for (const lang of ['python', 'javascript', 'php'] as const) {
      if (san[lang] !== undefined) config.sanitizers[lang] = stringList(san[lang], `sanitizers.${lang}`);
    }
  }
  const src = raw.sources as Record<string, unknown> | undefined;
  if (src && config.sources) {
    for (const lang of ['python', 'javascript', 'php'] as const) {
      if (src[lang] !== undefined) config.sources[lang] = sourceList(src[lang], `sources.${lang}`);
    }
  }
  const snk = raw.sinks as Record<string, unknown> | undefined;
  if (snk && config.sinks) {
    for (const lang of ['python', 'javascript', 'php'] as const) {
      if (snk[lang] !== undefined) config.sinks[lang] = sinkList(snk[lang], `sinks.${lang}`);
    }
  }
  return config;
}

/** ディレクトリ直下の設定ファイルを読む。なければ既定値 */
export function loadConfig(root: string): { config: ScanConfig; file?: string } {
  for (const name of CONFIG_FILES) {
    const file = path.join(root, name);
    if (fs.existsSync(file)) {
      try {
        return { config: parseConfig(fs.readFileSync(file, 'utf8')), file };
      } catch (e) {
        throw new Error(`${file}: ${(e as Error).message}`);
      }
    }
  }
  return { config: { ...DEFAULT_CONFIG, sanitizers: {}, sources: {}, sinks: {} } };
}
