import * as fs from 'node:fs';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { Confidence, ScanConfig, Severity } from './types';

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
};

const CONFIDENCES: Confidence[] = ['low', 'medium', 'high'];
const SEVERITIES: (Severity | 'none')[] = ['low', 'medium', 'high', 'critical', 'none'];

function stringList(value: unknown, key: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string')) {
    throw new Error(`設定 ${key} は文字列の配列で指定してください`);
  }
  return value as string[];
}

/** 設定ファイルの内容（YAML 文字列）を検証して ScanConfig にする */
export function parseConfig(text: string): ScanConfig {
  const raw = (parseYaml(text) ?? {}) as Record<string, unknown>;
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new Error('設定ファイルの形式が正しくありません');
  const config: ScanConfig = { ...DEFAULT_CONFIG, sanitizers: {} };

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
  return { config: { ...DEFAULT_CONFIG, sanitizers: {} } };
}
