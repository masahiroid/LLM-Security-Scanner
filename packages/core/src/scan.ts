import { createHash } from 'node:crypto';
import { analyze } from './engine';
import { javascript } from './languages/javascript';
import { php } from './languages/php';
import { python } from './languages/python';
import type { LanguageSpec } from './languages/spec';
import { getParser, languageForFile } from './parser';
import { SUPPRESSION_RULE_ID } from './rules';
import type { Confidence, Finding, LanguageId, ScanConfig } from './types';
import { DEFAULT_CONFIG } from './config';
import { CONFIDENCE_ORDER, FINGERPRINT_HASH_LENGTH, SUPPRESSION_COMMENT_PATTERN } from './constants';

const SPECS: Record<LanguageId, LanguageSpec> = {
  python,
  javascript,
  typescript: javascript,
  tsx: javascript,
  php,
};

export interface ScanSourceOptions {
  /** 指紋に使う相対パス（省略時は file） */
  relativePath?: string;
  language?: LanguageId;
  config?: ScanConfig;
}

interface Suppression {
  line: number;
  rules: string[] | 'all';
  valid: boolean;
  column: number;
  length: number;
}

export function parseSuppressions(lines: string[]): Suppression[] {
  const out: Suppression[] = [];
  lines.forEach((text, line) => {
    const m = SUPPRESSION_COMMENT_PATTERN.exec(text);
    if (!m) return;
    const rules = m[1] ? m[1].split(',').map((r) => r.trim()).filter(Boolean) : 'all';
    const reason = (m[2] ?? '').replace(/(\*\/|-->|\?>)\s*$/, '').trim();
    out.push({
      line,
      rules: rules.length === 0 ? 'all' : rules,
      valid: reason.length > 0 && !/^TODO\b/i.test(reason),
      column: m.index,
      length: m[0].length,
    });
  });
  return out;
}

function normalizeLine(text: string): string {
  return text.trim().replace(/\s+/g, ' ');
}

export function fingerprintOf(f: Omit<Finding, 'fingerprint'>, relPath: string, lines: string[]): string {
  const lineText = normalizeLine(lines[f.range.start.line] ?? '');
  return createHash('sha256')
    .update(`${f.ruleId}|${relPath.replace(/\\/g, '/')}|${f.functionName}|${lineText}`)
    .digest('hex')
    .slice(0, FINGERPRINT_HASH_LENGTH);
}

function memoizedMentions(text: string): (re: RegExp) => boolean {
  const cache = new Map<string, boolean>();
  return (re) => {
    let hit = cache.get(re.source);
    if (hit === undefined) {
      hit = re.test(text);
      cache.set(re.source, hit);
    }
    return hit;
  };
}

export function meetsConfidence(f: Finding, min: Confidence): boolean {
  return CONFIDENCE_ORDER[f.confidence] >= CONFIDENCE_ORDER[min];
}

/**
 * ソースコード 1 ファイルを解析する。
 * 抑制コメント（理由あり）で抑制された指摘は除き、理由のない抑制コメントは指摘として返す。
 * 確信度での絞り込みは呼び出し側で行う（meetsConfidence）。
 */
export async function scanSource(text: string, file: string, options: ScanSourceOptions = {}): Promise<Finding[]> {
  const language = options.language ?? languageForFile(file);
  if (!language) return [];
  const config = options.config ?? DEFAULT_CONFIG;
  const spec = SPECS[language];
  const parser = await getParser(language);
  const tree = parser.parse(text);
  if (!tree) return [];
  const family = spec.family;
  const raw = (() => {
    try {
      return analyze({
        root: tree.rootNode,
        file,
        language,
        spec,
        ctx: {
          mentions: memoizedMentions(text),
          customSanitizers: config.sanitizers[family] ?? [],
          customSources: config.sources?.[family] ?? [],
          customSinks: config.sinks?.[family] ?? [],
        },
      });
    } finally {
      tree.delete();
    }
  })();

  const lines = text.split(/\r?\n/);
  const suppressions = parseSuppressions(lines);
  const relPath = options.relativePath ?? file;
  const results: Finding[] = [];
  const seen = new Map<string, number>();

  const isSuppressed = (f: Omit<Finding, 'fingerprint'>): boolean => {
    const anchorLine = f.trace[f.trace.length - 1]?.range.start.line ?? f.range.start.line;
    const candidates = new Set([f.range.start.line, f.range.start.line - 1, anchorLine, anchorLine - 1]);
    return suppressions.some(
      (s) => s.valid && candidates.has(s.line) && (s.rules === 'all' || s.rules.includes(f.ruleId)),
    );
  };

  const push = (f: Omit<Finding, 'fingerprint'>) => {
    let fp = fingerprintOf(f, relPath, lines);
    const n = seen.get(fp) ?? 0;
    seen.set(fp, n + 1);
    if (n > 0) fp = `${fp}-${n}`;
    results.push({ ...f, fingerprint: fp });
  };

  for (const f of raw) {
    if (!isSuppressed(f)) push(f);
  }
  for (const s of suppressions) {
    if (s.valid) continue;
    const range = { start: { line: s.line, column: s.column }, end: { line: s.line, column: s.column + s.length } };
    push({
      ruleId: SUPPRESSION_RULE_ID,
      kind: 'suppression',
      severity: 'low',
      confidence: 'high',
      origin: 'none',
      message: '抑制コメントに理由がありません。`llmscan-ignore[ルールID]: 理由` の形で理由を書いてください（理由がない抑制は無効です）',
      file,
      language,
      range,
      trace: [],
      functionName: '<suppression>',
    });
  }
  results.sort((a, b) => a.range.start.line - b.range.start.line || a.range.start.column - b.range.start.column);
  return results;
}
