import * as fs from 'node:fs';
import type { Finding } from './types';

export interface BaselineEntry {
  fingerprint: string;
  ruleId: string;
  file: string;
  /** 参考情報（照合には使わない） */
  line: number;
}

export interface Baseline {
  version: 1;
  generatedAt: string;
  findings: BaselineEntry[];
}

export function createBaseline(findings: { finding: Finding; relativePath: string }[]): Baseline {
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    findings: findings
      .map(({ finding, relativePath }) => ({
        fingerprint: finding.fingerprint,
        ruleId: finding.ruleId,
        file: relativePath.replace(/\\/g, '/'),
        line: finding.range.start.line + 1,
      }))
      .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line),
  };
}

export function readBaseline(file: string): Set<string> | undefined {
  if (!fs.existsSync(file)) return undefined;
  const data = JSON.parse(fs.readFileSync(file, 'utf8')) as Baseline;
  if (data.version !== 1 || !Array.isArray(data.findings)) {
    throw new Error(`${file}: ベースラインの形式が正しくありません`);
  }
  return new Set(data.findings.map((f) => f.fingerprint));
}

export function writeBaseline(file: string, baseline: Baseline): void {
  fs.writeFileSync(file, JSON.stringify(baseline, null, 2) + '\n');
}
