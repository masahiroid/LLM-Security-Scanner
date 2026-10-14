import * as fs from 'node:fs';
import * as path from 'node:path';
import picomatch from 'picomatch';
import { DEFAULT_EXCLUDES } from './config';
import { languageForFile } from './parser';

/** 除外パターンの判定関数を作る（パスはルートからの相対・区切りは /） */
export function createExcludeMatcher(patterns: string[]): (relativePath: string) => boolean {
  const isMatch = picomatch([...DEFAULT_EXCLUDES, ...patterns], { dot: true });
  return (rel) => {
    const p = rel.replace(/\\/g, '/');
    // ディレクトリそのもの（"node_modules" 等）も除外できるよう末尾に / を付けて判定する
    return isMatch(p) || isMatch(p + '/');
  };
}

/** 対象ファイルを列挙する（ルートからの相対パスを返す） */
export function collectFiles(root: string, targets: string[], exclude: string[]): string[] {
  const excluded = createExcludeMatcher(exclude);
  const result = new Set<string>();

  const walk = (abs: string) => {
    const rel = path.relative(root, abs) || '.';
    if (rel !== '.' && excluded(rel)) return;
    let stat: fs.Stats;
    try {
      stat = fs.statSync(abs);
    } catch {
      return;
    }
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(abs).sort()) walk(path.join(abs, entry));
    } else if (stat.isFile() && languageForFile(abs)) {
      result.add(rel);
    }
  };

  for (const t of targets.length > 0 ? targets : ['.']) walk(path.resolve(root, t));
  return [...result];
}
