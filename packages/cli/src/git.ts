import { execFileSync } from 'node:child_process';

/** Git で変更されたファイル（ルート相対・/ 区切り）を返す */
export function getGitChangedFiles(root: string, diffBase?: string): Set<string> {
  const ref = diffBase ?? 'HEAD';
  const out = new Set<string>();
  try {
    const diffOut = execFileSync('git', ['diff', '--name-only', '--diff-filter=ACMRTUXB', ref], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    for (const line of diffOut.split(/\r?\n/)) {
      const trimmed = line.trim().replace(/\\/g, '/');
      if (trimmed) out.add(trimmed);
    }
    if (!diffBase) {
      const untrackedOut = execFileSync('git', ['ls-files', '--others', '--exclude-standard'], {
        cwd: root,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      for (const line of untrackedOut.split(/\r?\n/)) {
        const trimmed = line.trim().replace(/\\/g, '/');
        if (trimmed) out.add(trimmed);
      }
    }
  } catch (e) {
    throw new Error(`Git 差分の取得に失敗しました (${ref}): ${(e as Error).message}`);
  }
  return out;
}
