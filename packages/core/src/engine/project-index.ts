import type { Family } from '../languages/spec';
import type { Summary } from './summary';

/**
 * ワークスペース内の複数ファイルをまたぐ関数要約（Function Summary）を管理するインデックス。
 * 単一責任としてファイル別の関数要約登録・更新・再集計を担当する。
 */
export class ProjectIndex {
  private readonly fileEntries = new Map<
    string,
    { family: Family; summaries: Map<string, Summary> }
  >();
  private readonly familyCache = new Map<Family, Map<string, Summary>>();

  /**
   * 1 ファイル分の関数要約を登録または更新する
   */
  updateFile(file: string, family: Family, summaries: Map<string, Summary>): void {
    this.fileEntries.set(file, { family, summaries });
    this.familyCache.delete(family);
  }

  /**
   * 削除または対象外となったファイルの関数要約を除外する
   */
  removeFile(file: string): void {
    const existing = this.fileEntries.get(file);
    if (!existing) return;
    this.fileEntries.delete(file);
    this.familyCache.delete(existing.family);
  }

  /**
   * 全インデックスをクリアする
   */
  clear(): void {
    this.fileEntries.clear();
    this.familyCache.clear();
  }

  /**
   * 指定した言語ファミリーに属する全ファイルの関数要約マップを取得する。
   * 同名関数が複数ファイルで定義されており、かつ意味のある要約（source / sanitizes / sinks）が
   * 衝突する場合は安全側の要約を統合する。
   */
  getSummaries(family: Family): ReadonlyMap<string, Summary> {
    const cached = this.familyCache.get(family);
    if (cached) return cached;

    const merged = new Map<string, Summary>();
    for (const entry of this.fileEntries.values()) {
      if (entry.family !== family) continue;
      for (const [fnName, summary] of entry.summaries.entries()) {
        const prev = merged.get(fnName);
        if (!prev) {
          merged.set(fnName, summary);
        } else {
          merged.set(fnName, mergeSummaries(prev, summary));
        }
      }
    }

    this.familyCache.set(family, merged);
    return merged;
  }
}

function mergeSummaries(a: Summary, b: Summary): Summary {
  const mergedSinks = [...(a.sinks ?? []), ...(b.sinks ?? [])].filter(
    (s, idx, arr) =>
      arr.findIndex((x) => x.kind === s.kind && x.sinkLabel === s.sinkLabel) === idx,
  );
  const base: Summary =
    a.type === 'source'
      ? a
      : b.type === 'source'
        ? b
        : a.type === 'sanitizes'
          ? a
          : b.type === 'sanitizes'
            ? b
            : a.type === 'keep'
              ? a
              : b;
  return mergedSinks.length > 0 ? { ...base, sinks: mergedSinks } : base;
}
