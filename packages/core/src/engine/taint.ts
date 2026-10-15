import { MAX_TRACE_STEPS, ORIGIN_PRIORITY } from '../constants';
import type { OriginKind, SinkKind, TraceStep } from '../types';

/** 汚染された値の情報。null は「汚染されていない」 */
export interface Taint {
  origin: OriginKind;
  trace: TraceStep[];
  /** この種類の危険な処理に対しては無害化済み */
  sanitized: ReadonlySet<SinkKind>;
  /** 文字列の連結・埋め込みで組み立てられた値か */
  built: boolean;
  /** 無害化の有無が分からない関数を経由したか（確信度を下げる） */
  uncertain: boolean;
}

export type T = Taint | null;

export const NO_SANITIZE: ReadonlySet<SinkKind> = new Set();

/** 2つの汚染情報をマージする（片方または両方が汚染されている場合） */
export function union(a: T, b: T, built = false): T {
  if (!a && !b) return null;
  if (!a || !b) {
    const t = (a ?? b)!;
    return built && !t.built ? { ...t, built: true } : t;
  }
  const primary = ORIGIN_PRIORITY[b.origin] > ORIGIN_PRIORITY[a.origin] ? b : a;
  const sanitized = new Set([...a.sanitized].filter((k) => b.sanitized.has(k)));
  return { ...primary, sanitized, built: built || a.built || b.built };
}

/** トレース経路にステップを追加する（最大ステップ数を超えた場合は中抜けして圧縮） */
export function addStep(t: T, s: TraceStep): T {
  if (!t) return null;
  const trace =
    t.trace.length >= MAX_TRACE_STEPS
      ? [...t.trace.slice(0, 1), ...t.trace.slice(-(MAX_TRACE_STEPS - 2)), s]
      : [...t.trace, s];
  return { ...t, trace };
}

/** 新しい汚染源（Source）の Taint を生成する */
export function createSourceTaint(
  origin: 'user' | 'llm',
  stepItem: TraceStep,
): Taint {
  return {
    origin,
    trace: [stepItem],
    sanitized: NO_SANITIZE,
    built: false,
    uncertain: false,
  };
}

