import type { Confidence, SinkKind } from '../types';
import type { Taint } from './taint';

/**
 * 汚染情報と対象 Sink の種類から確信度（high / medium / low）を算出する
 */
export function confidenceOf(t: Taint, kind: SinkKind): Confidence {
  if (t.origin === 'param') {
    // 引数から HTML を組み立てるのはよくある書き方で、多くは信頼できるデータのため low に留める
    if (!t.built || kind === 'xss') return 'low';
    return t.uncertain ? 'low' : 'medium';
  }
  return t.uncertain ? 'medium' : 'high';
}

