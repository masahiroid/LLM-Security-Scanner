import { TRIAGE_JSON_FENCE_PATTERN } from './constants';
import type { Confidence, TriageConfig, TriageResult, TriageVerdict } from './types';

/**
 * LLM の応答テキストから JSON を抽出・正規化して TriageResult を生成する
 */
export function parseTriageResponse(
  rawText: string,
  originalCode: string,
  provider: TriageConfig['provider'],
  model: string,
): TriageResult {
  const fenceMatch = TRIAGE_JSON_FENCE_PATTERN.exec(rawText);
  const candidate = fenceMatch ? fenceMatch[1].trim() : rawText.trim();
  const braceStart = candidate.indexOf('{');
  const braceEnd = candidate.lastIndexOf('}');
  const jsonSlice =
    braceStart >= 0 && braceEnd > braceStart ? candidate.slice(braceStart, braceEnd + 1) : candidate;

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(jsonSlice) as Record<string, unknown>;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) ||
        !['true_positive', 'false_positive', 'needs_review'].includes(String(parsed.verdict)) ||
        !['high', 'medium', 'low'].includes(String(parsed.confidence)) ||
        !['reasoning', 'patchedCode', 'explanation'].every(key => typeof parsed[key] === 'string')) throw new Error('Invalid object');
  } catch {
    return {
      verdict: 'needs_review',
      confidence: 'low',
      reasoning: rawText.trim() || 'Failed to parse structured JSON response from LLM.',
      patchedCode: originalCode,
      explanation: '',
      provider,
      model,
      originalCode,
    };
  }

  const validVerdicts: TriageVerdict[] = ['true_positive', 'false_positive', 'needs_review'];
  const verdict: TriageVerdict = validVerdicts.includes(parsed.verdict as TriageVerdict)
    ? (parsed.verdict as TriageVerdict)
    : 'needs_review';

  const validConfidences: Confidence[] = ['high', 'medium', 'low'];
  const confidence: Confidence = validConfidences.includes(parsed.confidence as Confidence)
    ? (parsed.confidence as Confidence)
    : 'medium';

  const reasoning = typeof parsed.reasoning === 'string' && parsed.reasoning.trim()
    ? parsed.reasoning.trim()
    : 'No reasoning provided.';
  const patchedCode = typeof parsed.patchedCode === 'string' && parsed.patchedCode.length > 0
    ? parsed.patchedCode.replace(/\r\n/g, '\n')
    : originalCode;
  const explanation = typeof parsed.explanation === 'string' ? parsed.explanation.trim() : '';

  return {
    verdict,
    confidence,
    reasoning,
    patchedCode,
    explanation,
    provider,
    model,
    originalCode,
  };
}

