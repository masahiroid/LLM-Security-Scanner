import type { Confidence, Severity, TriageProvider } from '@llmscan/core';

export const EXIT_CODE_CLEAN = 0;
export const EXIT_CODE_FINDINGS = 1;
export const EXIT_CODE_ERROR = 2;

export const SUPPORTED_FORMATS = ['text', 'json', 'sarif'] as const;
export type OutputFormat = (typeof SUPPORTED_FORMATS)[number];
export const SUPPORTED_CONFIDENCES: Confidence[] = ['low', 'medium', 'high'];
export const SUPPORTED_FAIL_ON: (Severity | 'none')[] = ['low', 'medium', 'high', 'critical', 'none'];
export const SUPPORTED_SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical'];
export const SUPPORTED_PROVIDERS: TriageProvider[] = ['openai', 'anthropic', 'ollama'];

/** CLI の AI トリアージで既定とする最小重大度（コスト抑制のため高めに設定） */
export const DEFAULT_TRIAGE_MIN_SEVERITY: Severity = 'high';
