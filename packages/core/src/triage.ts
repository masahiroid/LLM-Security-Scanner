import { ANTHROPIC_API_VERSION, DEFAULT_TRIAGE_ENDPOINTS, DEFAULT_TRIAGE_MODELS,
  TRIAGE_MAX_TOKENS, TRIAGE_REQUEST_TIMEOUT_MS, TRIAGE_MAX_RESPONSE_CHARS, TRIAGE_TEMPERATURE } from './constants';
import type { TriageConfig, TriageRequestInput, TriageResult } from './types';
import { buildTriagePrompt } from './triage-prompt';
import { parseTriageResponse } from './triage-response';
export { buildTriagePrompt, extractCodeSnippet, maskTriageSecrets, type ExtractedSnippet } from './triage-prompt';
export { parseTriageResponse } from './triage-response';

export type FetchLike = (url: string, init: RequestInit) => Promise<{
  ok: boolean;
  status: number;
  text: () => Promise<string>;
  json: () => Promise<unknown>;
}>;

/**
 * 指定された BYOK プロバイダ（OpenAI / Anthropic / ローカル Ollama）を呼び出して
 * 静的解析の指摘を AI トリアージし、修正パッチ案を返す
 */
export async function triageFindingWithLlm(
  input: TriageRequestInput,
  config: TriageConfig,
  fetchImpl: FetchLike = globalThis.fetch as unknown as FetchLike,
): Promise<TriageResult> {
  const provider = config.provider;
  if (!['openai', 'anthropic', 'ollama'].includes(provider)) throw new Error('Unsupported triage provider');
  const model = config.model?.trim() || DEFAULT_TRIAGE_MODELS[provider];
  const endpoint = config.endpoint?.trim() || DEFAULT_TRIAGE_ENDPOINTS[provider];
  validateTriageEndpoint(endpoint, provider);
  const timeoutMs = config.timeoutMs ?? TRIAGE_REQUEST_TIMEOUT_MS;

  if ((provider === 'openai' || provider === 'anthropic') && !config.apiKey?.trim()) {
    throw new Error(
      input.isJa !== false
        ? `${provider} の API キーが設定されていません。コマンド「LLMScan: AI トリアージ設定 (API キー / プロバイダ)」から設定してください。`
        : `API key for ${provider} is not configured. Please run "LLMScan: Configure AI Triage (API Key / Provider)" first.`,
    );
  }

  const { systemPrompt, userPrompt, originalCode } = buildTriagePrompt(input);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  let body: Record<string, unknown>;

  if (provider === 'openai') {
    headers['Authorization'] = `Bearer ${config.apiKey!.trim()}`;
    body = {
      model,
      temperature: TRIAGE_TEMPERATURE,
      max_tokens: TRIAGE_MAX_TOKENS,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
    };
  } else if (provider === 'anthropic') {
    headers['x-api-key'] = config.apiKey!.trim();
    headers['anthropic-version'] = ANTHROPIC_API_VERSION;
    body = {
      model,
      max_tokens: TRIAGE_MAX_TOKENS,
      temperature: TRIAGE_TEMPERATURE,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }],
    };
  } else {
    body = {
      model,
      stream: false,
      format: 'json',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let responseText = '';
  try {
    const res = await fetchImpl(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: 'error',
    });
    if (!res.ok) {
      throw new Error(`LLM API Error (HTTP ${res.status})`);
    }
    const raw = await res.text();
    if (raw.length > TRIAGE_MAX_RESPONSE_CHARS) throw new Error('LLM response too large');
    const data = JSON.parse(raw) as Record<string, unknown>;
    if (!data || typeof data !== 'object') throw new Error('Invalid LLM response');
    if (provider === 'openai') {
      const choices = data.choices as Array<{ message?: { content?: string } }> | undefined;
      responseText = choices?.[0]?.message?.content ?? '';
    } else if (provider === 'anthropic') {
      const content = data.content as Array<{ type?: string; text?: string }> | undefined;
      responseText = content?.find((c) => c.type === 'text')?.text ?? '';
    } else {
      const message = data.message as { content?: string } | undefined;
      responseText = message?.content ?? '';
    }
  } finally {
    clearTimeout(timer);
  }

  return parseTriageResponse(responseText, originalCode, provider, model);
}


export function validateTriageEndpoint(endpoint: string, provider: TriageConfig['provider']): void {
  const url = new URL(endpoint);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || url.search || url.hash ||
      (url.protocol !== 'https:' && !(provider === 'ollama' && loopback && url.protocol === 'http:'))) {
    throw new Error('Use HTTPS, or loopback HTTP for local Ollama; credentials, queries and fragments are forbidden.');
  }
}
