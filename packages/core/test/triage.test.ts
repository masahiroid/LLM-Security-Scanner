import { describe, it, expect, vi } from 'vitest';
import { buildTriagePrompt, maskTriageSecrets, parseTriageResponse, triageFindingWithLlm, validateTriageEndpoint, triageContextBounds } from '../src';
import type { TriageRequestInput, TriageProvider } from '../src';
const input: TriageRequestInput = { ruleId: 'JS-CODEI-001', severity: 'high', message: 'unsafe', filePath: '/private/customer/app.ts', language: 'typescript', startLine: 2, endLine: 2, trace: [], sourceText: 'function run(value) {\n  eval(value);\n}', isJa: false };
const answer = { verdict: 'true_positive', confidence: 'high', reasoning: 'Unsafe execution', patchedCode: '  JSON.parse(value);', explanation: 'Parse data only' };
const response = (data: unknown, status = 200) => ({ ok: status === 200, status, text: async () => JSON.stringify(data), json: async () => data });
describe('optional AI triage privacy and provider contracts', () => {
  it('masks keys, credentials, bearer tokens and multiline private keys', () => {
    const value = 'sk-' + 'a'.repeat(30);
    const masked = maskTriageSecrets(`${value}\npassword = "private"\nBearer abc.def\n-----BEGIN RSA PRIVATE KEY-----\nkey\n-----END RSA PRIVATE KEY-----`);
    for (const secret of [value, 'private', 'abc.def', 'PRIVATE KEY']) expect(masked).not.toContain(secret);
  });
  it('masks metadata and snippets without altering local original code; omits file paths', () => {
    const secret = 'sk-' + 'z'.repeat(30);
    const result = buildTriagePrompt({ ...input, sourceText: `header\neval("${secret}");`, trace: [secret], message: secret });
    expect(result.userPrompt).not.toContain(secret);
    expect(result.userPrompt).not.toContain(input.filePath);
    expect(result.originalCode).toContain(secret);
  });
  it('does not send surrounding functions when bounded', async () => {
    const sourceText = 'function other() { return "private"; }\nfunction run(x) {\n eval(x);\n}\nfunction next() { return "secret"; }';
    const bounds = await triageContextBounds(sourceText, 'typescript', 2, 2);
    const prompt = buildTriagePrompt({ ...input, sourceText, startLine: 3, endLine: 3, ...bounds });
    expect(prompt.userPrompt).not.toContain('private'); expect(prompt.userPrompt).not.toContain('secret'); expect(prompt.userPrompt).toContain('function run');
  });
  it('bounds top-level findings to the target line', async () => {
    expect(await triageContextBounds('const privateValue = 1;\neval(x);', 'typescript', 1, 1)).toEqual({ contextStartLine: 2, contextEndLine: 2 });
  });
  it.each(['http://example.com/api', 'https://user:pass@example.com', 'https://example.com?key=secret', 'file:///etc/passwd'])('rejects unsafe destination %s', endpoint => {
    expect(() => validateTriageEndpoint(endpoint, 'openai')).toThrow();
  });
  it('allows local Ollama HTTP but forbids remote plaintext', () => {
    expect(() => validateTriageEndpoint('http://127.0.0.1:11434/api/chat', 'ollama')).not.toThrow();
    expect(() => validateTriageEndpoint('http://example.com/api/chat', 'ollama')).toThrow();
  });
  it.each(['openai', 'anthropic', 'ollama'] as TriageProvider[])('uses the %s wire format and parses responses', async provider => {
    const data = provider === 'openai' ? { choices: [{ message: { content: JSON.stringify(answer) } }] } : provider === 'anthropic' ? { content: [{ type: 'text', text: JSON.stringify(answer) }] } : { message: { content: JSON.stringify(answer) } };
    const fetcher = vi.fn(async () => response(data));
    const result = await triageFindingWithLlm(input, { provider, apiKey: 'test-key', model: 'test-model' }, fetcher);
    const init = fetcher.mock.calls[0] as unknown as [string, RequestInit];
    const body = JSON.parse(init[1].body as string);
    expect(body.model).toBe('test-model'); expect(init[1].redirect).toBe('error');
    if (provider === 'ollama') expect(body.stream).toBe(false);
    else expect(JSON.stringify(init[1].headers)).toContain('test-key');
    expect(result.verdict).toBe('true_positive'); expect(result.patchedCode).toBe(answer.patchedCode);
  });
  it('missing credentials and oversized snippets never call fetch', async () => {
    const fetcher = vi.fn();
    await expect(triageFindingWithLlm(input, { provider: 'openai' }, fetcher)).rejects.toThrow('API key');
    await expect(triageFindingWithLlm({ ...input, message: 'x'.repeat(30_000) }, { provider: 'ollama' }, fetcher)).rejects.toThrow('too large');
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('HTTP failures never expose echoed credentials or source', async () => {
    await expect(triageFindingWithLlm(input, { provider: 'ollama' }, async () => response({ secret: 'private source' }, 401))).rejects.toThrow(/^LLM API Error \(HTTP 401\)$/);
  });
  it('timeout aborts the request', async () => {
    const fetcher = vi.fn((_url: string, init: RequestInit) => new Promise<never>((_resolve, reject) => init.signal!.addEventListener('abort', () => reject(new Error('aborted')))));
    await expect(triageFindingWithLlm(input, { provider: 'ollama', timeoutMs: 1 }, fetcher)).rejects.toThrow('aborted');
  });
  it.each(['null', '[]', 'bad json', '{"verdict":"safe","patchedCode":"deleteAll()"}', '{"verdict":"true_positive","confidence":"high"}'])('invalid response cannot provide a patch: %s', raw => {
    const result = parseTriageResponse(raw, 'original', 'ollama', 'model');
    expect(result.verdict).toBe('needs_review'); expect(result.patchedCode).toBe('original');
  });
  it('accepts fenced valid JSON', () => {
    expect(parseTriageResponse('```json\n' + JSON.stringify(answer) + '\n```', 'original', 'ollama', 'model').verdict).toBe('true_positive');
  });
});
