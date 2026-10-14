// llmscan テスト用フィクスチャ（別名 import・LLM クライアントの書き方の違い）
import { exec as run, execSync } from 'node:child_process';
import { Ollama } from 'ollama';
import OpenAI from 'openai';

const { exec: runCjs } = require('child_process');
const openai = new OpenAI();
const ollama = new Ollama({ host: 'http://localhost:11434' });

export async function aliasedExec() {
  const response = await openai.responses.create({ model: 'm', input: 'hi' });
  run(response.output_text); // expect: LLM05-CMDI-001
  runCjs(response.output_text); // expect: LLM05-CMDI-001
  // 安全：固定のコマンド
  run('date');
  execSync('date');
}

export async function ollamaClient() {
  const r = await ollama.chat({ model: 'm', messages: [] });
  eval(r.message.content); // expect: LLM05-CODEI-001
}

export async function unrelatedChat(room: { chat(): Promise<string> }) {
  // 安全：Ollama のクライアントではない chat()
  const text = await room.chat();
  console.log(text);
}

export async function sameNameInOtherScope() {
  const response = await openai.responses.create({ model: 'm', input: 'hi' });
  console.log(response.output_text);
}
export function otherScope(response: string) {
  // 別の関数の同名変数とはつながらない
  eval('1 + 1');
  return response;
}
