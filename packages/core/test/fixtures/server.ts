// llmscan テスト用フィクスチャ（意図的に脆弱なコード）
import { exec, execFile } from 'node:child_process';
import express from 'express';
import OpenAI from 'openai';
import { generateText } from 'ai';
import mysql from 'mysql2/promise';

const app = express();
const openai = new OpenAI();
const db = await mysql.createConnection({});

app.get('/user', async (req, res) => {
  const id = req.query.id as string;
  await db.query(`SELECT * FROM users WHERE id = ${id}`); // expect: JS-SQLI-001
  await db.query('SELECT * FROM users WHERE id = ' + id); // expect: JS-SQLI-001
  // 安全：プレースホルダ
  await db.query('SELECT * FROM users WHERE id = ?', [id]);
  // 安全：数値化
  await db.query('SELECT * FROM users WHERE id = ' + Number(id));
  res.send('ok');
});

app.post('/convert', (req, res) => {
  const { file } = req.body;
  exec(`convert ${file} out.png`); // expect: JS-CMDI-001
  // 安全：引数を配列で渡す
  execFile('convert', [file, 'out.png']);
  res.send('ok');
});

app.post('/eval', (req, res) => {
  res.send(String(eval(req.body.expr))); // expect: JS-CODEI-001
});

export async function summarize(userText: string) {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: userText }],
  });
  const html = completion.choices[0].message.content ?? '';
  document.getElementById('out')!.innerHTML = html; // expect: LLM05-XSS-001
  document.getElementById('out')!.textContent = html;
  const fn = new Function(html); // expect: LLM05-CODEI-001
  return fn;
}

export async function aiSql(question: string) {
  const { text } = await generateText({ model: 'x' as any, prompt: question });
  return db.query(text); // expect: LLM05-SQLI-001
}

export function Preview({ markdown }: { markdown: string }) {
  // 引数から HTML を組み立てるだけなら確信度 low（既定では表示しない）
  return { dangerouslySetInnerHTML: { __html: '<div>' + markdown + '</div>' } };
}

export function Comment() {
  const body = new URLSearchParams(location.search).get('c');
  return { dangerouslySetInnerHTML: { __html: '<p>' + body + '</p>' } }; // expect: JS-XSS-001
}

const SORTS = ['name', 'created_at'];
export async function sorted(req: any) {
  const s = req.query.sort;
  const sort = SORTS.includes(s) ? s : 'name';
  // 許可リストで検証済み
  return db.query('SELECT * FROM items ORDER BY ' + sort);
}

export function showQuery() {
  const q = new URLSearchParams(location.search).get('q') ?? '';
  document.write('<p>' + q + '</p>'); // expect: JS-XSS-001
  const safe = encodeURIComponent(q);
  document.write('<p>' + safe + '</p>');
}

export async function prismaSafe(prisma: any, name: string) {
  // 安全：タグ付きテンプレートはライブラリ側でパラメータ化される
  return prisma.$queryRaw`SELECT * FROM users WHERE name = ${name}`;
}

export async function prismaUnsafe(prisma: any, name: string) {
  return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name = '${name}'`); // expect: JS-SQLI-001
}

const re = /a+/;
export function notCommand(input: string) {
  // RegExp#exec はコマンド実行ではない
  return re.exec(input);
}
