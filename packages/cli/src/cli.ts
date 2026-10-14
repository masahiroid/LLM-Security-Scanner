import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseArgs } from 'node:util';
import {
  type Confidence,
  type Finding,
  type ScanConfig,
  type Severity,
  SEVERITY_ORDER,
  collectFiles,
  createBaseline,
  initParsers,
  loadConfig,
  meetsConfidence,
  readBaseline,
  scanSource,
  toSarif,
  writeBaseline,
} from '@llmscan/core';

const VERSION = '0.1.0';

const HELP = `LLM Security Scanner ${VERSION}（コマンド名: llmscan）

使い方:
  llmscan scan [パス...] [オプション]

オプション:
  --format <text|json|sarif>   出力形式（既定: text）
  --output <ファイル>           結果をファイルに書き出す（既定: 標準出力）
  --root <ディレクトリ>         プロジェクトのルート（既定: カレントディレクトリ）
  --config <ファイル>           設定ファイル（既定: <root>/.llmscan.yml）
  --baseline <ファイル>         ベースライン（既定: 設定の baseline）
  --no-baseline                 ベースラインを使わない
  --update-baseline             現在の指摘でベースラインを作成・更新する
  --min-confidence <low|medium|high>
  --fail-on <low|medium|high|critical|none>
                                ベースライン外にこの重大度以上の指摘があれば終了コード 1
  -h, --help

終了コード: 0 = 問題なし / 1 = 失敗条件の指摘あり / 2 = 実行エラー
`;

interface Item {
  finding: Finding;
  relativePath: string;
}

function wasmDir(): string | undefined {
  // バンドル版は dist/wasm に WASM を同梱する
  const dir = path.join(__dirname, 'wasm');
  return fs.existsSync(path.join(dir, 'tree-sitter.wasm')) ? dir : undefined;
}

function formatText(items: Item[], baselined: number, scanned: number): string {
  const lines: string[] = [];
  const sevLabel: Record<Severity, string> = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };
  for (const { finding: f, relativePath } of items) {
    lines.push(
      `${relativePath}:${f.range.start.line + 1}:${f.range.start.column + 1}  ${sevLabel[f.severity]}  ${f.ruleId}  (確信度: ${f.confidence})`,
    );
    lines.push(`  ${f.message}`);
    for (const s of f.trace) lines.push(`    ${s.range.start.line + 1}行目: ${s.message}`);
    lines.push('');
  }
  const counts = (['critical', 'high', 'medium', 'low'] as Severity[])
    .map((s) => `${sevLabel[s]} ${items.filter((i) => i.finding.severity === s).length}`)
    .join(' / ');
  lines.push(`${scanned} ファイルを解析: 指摘 ${items.length} 件（${counts}）` + (baselined > 0 ? `、ベースラインで除外 ${baselined} 件` : ''));
  return lines.join('\n') + '\n';
}

async function scan(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      format: { type: 'string', default: 'text' },
      output: { type: 'string' },
      root: { type: 'string' },
      config: { type: 'string' },
      baseline: { type: 'string' },
      'no-baseline': { type: 'boolean', default: false },
      'update-baseline': { type: 'boolean', default: false },
      'min-confidence': { type: 'string' },
      'fail-on': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  if (values.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (!['text', 'json', 'sarif'].includes(values.format!)) throw new Error(`--format が不正です: ${values.format}`);

  const root = path.resolve(values.root ?? process.cwd());
  let config: ScanConfig;
  if (values.config) {
    const dir = path.dirname(path.resolve(values.config));
    const loaded = loadConfig(dir);
    if (!loaded.file) throw new Error(`設定ファイルが見つかりません: ${values.config}`);
    config = loaded.config;
  } else {
    config = loadConfig(root).config;
  }
  if (values['min-confidence']) {
    if (!['low', 'medium', 'high'].includes(values['min-confidence'])) throw new Error('--min-confidence が不正です');
    config.minConfidence = values['min-confidence'] as Confidence;
  }
  if (values['fail-on']) {
    if (!['low', 'medium', 'high', 'critical', 'none'].includes(values['fail-on'])) throw new Error('--fail-on が不正です');
    config.failOn = values['fail-on'] as Severity | 'none';
  }

  await initParsers({ wasmDir: wasmDir() });
  const files = collectFiles(root, positionals, config.exclude);
  const all: Item[] = [];
  for (const rel of files) {
    const abs = path.join(root, rel);
    let text: string;
    try {
      text = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    if (text.length > 2_000_000) continue; // 巨大な生成ファイルは対象外
    const findings = await scanSource(text, abs, { relativePath: rel, config });
    for (const finding of findings) {
      if (meetsConfidence(finding, config.minConfidence)) all.push({ finding, relativePath: rel });
    }
  }

  const baselinePath = path.resolve(root, values.baseline ?? config.baseline);
  if (values['update-baseline']) {
    writeBaseline(baselinePath, createBaseline(all));
    process.stderr.write(`ベースラインを更新しました: ${path.relative(process.cwd(), baselinePath)}（${all.length} 件）\n`);
    return 0;
  }

  const known = values['no-baseline'] ? undefined : readBaseline(baselinePath);
  const items = known ? all.filter((i) => !known.has(i.finding.fingerprint)) : all;
  const baselined = all.length - items.length;

  let out: string;
  if (values.format === 'json') {
    out = JSON.stringify({ version: VERSION, findings: items.map((i) => ({ ...i.finding, file: i.relativePath })) }, null, 2) + '\n';
  } else if (values.format === 'sarif') {
    out = JSON.stringify(toSarif(items, VERSION), null, 2) + '\n';
  } else {
    out = formatText(items, baselined, files.length);
  }
  if (values.output) fs.writeFileSync(values.output, out);
  else process.stdout.write(out);

  if (config.failOn === 'none') return 0;
  const threshold = SEVERITY_ORDER[config.failOn];
  return items.some((i) => i.finding.kind !== 'suppression' && SEVERITY_ORDER[i.finding.severity] >= threshold) ? 1 : 0;
}

async function main(): Promise<number> {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === '-h' || command === '--help') {
    process.stdout.write(HELP);
    return command ? 0 : 2;
  }
  if (command === '--version' || command === '-v') {
    process.stdout.write(VERSION + '\n');
    return 0;
  }
  if (command !== 'scan') {
    process.stderr.write(`不明なコマンドです: ${command}\n\n${HELP}`);
    return 2;
  }
  return scan(rest);
}

main().then(
  (code) => process.exit(code),
  (e: unknown) => {
    process.stderr.write(`llmscan: ${(e as Error).message}\n`);
    process.exit(2);
  },
);
