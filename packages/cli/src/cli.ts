import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseArgs } from 'node:util';
import {
  type Confidence,
  type Finding,
  MAX_FILE_SIZE_BYTES,
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

const VERSION = '1.4.0';
const EXIT_CODE_CLEAN = 0;
const EXIT_CODE_FINDINGS = 1;
const EXIT_CODE_ERROR = 2;

const SUPPORTED_FORMATS = ['text', 'json', 'sarif'] as const;
const SUPPORTED_CONFIDENCES: Confidence[] = ['low', 'medium', 'high'];
const SUPPORTED_FAIL_ON: (Severity | 'none')[] = ['low', 'medium', 'high', 'critical', 'none'];

const HELP = `LLM Security Scanner ${VERSION}（コマンド名: llmscan）

使い方:
  llmscan scan [パス...] [オプション]

オプション:
  --format <text|json|sarif>   出力形式（既定: text）
  --output <ファイル>           結果をファイルに書き出す（既定: 標準出力）
  --root <ディレクトリ>         プロジェクトのルート（既定: カレントディレクトリ）
  --config <ファイル>           設定ファイル（既定: <root>/.llmscan.yml）
  --changed-only                Git で変更されたファイルのみをスキャン（HEAD との差分＋未追跡ファイル）
  --diff-base <Git参照>         指定した Git 参照（例: origin/main）から変更されたファイルのみをスキャン
  --baseline <ファイル>         ベースライン（既定: 設定の baseline）
  --no-baseline                 ベースラインを使わない
  --update-baseline             現在の指摘でベースラインを作成・更新する
  --min-confidence <low|medium|high>
  --fail-on <low|medium|high|critical|none>
                                ベースライン外にこの重大度以上の指摘があれば終了コード 1
  -h, --help

終了コード: ${EXIT_CODE_CLEAN} = 問題なし / ${EXIT_CODE_FINDINGS} = 失敗条件の指摘あり / ${EXIT_CODE_ERROR} = 実行エラー
`;

interface Item {
  finding: Finding;
  relativePath: string;
}

function getGitChangedFiles(root: string, diffBase?: string): Set<string> {
  const ref = diffBase ?? 'HEAD';
  const out = new Set<string>();
  try {
    const diffOut = execFileSync('git', ['diff', '--name-only', '--diff-filter=ACMRTUXB', ref], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    for (const line of diffOut.split(/\r?\n/)) {
      const trimmed = line.trim().replace(/\\/g, '/');
      if (trimmed) out.add(trimmed);
    }
    if (!diffBase) {
      const untrackedOut = execFileSync('git', ['ls-files', '--others', '--exclude-standard'], {
        cwd: root,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      for (const line of untrackedOut.split(/\r?\n/)) {
        const trimmed = line.trim().replace(/\\/g, '/');
        if (trimmed) out.add(trimmed);
      }
    }
  } catch (e) {
    throw new Error(`Git 差分の取得に失敗しました (${ref}): ${(e as Error).message}`);
  }
  return out;
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
      'changed-only': { type: 'boolean', default: false },
      'diff-base': { type: 'string' },
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
    return EXIT_CODE_CLEAN;
  }
  if (!SUPPORTED_FORMATS.includes(values.format as (typeof SUPPORTED_FORMATS)[number])) {
    throw new Error(`--format が不正です: ${values.format}`);
  }

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
    if (!SUPPORTED_CONFIDENCES.includes(values['min-confidence'] as Confidence)) {
      throw new Error('--min-confidence が不正です');
    }
    config.minConfidence = values['min-confidence'] as Confidence;
  }
  if (values['fail-on']) {
    if (!SUPPORTED_FAIL_ON.includes(values['fail-on'] as Severity | 'none')) {
      throw new Error('--fail-on が不正です');
    }
    config.failOn = values['fail-on'] as Severity | 'none';
  }

  await initParsers({ wasmDir: wasmDir() });
  let files = collectFiles(root, positionals, config.exclude);
  if (values['changed-only'] || values['diff-base']) {
    const changed = getGitChangedFiles(root, values['diff-base']);
    files = files.filter((rel) => changed.has(rel.replace(/\\/g, '/')));
  }
  const all: Item[] = [];
  for (const rel of files) {
    const abs = path.join(root, rel);
    let text: string;
    try {
      text = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    if (text.length > MAX_FILE_SIZE_BYTES) continue; // 巨大な生成ファイルは対象外
    const findings = await scanSource(text, abs, { relativePath: rel, config });
    for (const finding of findings) {
      if (meetsConfidence(finding, config.minConfidence)) all.push({ finding, relativePath: rel });
    }
  }

  const baselinePath = path.resolve(root, values.baseline ?? config.baseline);
  if (values['update-baseline']) {
    writeBaseline(baselinePath, createBaseline(all));
    process.stderr.write(`ベースラインを更新しました: ${path.relative(process.cwd(), baselinePath)}（${all.length} 件）\n`);
    return EXIT_CODE_CLEAN;
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

  if (config.failOn === 'none') return EXIT_CODE_CLEAN;
  const threshold = SEVERITY_ORDER[config.failOn];
  return items.some((i) => i.finding.kind !== 'suppression' && SEVERITY_ORDER[i.finding.severity] >= threshold)
    ? EXIT_CODE_FINDINGS
    : EXIT_CODE_CLEAN;
}

async function main(): Promise<number> {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === '-h' || command === '--help') {
    process.stdout.write(HELP);
    return command ? EXIT_CODE_CLEAN : EXIT_CODE_ERROR;
  }
  if (command === '--version' || command === '-v') {
    process.stdout.write(VERSION + '\n');
    return EXIT_CODE_CLEAN;
  }
  if (command !== 'scan') {
    process.stderr.write(`不明なコマンドです: ${command}\n\n${HELP}`);
    return EXIT_CODE_ERROR;
  }
  return scan(rest);
}

main().then(
  (code) => process.exit(code),
  (e: unknown) => {
    process.stderr.write(`llmscan: ${(e as Error).message}\n`);
    process.exit(EXIT_CODE_ERROR);
  },
);
