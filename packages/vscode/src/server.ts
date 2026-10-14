import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  type Confidence,
  type Finding,
  KIND_META,
  type LanguageId,
  OWASP_A05,
  OWASP_LLM05,
  type ScanConfig,
  DEFAULT_CONFIG,
  collectFiles,
  createBaseline,
  createExcludeMatcher,
  initParsers,
  loadConfig,
  meetsConfidence,
  readBaseline,
  scanSource,
  writeBaseline,
} from '@llmscan/core';
import {
  type CodeAction,
  CodeActionKind,
  type Diagnostic,
  DiagnosticSeverity,
  type Hover,
  MarkupKind,
  ProposedFeatures,
  TextDocumentSyncKind,
  TextDocuments,
  createConnection,
} from 'vscode-languageserver/node';
import { TextDocument } from 'vscode-languageserver-textdocument';
import { URI } from 'vscode-uri';

const SCAN_WORKSPACE = 'llmscan.scanWorkspace';
const CREATE_BASELINE = 'llmscan.createBaseline';
const DEBOUNCE_MS = 300;

interface Settings {
  enable: boolean;
  minConfidence: '' | Confidence;
  showBaselined: boolean;
}

interface Root {
  dir: string;
  config: ScanConfig;
  configError?: string;
  baseline?: Set<string>;
  excluded: (rel: string) => boolean;
}

const connection = createConnection(ProposedFeatures.all);
const documents = new TextDocuments(TextDocument);

let roots: Root[] = [];
let rootDirs: string[] = [];
let settings: Settings = { enable: true, minConfidence: '', showBaselined: false };
let supportsConfiguration = false;
let supportsWorkspaceFolders = false;
/** URI ごとの表示中の指摘（ホバー・コードアクション用） */
const shown = new Map<string, Finding[]>();
const timers = new Map<string, NodeJS.Timeout>();

const LANGUAGE_IDS: Record<string, LanguageId> = {
  python: 'python',
  javascript: 'javascript',
  javascriptreact: 'javascript',
  typescript: 'typescript',
  typescriptreact: 'tsx',
  php: 'php',
};

// ---------------------------------------------------------------- 設定・ルート

function loadRoot(dir: string): Root {
  let config: ScanConfig;
  let configError: string | undefined;
  try {
    config = loadConfig(dir).config;
  } catch (e) {
    configError = (e as Error).message;
    config = { ...DEFAULT_CONFIG, sanitizers: {} };
  }
  let baseline: Set<string> | undefined;
  try {
    baseline = readBaseline(path.resolve(dir, config.baseline));
  } catch (e) {
    configError = (e as Error).message;
  }
  return { dir, config, configError, baseline, excluded: createExcludeMatcher(config.exclude) };
}

function reloadRoots(): void {
  roots = rootDirs.map(loadRoot);
  for (const r of roots) {
    if (r.configError) connection.window.showWarningMessage(`LLM Security Scanner: ${r.configError}`);
  }
}

function rootFor(file: string): Root | undefined {
  let best: Root | undefined;
  for (const r of roots) {
    if ((file === r.dir || file.startsWith(r.dir + path.sep)) && (!best || r.dir.length > best.dir.length)) best = r;
  }
  return best;
}

async function refreshSettings(): Promise<void> {
  if (!supportsConfiguration) return;
  const s = (await connection.workspace.getConfiguration('llmscan')) as Partial<Settings> | null;
  settings = {
    enable: s?.enable ?? true,
    minConfidence: s?.minConfidence ?? '',
    showBaselined: s?.showBaselined ?? false,
  };
}

// ---------------------------------------------------------------- 診断

const SEVERITY: Record<Finding['severity'], DiagnosticSeverity> = {
  critical: DiagnosticSeverity.Error,
  high: DiagnosticSeverity.Error,
  medium: DiagnosticSeverity.Warning,
  low: DiagnosticSeverity.Information,
};
const CONFIDENCE_LABEL: Record<Confidence, string> = { high: '高', medium: '中', low: '低' };

function toDiagnostic(f: Finding, uri: string): Diagnostic {
  const owasp = f.ruleId.startsWith('LLM05') ? OWASP_LLM05 : OWASP_A05;
  return {
    range: { start: { line: f.range.start.line, character: f.range.start.column }, end: { line: f.range.end.line, character: f.range.end.column } },
    severity: SEVERITY[f.severity],
    source: 'llmscan',
    code: f.ruleId,
    codeDescription: f.kind === 'suppression' ? undefined : { href: owasp.url },
    message: f.kind === 'suppression' ? f.message : `${f.message}（確信度: ${CONFIDENCE_LABEL[f.confidence]}）`,
    relatedInformation: f.trace.map((s) => ({
      location: { uri, range: { start: { line: s.range.start.line, character: s.range.start.column }, end: { line: s.range.end.line, character: s.range.end.column } } },
      message: s.message,
    })),
    data: { ruleId: f.ruleId, fingerprint: f.fingerprint, anchorLine: f.trace[f.trace.length - 1]?.range.start.line ?? f.range.start.line },
  };
}

interface ScanTarget {
  uri: string;
  file: string;
  text: string;
  languageId?: string;
}

async function findingsFor(target: ScanTarget): Promise<Finding[]> {
  if (!settings.enable) return [];
  const root = rootFor(target.file);
  const rel = root ? path.relative(root.dir, target.file) : path.basename(target.file);
  if (root?.excluded(rel)) return [];
  const config = root?.config;
  const language = target.languageId ? LANGUAGE_IDS[target.languageId] : undefined;
  const findings = await scanSource(target.text, target.file, { relativePath: rel, config, language });
  const min: Confidence = settings.minConfidence || config?.minConfidence || 'medium';
  return findings.filter(
    (f) => meetsConfidence(f, min) && (settings.showBaselined || !root?.baseline?.has(f.fingerprint)),
  );
}

async function publish(target: ScanTarget): Promise<number> {
  const findings = await findingsFor(target);
  shown.set(target.uri, findings);
  await connection.sendDiagnostics({ uri: target.uri, diagnostics: findings.map((f) => toDiagnostic(f, target.uri)) });
  return findings.length;
}

function fileOf(uri: string): string {
  const u = URI.parse(uri);
  return u.scheme === 'file' ? u.fsPath : u.path;
}

async function validate(doc: TextDocument): Promise<void> {
  try {
    await publish({ uri: doc.uri, file: fileOf(doc.uri), text: doc.getText(), languageId: doc.languageId });
  } catch (e) {
    connection.console.error(`LLM Security Scanner: ${doc.uri} の解析に失敗しました: ${(e as Error).stack ?? e}`);
  }
}

function schedule(doc: TextDocument): void {
  clearTimeout(timers.get(doc.uri));
  timers.set(
    doc.uri,
    setTimeout(() => {
      timers.delete(doc.uri);
      void validate(doc);
    }, DEBOUNCE_MS),
  );
}

function revalidateOpen(): void {
  for (const doc of documents.all()) void validate(doc);
}

// ---------------------------------------------------------------- コマンド

interface WorkspaceFile {
  root: Root;
  rel: string;
  target: ScanTarget;
}

/** ワークスペースの対象ファイル（開いているものはエディタ上の内容）を列挙する */
function* workspaceFiles(): Generator<WorkspaceFile> {
  for (const root of roots) {
    for (const rel of collectFiles(root.dir, [], root.config.exclude)) {
      const file = path.join(root.dir, rel);
      const uri = URI.file(file).toString();
      const open = documents.get(uri);
      const text = open?.getText() ?? fs.readFileSync(file, 'utf8');
      if (text.length > 2_000_000) continue; // 巨大な生成ファイルは対象外
      yield { root, rel, target: { uri, file, text, languageId: open?.languageId } };
    }
  }
}

async function scanWorkspace(): Promise<{ files: number; findings: number }> {
  let total = 0;
  let files = 0;
  for (const { target } of workspaceFiles()) {
    files++;
    total += await publish(target);
  }
  connection.window.showInformationMessage(`LLM Security Scanner: ${files} ファイルをスキャンし、${total} 件の指摘がありました`);
  return { files, findings: total };
}

async function updateBaseline(): Promise<{ written: string[] }> {
  if (roots.length === 0) {
    connection.window.showWarningMessage('LLM Security Scanner: ベースラインを作成するにはフォルダーを開いてください');
    return { written: [] };
  }
  const byRoot = new Map<Root, { finding: Finding; relativePath: string }[]>(roots.map((r) => [r, []]));
  for (const { root, rel, target } of workspaceFiles()) {
    const findings = await scanSource(target.text, target.file, {
      relativePath: rel,
      config: root.config,
      language: target.languageId ? LANGUAGE_IDS[target.languageId] : undefined,
    });
    const min = settings.minConfidence || root.config.minConfidence;
    for (const finding of findings) if (meetsConfidence(finding, min)) byRoot.get(root)!.push({ finding, relativePath: rel });
  }
  const written: string[] = [];
  for (const root of roots) {
    const mine = byRoot.get(root)!;
    const file = path.resolve(root.dir, root.config.baseline);
    writeBaseline(file, createBaseline(mine));
    written.push(file);
    connection.window.showInformationMessage(`LLM Security Scanner: ベースラインを更新しました（${mine.length} 件）: ${path.relative(root.dir, file)}`);
  }
  reloadRoots();
  revalidateOpen();
  return { written };
}

// ---------------------------------------------------------------- ホバー・コードアクション

function family(lang: LanguageId): 'python' | 'javascript' | 'php' {
  return lang === 'python' ? 'python' : lang === 'php' ? 'php' : 'javascript';
}

function hoverMarkdown(f: Finding): string {
  if (f.kind === 'suppression') return `**LLM Security Scanner** \`${f.ruleId}\`\n\n${f.message}`;
  const meta = KIND_META[f.kind];
  const llm = f.ruleId.startsWith('LLM05');
  const owasp = llm ? OWASP_LLM05 : OWASP_A05;
  const lines = [
    `**LLM Security Scanner** \`${f.ruleId}\` — ${llm ? 'LLM05 不適切な出力処理 / ' : ''}${meta.title}`,
    '',
    `重大度: **${f.severity}** ／ 確信度: **${CONFIDENCE_LABEL[f.confidence]}**`,
    '',
    f.message,
    '',
    `**なぜ危険か** ${meta.why}`,
  ];
  if (llm) {
    lines.push('', 'LLM の応答はプロンプトインジェクションで外部から操作できるため、ユーザー入力と同じく信頼できない値として扱ってください。');
  }
  lines.push('', `**安全な書き方** ${meta.fix[family(f.language)]}`, '', '**経路**');
  for (const s of f.trace) lines.push(`1. ${s.range.start.line + 1} 行目: ${s.message.replace(/[*_`[\]]/g, '\\$&')}`);
  lines.push('', `[${owasp.id} ${owasp.title}](${owasp.url}) ／ ${meta.cwe}`);
  return lines.join('\n');
}

function suppressionEdit(doc: TextDocument, line: number, ruleId: string, lang: LanguageId) {
  const text = doc.getText({ start: { line, character: 0 }, end: { line, character: Number.MAX_SAFE_INTEGER } });
  const indent = /^\s*/.exec(text)?.[0] ?? '';
  const body = `llmscan-ignore[${ruleId}]: TODO 理由を記入`;
  let comment: string;
  if (lang === 'python') comment = `# ${body}`;
  else if (lang === 'php' && text.trimStart().startsWith('<')) comment = `<?php // ${body} ?>`;
  else comment = `// ${body}`;
  return { range: { start: { line, character: 0 }, end: { line, character: 0 } }, newText: `${indent}${comment}\n` };
}

// ---------------------------------------------------------------- LSP

connection.onInitialize(async (params) => {
  supportsConfiguration = params.capabilities.workspace?.configuration === true;
  supportsWorkspaceFolders = params.capabilities.workspace?.workspaceFolders === true;
  const folders = params.workspaceFolders?.map((f) => URI.parse(f.uri).fsPath) ?? [];
  if (folders.length === 0 && params.rootUri) folders.push(URI.parse(params.rootUri).fsPath);
  rootDirs = folders;
  await initParsers({ wasmDir: path.join(__dirname, 'wasm') });
  reloadRoots();
  return {
    capabilities: {
      textDocumentSync: TextDocumentSyncKind.Incremental,
      hoverProvider: true,
      codeActionProvider: { codeActionKinds: [CodeActionKind.QuickFix] },
      executeCommandProvider: { commands: [SCAN_WORKSPACE, CREATE_BASELINE] },
      workspace: { workspaceFolders: { supported: true, changeNotifications: true } },
    },
  };
});

connection.onInitialized(async () => {
  await refreshSettings();
  revalidateOpen();
  if (!supportsWorkspaceFolders) return;
  connection.workspace.onDidChangeWorkspaceFolders((e) => {
    const removed = new Set(e.removed.map((f) => URI.parse(f.uri).fsPath));
    rootDirs = [...rootDirs.filter((d) => !removed.has(d)), ...e.added.map((f) => URI.parse(f.uri).fsPath)];
    reloadRoots();
    revalidateOpen();
  });
});

connection.onDidChangeConfiguration(async () => {
  await refreshSettings();
  revalidateOpen();
});

// .llmscan.yml・ベースラインの変更
connection.onDidChangeWatchedFiles(() => {
  reloadRoots();
  revalidateOpen();
});

documents.onDidOpen((e) => void validate(e.document));
documents.onDidChangeContent((e) => schedule(e.document));
documents.onDidClose((e) => {
  clearTimeout(timers.get(e.document.uri));
  shown.delete(e.document.uri);
  void connection.sendDiagnostics({ uri: e.document.uri, diagnostics: [] });
});

connection.onHover((params): Hover | null => {
  const { line, character } = params.position;
  const hits = (shown.get(params.textDocument.uri) ?? []).filter((f) => {
    const { start, end } = f.range;
    const afterStart = line > start.line || (line === start.line && character >= start.column);
    const beforeEnd = line < end.line || (line === end.line && character <= end.column);
    return afterStart && beforeEnd;
  });
  if (hits.length === 0) return null;
  return { contents: { kind: MarkupKind.Markdown, value: hits.map(hoverMarkdown).join('\n\n---\n\n') } };
});

connection.onCodeAction((params): CodeAction[] => {
  const doc = documents.get(params.textDocument.uri);
  if (!doc) return [];
  const lang = LANGUAGE_IDS[doc.languageId];
  if (!lang) return [];
  const actions: CodeAction[] = [];
  for (const d of params.context.diagnostics) {
    if (d.source !== 'llmscan' || !d.data || d.code === 'LLMSCAN-SUPPRESS-001') continue;
    const { ruleId, anchorLine } = d.data as { ruleId: string; anchorLine: number };
    actions.push({
      title: `LLM Security Scanner: ${ruleId} をこの箇所で抑制する（理由の記入が必要）`,
      kind: CodeActionKind.QuickFix,
      diagnostics: [d],
      edit: { changes: { [doc.uri]: [suppressionEdit(doc, anchorLine, ruleId, lang)] } },
    });
  }
  return actions;
});

connection.onExecuteCommand(async (params) => {
  if (params.command === SCAN_WORKSPACE) return scanWorkspace();
  if (params.command === CREATE_BASELINE) return updateBaseline();
  return undefined;
});

documents.listen(connection);
connection.listen();
