import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  type Confidence,
  DEFAULT_CONFIG,
  DEFAULT_DEBOUNCE_MS,
  type Finding,
  type LanguageId,
  MAX_FILE_SIZE_BYTES,
  type ScanConfig,
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
  type Hover,
  MarkupKind,
  ProposedFeatures,
  TextDocumentSyncKind,
  TextDocuments,
  createConnection,
} from 'vscode-languageserver/node';
import { TextDocument } from 'vscode-languageserver-textdocument';
import { URI } from 'vscode-uri';
import { buildCodeActions } from './server/code-actions';
import {
  COMMAND_CLEAR_BASELINE,
  COMMAND_CLEAR_SCAN,
  COMMAND_CREATE_BASELINE,
  COMMAND_SCAN_WORKSPACE,
  LANGUAGE_ID_MAP,
} from './server/constants';
import { toDiagnostic } from './server/diagnostics';
import { createHoverMarkdown } from './server/hover';

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
let clientLocale = '';
const isJa = () => clientLocale.startsWith('ja') || (!clientLocale && (process.env.VSCODE_NLS_CONFIG?.includes('"locale":"ja"') ?? false));
/** URI ごとの表示中の指摘（ホバー・コードアクション用） */
const shown = new Map<string, Finding[]>();
const timers = new Map<string, NodeJS.Timeout>();

const LANGUAGE_IDS = LANGUAGE_ID_MAP;

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
  await connection.sendDiagnostics({ uri: target.uri, diagnostics: findings.map((f) => toDiagnostic(f, target.uri, isJa())) });
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
    }, DEFAULT_DEBOUNCE_MS),
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
      if (text.length > MAX_FILE_SIZE_BYTES) continue; // 巨大な生成ファイルは対象外
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
  const msg = isJa()
    ? `LLMScan: ${files} ファイルをスキャンし、${total} 件の指摘がありました`
    : `LLMScan: Scanned ${files} files, found ${total} findings`;
  connection.window.showInformationMessage(msg);
  return { files, findings: total };
}

async function updateBaseline(): Promise<{ written: string[] }> {
  if (roots.length === 0) {
    const msg = isJa()
      ? 'LLMScan: ベースラインを作成するにはフォルダーを開いてください'
      : 'LLMScan: Please open a folder to create a baseline';
    connection.window.showWarningMessage(msg);
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
    const msg = isJa()
      ? `LLMScan: ベースラインを更新しました（${mine.length} 件）: ${path.relative(root.dir, file)}`
      : `LLMScan: Updated baseline (${mine.length} findings): ${path.relative(root.dir, file)}`;
    connection.window.showInformationMessage(msg);
  }
  reloadRoots();
  revalidateOpen();
  return { written };
}

function clearScan(): { cleared: number } {
  let cleared = 0;
  const openUris = new Set(documents.all().map((d) => d.uri));
  for (const uri of Array.from(shown.keys())) {
    if (!openUris.has(uri)) {
      shown.delete(uri);
      void connection.sendDiagnostics({ uri, diagnostics: [] });
      cleared++;
    }
  }
  const msg = isJa()
    ? `LLMScan: スキャン結果をクリアしました（未編集の ${cleared} ファイルの指摘を非表示にしました）`
    : `LLMScan: Cleared scan results (${cleared} closed files reset)`;
  connection.window.showInformationMessage(msg);
  return { cleared };
}

function clearBaseline(): { cleared: string[] } {
  const cleared: string[] = [];
  for (const root of roots) {
    const file = path.resolve(root.dir, root.config.baseline);
    if (fs.existsSync(file)) {
      try {
        fs.unlinkSync(file);
        cleared.push(file);
      } catch (e) {
        connection.window.showErrorMessage(`LLMScan: Failed to remove baseline: ${(e as Error).message}`);
      }
    }
  }
  reloadRoots();
  revalidateOpen();
  const msg = isJa()
    ? `LLMScan: ベースラインを解除しました（${cleared.length} 個のファイルを削除）。すべての指摘を再表示します`
    : `LLMScan: Cleared baseline (${cleared.length} files removed). Showing all findings again`;
  connection.window.showInformationMessage(msg);
  return { cleared };
}

// ---------------------------------------------------------------- LSP

connection.onInitialize(async (params) => {
  clientLocale = params.locale ?? '';
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
      executeCommandProvider: {
        commands: [
          COMMAND_SCAN_WORKSPACE,
          COMMAND_CREATE_BASELINE,
          COMMAND_CLEAR_SCAN,
          COMMAND_CLEAR_BASELINE,
        ],
      },
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
  return { contents: { kind: MarkupKind.Markdown, value: hits.map((h) => createHoverMarkdown(h, isJa())).join('\n\n---\n\n') } };
});

connection.onCodeAction((params): CodeAction[] => {
  const doc = documents.get(params.textDocument.uri);
  if (!doc) return [];
  const lang = LANGUAGE_IDS[doc.languageId];
  if (!lang) return [];
  return buildCodeActions(doc, params.context.diagnostics, lang);
});

connection.onExecuteCommand(async (params) => {
  if (params.command === COMMAND_SCAN_WORKSPACE) return scanWorkspace();
  if (params.command === COMMAND_CREATE_BASELINE) return updateBaseline();
  if (params.command === COMMAND_CLEAR_SCAN) return clearScan();
  if (params.command === COMMAND_CLEAR_BASELINE) return clearBaseline();
  return undefined;
});

documents.listen(connection);
connection.listen();
