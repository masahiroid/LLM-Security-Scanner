import { createRequire } from 'node:module';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Language, Parser } from 'web-tree-sitter';
import type { LanguageId } from './types';

const GRAMMAR_FILES: Record<LanguageId, string> = {
  python: 'tree-sitter-python.wasm',
  javascript: 'tree-sitter-javascript.wasm',
  typescript: 'tree-sitter-typescript.wasm',
  tsx: 'tree-sitter-tsx.wasm',
  php: 'tree-sitter-php.wasm',
};

const GRAMMAR_PACKAGES: Record<LanguageId, string> = {
  python: 'tree-sitter-python',
  javascript: 'tree-sitter-javascript',
  typescript: 'tree-sitter-typescript',
  tsx: 'tree-sitter-typescript',
  php: 'tree-sitter-php',
};

export interface ParserOptions {
  /**
   * WASM ファイル（tree-sitter.wasm と各言語の文法）を置いたディレクトリ。
   * バンドル済みの CLI / VS Code 拡張から渡す。省略時は node_modules から解決する。
   */
  wasmDir?: string;
}

let initPromise: Promise<void> | undefined;
let wasmDirOption: string | undefined;
const languages = new Map<LanguageId, Promise<Language>>();
const parsers = new Map<LanguageId, Parser>();

function resolveFromPackage(pkg: string, file: string): string {
  const here = typeof __filename !== 'undefined' ? __filename : fileURLToPath(import.meta.url);
  const req = createRequire(here);
  // exports で package.json を公開していないパッケージもあるため、エントリから上位へ辿って探す
  let dir = path.dirname(req.resolve(pkg));
  while (!fs.existsSync(path.join(dir, file)) || !fs.existsSync(path.join(dir, 'package.json'))) {
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error(`${pkg} の ${file} が見つかりません`);
    dir = parent;
  }
  return path.join(dir, file);
}

export function initParsers(options: ParserOptions = {}): Promise<void> {
  if (!initPromise) {
    wasmDirOption = options.wasmDir;
    initPromise = Parser.init({
      locateFile: (name: string) =>
        wasmDirOption ? path.join(wasmDirOption, name) : resolveFromPackage('web-tree-sitter', name),
    });
  }
  return initPromise;
}

function loadLanguage(lang: LanguageId): Promise<Language> {
  let promise = languages.get(lang);
  if (!promise) {
    const file = GRAMMAR_FILES[lang];
    const wasmPath = wasmDirOption
      ? path.join(wasmDirOption, file)
      : resolveFromPackage(GRAMMAR_PACKAGES[lang], file);
    promise = Language.load(wasmPath);
    languages.set(lang, promise);
  }
  return promise;
}

export async function getParser(lang: LanguageId): Promise<Parser> {
  await initParsers();
  let parser = parsers.get(lang);
  if (!parser) {
    parser = new Parser();
    parser.setLanguage(await loadLanguage(lang));
    parsers.set(lang, parser);
  }
  return parser;
}

/** 拡張子から言語を判定する。対象外なら undefined */
export function languageForFile(file: string): LanguageId | undefined {
  const lower = file.toLowerCase();
  if (lower.endsWith('.d.ts') || /\.min\.js$/.test(lower)) return undefined;
  const ext = path.extname(lower);
  switch (ext) {
    case '.py':
      return 'python';
    case '.js':
    case '.mjs':
    case '.cjs':
    case '.jsx':
      return 'javascript';
    case '.ts':
    case '.mts':
    case '.cts':
      return 'typescript';
    case '.tsx':
      return 'tsx';
    case '.php':
      return 'php';
    default:
      return undefined;
  }
}
