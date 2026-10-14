// CLI / VS Code 拡張のビルドで共用する処理（WASM のコピー・esbuild 設定）
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const coreDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '../packages/core');
const require = createRequire(path.join(coreDir, 'package.json'));

const FILES = [
  ['web-tree-sitter', 'tree-sitter.wasm'],
  ['tree-sitter-python', 'tree-sitter-python.wasm'],
  ['tree-sitter-javascript', 'tree-sitter-javascript.wasm'],
  ['tree-sitter-typescript', 'tree-sitter-typescript.wasm'],
  ['tree-sitter-typescript', 'tree-sitter-tsx.wasm'],
  ['tree-sitter-php', 'tree-sitter-php.wasm'],
];

function packageDir(pkg, file) {
  let dir = path.dirname(require.resolve(pkg));
  while (!fs.existsSync(path.join(dir, file)) || !fs.existsSync(path.join(dir, 'package.json'))) {
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error(`${pkg} の ${file} が見つかりません`);
    dir = parent;
  }
  return dir;
}

export function copyWasm(destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  for (const [pkg, file] of FILES) fs.copyFileSync(path.join(packageDir(pkg, file), file), path.join(destDir, file));
}

/** esbuild 共通設定：web-tree-sitter は CJS 版を取り込む（ESM 版は import.meta.url に依存するため） */
export const commonBuildOptions = {
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'cjs',
  logLevel: 'warning',
  define: { 'import.meta.url': 'undefined' },
  plugins: [
    {
      name: 'web-tree-sitter-cjs',
      setup(build) {
        build.onResolve({ filter: /^web-tree-sitter$/ }, () => ({
          path: path.join(packageDir('web-tree-sitter', 'tree-sitter.cjs'), 'tree-sitter.cjs'),
        }));
      },
    },
  ],
};
