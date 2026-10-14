import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { commonBuildOptions, copyWasm } from '../../scripts/build-common.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(here, 'dist');
fs.rmSync(dist, { recursive: true, force: true });

const options = { ...commonBuildOptions, tsconfig: path.join(here, '../../tsconfig.json'), minify: true, keepNames: true };
await build({ ...options, entryPoints: [path.join(here, 'src/extension.ts')], outfile: path.join(dist, 'extension.js'), external: ['vscode'] });
await build({ ...options, entryPoints: [path.join(here, 'src/server.ts')], outfile: path.join(dist, 'server.js') });

// tree-sitter 本体と各言語の文法を同梱する
copyWasm(path.join(dist, 'wasm'));
