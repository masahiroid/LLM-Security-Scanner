import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { commonBuildOptions, copyWasm } from '../../scripts/build-common.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(here, 'dist');
fs.rmSync(dist, { recursive: true, force: true });

await build({
  ...commonBuildOptions,
  entryPoints: [path.join(here, 'src/cli.ts')],
  outfile: path.join(dist, 'cli.js'),
  banner: { js: '#!/usr/bin/env node' },
  tsconfig: path.join(here, '../../tsconfig.json'),
});

// tree-sitter 本体と各言語の文法を同梱する
copyWasm(path.join(dist, 'wasm'));
fs.chmodSync(path.join(dist, 'cli.js'), 0o755);
