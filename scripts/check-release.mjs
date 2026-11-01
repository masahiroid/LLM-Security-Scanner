import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const packages = ['core', 'cli', 'vscode'].map(name => JSON.parse(readFileSync(`packages/${name}/package.json`, 'utf8')));
const version = packages[0].version;
if (!packages.every(pkg => pkg.version === version && (!pkg.dependencies?.['@llmscan/core'] || pkg.dependencies['@llmscan/core'] === version))) throw new Error('Workspace versions differ');
const constants = readFileSync('packages/core/src/constants.ts', 'utf8');
if (!constants.includes(`LLMSCAN_VERSION = '${version}'`)) throw new Error('Core version differs');
if (process.env.GITHUB_REF?.startsWith('refs/tags/') && process.env.GITHUB_REF !== `refs/tags/v${version}`) throw new Error('Release tag differs from package version');
for (const file of ['README.md', 'README.ja.md', 'packages/vscode/README.md', 'packages/vscode/README.ja.md']) {
  if (!readFileSync(file, 'utf8').includes(`v${version}`)) throw new Error(`Outdated README: ${file}`);
}
const files = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
const forbidden = /(^|\/)(docs|\.agents|\.agent|scratch|tmp|SBOM-Reports)(\/|$)|(^|\/)(AGENTS|GEMINI|ROADMAP[^/]*|roadmap[^/]*)\.md$|\.scratch\./;
const leaks = files.filter(file => forbidden.test(file));
if (leaks.length) throw new Error(`Internal files tracked: ${leaks.join(', ')}`);
console.log(`Release v${version}: versions, READMEs and tracked-file policy verified.`);
