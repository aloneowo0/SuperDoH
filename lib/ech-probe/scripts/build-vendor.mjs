#!/usr/bin/env node
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const out = resolve(root, 'vendor');
await mkdir(out, { recursive: true });
await mkdir(resolve(out, 'licenses'), { recursive: true });
const legalFiles = [
  ['pkijs', 'node_modules/pkijs/LICENSE'], ['asn1js', 'node_modules/asn1js/LICENSE'],
  ['pvutils', 'node_modules/pvutils/LICENSE'], ['pvtsutils', 'node_modules/pvtsutils/LICENSE'],
  ['bytestreamjs', 'node_modules/bytestreamjs/LICENSE'], ['tslib', 'node_modules/tslib/LICENSE.txt'],
  ['noble-hashes', 'node_modules/@noble/hashes/LICENSE'], ['esbuild', 'node_modules/esbuild/LICENSE.md'],
];
for (const [name, path] of legalFiles) await writeFile(resolve(out, 'licenses', `${name}.txt`), await readFile(resolve(root, path)));
await build({
  entryPoints: [resolve(root, 'scripts/pki-entry.js')],
  outfile: resolve(out, 'pki-core.js'),
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  minify: true,
  legalComments: 'none',
  treeShaking: true,
});
const manifest = {
  generatedAt: new Date().toISOString().slice(0, 10),
  source: 'https://registry.npmjs.org/',
  packages: {
    pkijs: { version: '3.4.1', license: 'BSD-3-Clause' },
    asn1js: { version: '3.0.6', license: 'BSD-3-Clause' },
    pvutils: { version: '1.2.0', license: 'MIT' },
    pvtsutils: { version: '1.3.6', license: 'MIT' },
    bytestreamjs: { version: '2.0.1', license: 'BSD-3-Clause' },
    tslib: { version: '2.8.1', license: '0BSD' },
    '@noble/hashes': { version: '1.8.0', license: 'MIT' },
    esbuild: { version: '0.25.12', license: 'MIT' },
  },
  output: 'pki-core.js',
  sha256: createHash('sha256').update(await readFile(resolve(out, 'pki-core.js'))).digest('hex'),
};
await writeFile(resolve(out, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Built vendor/pki-core.js sha256=${manifest.sha256}`);
