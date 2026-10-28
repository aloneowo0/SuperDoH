import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..'), dist = path.join(root, '.acceptance/padding-cache-20261028/dist');
await mkdir(dist, { recursive: true });
for (const [entry, name] of [['main.js', 'check.js'], ['fixture.js', 'fixture.js']]) await build({
  entryPoints: [path.join(here, entry)], outfile: path.join(dist, name), bundle: true, format: 'esm', platform: 'browser', target: 'es2022', external: ['cloudflare:sockets'],
  plugins: [{ name: 'external-wasm', setup(b) { b.onResolve({ filter: /dns_bindgen_bg\.wasm$/ }, () => ({ path: './dns_bindgen_bg.wasm', external: true })); } }],
});
await copyFile(path.join(root, 'lib/dns-wasm/dns_bindgen_bg.wasm'), path.join(dist, 'dns_bindgen_bg.wasm'));
console.log('Built isolated Padding cache Workers.');
