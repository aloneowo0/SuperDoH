import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { compileList, exportSnapshot } from '../../../lib/ip-list/index.js';
import data from '../../../src/generated/ip-lists.js';
const root = new URL('../../../', import.meta.url), dist = new URL('.acceptance/embedded-ip-lists-20261029/dist/', root);
const values = { ...data };
for (const [name, text] of [['check_cf', '192.0.2.0/24\n'], ['check_meta', '198.51.100.0/24\n']]) {
  const bytes = new TextEncoder().encode(text);
  values[name] = { snapshot: exportSnapshot(compileList(bytes, 'text', 4096, 262144), bytes.length), sha256: '0'.repeat(64), fetchedAt: new Date().toISOString() };
}
await mkdir(dist, { recursive: true });
for (const [entry, name] of [[new URL('main.js', import.meta.url), 'check.js'], [new URL('../padding-cache/fixture.js', import.meta.url), 'fixture.js']]) await build({
  entryPoints: [fileURLToPath(entry)], outfile: fileURLToPath(new URL(name, dist)), bundle: true, format: 'esm', platform: 'browser', target: 'es2022', external: ['cloudflare:sockets'],
  plugins: [
    { name: 'check-only-snapshots', setup(b) {
      b.onResolve({ filter: /generated\/ip-lists\.js$/ }, () => ({ path: 'embedded', namespace: 'check-only' }));
      b.onLoad({ filter: /.*/, namespace: 'check-only' }, () => ({ contents: 'export default ' + JSON.stringify(values), loader: 'js' }));
    } },
    { name: 'external-wasm', setup(b) { b.onResolve({ filter: /dns_bindgen_bg\.wasm$/ }, () => ({ path: './dns_bindgen_bg.wasm', external: true })); } },
  ],
});
await copyFile(new URL('lib/dns-wasm/dns_bindgen_bg.wasm', root), new URL('dns_bindgen_bg.wasm', dist));
console.log('Built embedded-list cloud check and controlled fixture.');
