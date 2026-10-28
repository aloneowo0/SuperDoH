import { build } from 'esbuild';
import { copyFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const release = path.resolve(here, '../../..');
const dist = path.join(release, '.acceptance', 'ecs-20261028', 'dist');
await mkdir(dist, { recursive: true });
const wasm = path.join(release, 'lib/dns-wasm/dns_bindgen_bg.wasm');
const plugin = { name: 'external-dns-wasm', setup(builder) {
  builder.onResolve({ filter: /dns_bindgen_bg[.]wasm$/ }, () => ({ path: './dns_bindgen_bg.wasm', external: true }));
} };
for (const [entry, outfile] of [['main.js', 'check.js'], ['fixture.js', 'fixture.js']]) {
  await build({ entryPoints: [path.join(here, entry)], outfile: path.join(dist, outfile), bundle: true, format: 'esm', platform: 'browser', target: 'es2022', external: ['cloudflare:sockets'], plugins: [plugin] });
}
await copyFile(wasm, path.join(dist, 'dns_bindgen_bg.wasm'));
console.log(`Built bundled ESM Workers and external WASM at ${dist}`);
