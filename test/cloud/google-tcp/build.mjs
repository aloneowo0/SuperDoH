import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
const root = new URL('../../../', import.meta.url), dist = new URL('.acceptance/google-tcp-20261029/dist/', root);
await mkdir(dist, { recursive: true });
await build({ entryPoints: [fileURLToPath(new URL('main.js', import.meta.url))], outfile: fileURLToPath(new URL('check.js', dist)), bundle: true, format: 'esm', platform: 'browser', target: 'es2022', external: ['cloudflare:sockets'], plugins: [{ name: 'external-wasm', setup(b) { b.onResolve({ filter: /dns_bindgen_bg\.wasm$/ }, () => ({ path: './dns_bindgen_bg.wasm', external: true })); } }] });
await copyFile(new URL('lib/dns-wasm/dns_bindgen_bg.wasm', root), new URL('dns_bindgen_bg.wasm', dist));
console.log('Built isolated Google TCP check Worker.');
