import { mkdir, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
const dir = new URL('../../../.acceptance/padding-cache-20261028/', import.meta.url);
await mkdir(dir, { recursive: true });
const key = randomBytes(32).toString('hex'), expires = Date.now() + 3500000;
const origin = name => `https://${name}.aloneowo0.workers.dev`;
const fixtureName = 'superdoh-padding-fixture-20261028', checkName = 'superdoh-padding-check-20261028';
const base = { account_id: 'de840a0c07482d94be19fdc1aad928da', compatibility_date: '2026-10-19', compatibility_flags: ['enable_request_signal', 'global_fetch_strictly_public', 'no_nodejs_compat', 'no_nodejs_compat_v2'], workers_dev: true, preview_urls: false, observability: { enabled: false }, rules: [{ type: 'CompiledWasm', globs: ['**/*.wasm'], fallthrough: false }], vars: { EXPIRES: expires } };
for (const [role, name] of [['fixture', fixtureName], ['check', checkName]]) {
  await writeFile(new URL(`${role}.json`, dir), JSON.stringify({ ...base, name, main: `./dist/${role}.js` }, null, 2), { flag: 'wx' });
  await writeFile(new URL(`${role}-secrets.json`, dir), JSON.stringify({ KEY: key, ...(role === 'check' ? { FIXTURE: `${origin(fixtureName)}/${key}` } : {}) }), { flag: 'wx' });
}
await writeFile(new URL('access.json', dir), JSON.stringify({ key, expires, endpoint: origin(checkName), fixtureName, checkName }), { flag: 'wx' });
await writeFile(new URL('ledger.json', dir), JSON.stringify({ budget: 40, used: 0, requests: [] }, null, 2), { flag: 'wx' });
console.log('Created private expiring configuration, secrets and independent 40-request ledger.');
