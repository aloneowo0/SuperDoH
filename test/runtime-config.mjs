import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Miniflare, Log, LogLevel } from 'miniflare';
import { runtimeInfo } from '../lib/ech-probe/test/runtime.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const config = JSON.parse(fs.readFileSync(path.join(root, 'wrangler.jsonc'), 'utf8').replace(/^\s*\/\/.*$/gm, ''));
const runtime = runtimeInfo(createRequire(import.meta.url));

test('deployment and application tests use the supported workerd compatibility date without Node APIs', () => {
  assert.equal(config.compatibility_date, runtime.compatibilityDate);
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  assert.equal(runtime.workerd, wranglerRequire('workerd/package.json').version);
  const libraryRequire = createRequire(path.join(root, 'lib/ech-probe/package.json'));
  assert.equal(runtime.workerd, runtimeInfo(libraryRequire).workerd);
  for (const flag of ['enable_request_signal', 'global_fetch_strictly_public', 'no_nodejs_compat', 'no_nodejs_compat_v2']) {
    assert.ok(config.compatibility_flags.includes(flag), `missing ${flag}`);
  }
  assert.equal(config.upload_source_maps, true);
  for (const name of fs.readdirSync(path.join(root, 'test')).filter(name => name.endsWith('.mjs'))) {
    const source = fs.readFileSync(path.join(root, 'test', name), 'utf8');
    const dates = [...source.matchAll(/compatibilityDate:\s*['"]([\d-]+)['"]/g)];
    for (const [, date] of dates) assert.equal(date, config.compatibility_date, name);
    if (dates.length) {
      assert.ok(source.includes('no_nodejs_compat'), name);
      assert.ok(source.includes('no_nodejs_compat_v2'), name);
    }
  }
});

test('configured runtime can execute a request without Node globals', async () => {
  const mf = new Miniflare({
    modules: true, compatibilityDate: config.compatibility_date, compatibilityFlags: config.compatibility_flags,
    script: 'export default { fetch() { return Response.json({ process: typeof process, buffer: typeof Buffer }); } };',
    log: new Log(LogLevel.NONE),
  });
  try {
    const response = await mf.dispatchFetch('https://runtime.test/');
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { process: 'undefined', buffer: 'undefined' });
  } finally { await mf.dispose(); }
});
