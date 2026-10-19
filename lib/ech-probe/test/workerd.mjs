import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { runtimeInfo } from './runtime.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(process.env.ECH_PROBE_TEST_TOOLS
  ? path.resolve(process.env.ECH_PROBE_TEST_TOOLS, 'package.json')
  : import.meta.url);
const { Miniflare } = require('miniflare');
const meta = JSON.parse(await fs.readFile(path.join(root, 'test/fixtures/meta.json'), 'utf8'));
const certificates = JSON.parse(await fs.readFile(path.join(root, 'test/fixtures/certificates.json'), 'utf8'));
const fixture = { meta, certificates };
const options = compatibilityDate => ({
  modules: true,
  scriptPath: path.join(root, 'test/worker.js'),
  modulesRoot: root,
  compatibilityDate,
  modulesRules: [{ type: 'ESModule', include: ['**/*.js'], fallthrough: true }],
});
let mf;
const runtime = runtimeInfo(require);
const compat = runtime.compatibilityDate;
try {
  mf = new Miniflare(options(compat));
  const response = await mf.dispatchFetch('https://ech-probe.test/', { method: 'POST', body: JSON.stringify(fixture), headers: { 'content-type': 'application/json' } });
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  assert.equal(body.failed, 0);
  assert.equal(body.preCancelledProbe, 'ABORTED');
  console.log(`ECH probe workerd offline tests: ${body.passed} passed (workerd ${runtime.workerd}, compatibility date ${compat}, no nodejs_compat)`);
} finally {
  await mf?.dispose();
}
