import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(process.env.DNS_WASM_TEST_TOOLS ? path.resolve(process.env.DNS_WASM_TEST_TOOLS, 'package.json') : import.meta.url);
const { Miniflare } = require('miniflare');
const mf = new Miniflare({
  modules: true,
  scriptPath: path.join(root, 'test/worker.js'),
  modulesRoot: root,
  compatibilityDate: '2025-05-27',
  modulesRules: [
    { type: 'ESModule', include: ['**/*.js'], fallthrough: true },
    { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true },
  ],
});
let passed = 0;
try {
  for (const type of [1, 28, 64, 65, 65280]) {
    const response = await mf.dispatchFetch(`https://dns.test/?name=x.com&type=${type}`);
    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.id, 0x4242);
    assert.deepEqual(data.questions, [{ name: 'x.com', rtype: type, class: 1 }]);
    assert.equal(data.is_response, false);
    passed++;
  }
  for (const type of ['-1', '65536', '1.5', 'NaN']) {
    assert.equal((await mf.dispatchFetch(`https://dns.test/?type=${type}`)).status, 400);
    passed++;
  }
  for (const body of [new Uint8Array(), new Uint8Array(11), new Uint8Array(65536), new Uint8Array([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1])]) {
    assert.equal((await mf.dispatchFetch('https://dns.test/', { method: 'POST', body })).status, 400);
    passed++;
  }
  // A compressed-owner A response for x.com -> 1.2.3.4.
  const query = await (await mf.dispatchFetch('https://dns.test/?type=1')).json();
  const responseWire = new Uint8Array([...query.wire, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
  responseWire[2] = 0x81; responseWire[3] = 0x80; responseWire[7] = 1;
  const parsed = await (await mf.dispatchFetch('https://dns.test/', { method: 'POST', body: responseWire })).json();
  assert.deepEqual(parsed.answers, [{ name: 'x.com', rtype: 1, class: 1, ttl: 60, data: '1.2.3.4', rdata: { A: { addr: '1.2.3.4' } } }]);
  passed++;
  // Optional externally captured wire responses are never needed for the basic smoke test.
  {
    const fixtures = JSON.parse(fs.readFileSync(process.env.DNS_WASM_DNS_FIXTURES || path.join(root, 'test/fixtures/real-dns.json'), 'utf8'));
    for (const [key, encoded] of Object.entries(fixtures)) {
      const response = await mf.dispatchFetch('https://dns.test/', { method: 'POST', body: Buffer.from(encoded, 'base64') });
      assert.equal(response.status, 200, key);
      const data = await response.json();
      assert.equal(data.is_response, true, key);
      assert.equal(data.questions[0].rtype, Number(key.split(':').at(-1)), key);
      passed++;
    }
  }
  console.log(`Workers/workerd WASM smoke tests: ${passed} passed`);
} finally {
  await mf.dispose();
}
