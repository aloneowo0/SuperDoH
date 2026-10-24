import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import net from 'node:net';
import tls from 'node:tls';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { runtimeInfo } from './runtime.mjs';

// Opt-in: ECH_PROBE_OPENSSL must name an OpenSSL build with `ech` and s_server -ech_key.
const openssl = process.env.ECH_PROBE_OPENSSL;
assert.ok(openssl, 'Set ECH_PROBE_OPENSSL to an ECH-capable OpenSSL executable');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixture = JSON.parse(await fs.readFile(path.join(root, 'test/fixtures/certificates.json'), 'utf8'));
const require = createRequire(process.env.ECH_PROBE_TEST_TOOLS
  ? path.resolve(process.env.ECH_PROBE_TEST_TOOLS, 'package.json') : import.meta.url);
const { Miniflare } = require('miniflare');
const runtime = runtimeInfo(require);
const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ech-probe-interop-'));
const environment = { ...process.env, OPENSSL_CONF: '' };
const pem = (type, base64) => `-----BEGIN ${type}-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END ${type}-----\n`;
let server, mf;
let logs = '';
let passed = 0;
try {
  await fs.writeFile(path.join(temp, 'leaf.pem'), fixture.leafPem);
  await fs.writeFile(path.join(temp, 'intermediate.pem'), fixture.intermediatePem);
  await fs.writeFile(path.join(temp, 'root.pem'), fixture.rootPem);
  await fs.writeFile(path.join(temp, 'key.pem'), pem('PRIVATE KEY', fixture.leafPrivateKeyPkcs8Base64));
  const result = spawnSync(openssl, ['ech', '-public_name', 'example.test', '-suite', '0x20,1,1',
    '-ech_version', '65037', '-out', path.join(temp, 'ech.pem')], { env: environment, encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  const reservation = net.createServer();
  await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  server = spawn(openssl, ['s_server', '-accept', `127.0.0.1:${port}`, '-tls1_3', '-ciphersuites', 'TLS_AES_128_GCM_SHA256',
    '-cert', path.join(temp, 'leaf.pem'), '-key', path.join(temp, 'key.pem'), '-cert_chain', path.join(temp, 'intermediate.pem'),
    '-ech_key', path.join(temp, 'ech.pem'), '-verify', '1', '-CAfile', path.join(temp, 'root.pem'), '-www', '-no_ticket', '-msg'], { env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
  server.on('error', error => { logs += String(error); });
  for (const stream of [server.stdout, server.stderr]) stream.on('data', data => { if (logs.length < 1048576) logs += data; });
  const deadline = Date.now() + 10000;
  // Use the server's bound-listener signal, not a connection to a just-released port.
  while (!logs.split(/\r?\n/).includes('ACCEPT')) {
    if (server.exitCode !== null || server.signalCode !== null) throw new Error(`OpenSSL exited early: ${logs}`);
    assert.ok(Date.now() < deadline, `OpenSSL did not start: ${logs}`);
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  await new Promise((resolve, reject) => {
    const client = tls.connect({ host: '127.0.0.1', port, servername: 'example.test', ca: fixture.rootPem,
      ciphers: 'TLS_AES_128_GCM_SHA256', minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
    client.setTimeout(3000, () => client.destroy(new Error('OpenSSL baseline TLS timed out')));
    client.once('secureConnect', () => { client.end(); resolve(); });
    client.once('error', reject);
  });
  console.log('Independent Node TLS baseline connected to OpenSSL');
  mf = new Miniflare({ modules: true, modulesRoot: root, scriptPath: path.join(root, 'test/interop-worker.js'),
    compatibilityDate: runtime.compatibilityDate, compatibilityFlags: runtime.compatibilityFlags, modulesRules: [{ type: 'ESModule', include: ['**/*.js'], fallthrough: true }] });
  const cases = [
    [{ verifyCertificate: true }, null, true],
    [{ verifyCertificate: false }, null, false],
    [{ verifyCertificate: true, serverName: 'wrong.example' }, 'HOSTNAME'],
    [{ verifyCertificate: true, defaultRoots: true }, 'CERTIFICATE'],
  ];
  for (const [options, expectedError, authenticated] of cases) {
    const response = await mf.dispatchFetch('http://interop.test/', { method: 'POST',
      body: JSON.stringify({ port, rootPem: fixture.rootPem, ...options }), headers: { 'Content-Type': 'application/json' } });
    const data = await response.json();
    if (expectedError) {
      assert.equal(response.status, 502, JSON.stringify(data));
      assert.equal(data.code, expectedError, JSON.stringify(data));
    } else {
      assert.equal(response.status, 200, JSON.stringify(data));
      assert.equal(data.authenticated, authenticated);
      assert.equal(data.handshakeComplete, true);
      assert.ok(data.configCount > 0);
      assert.ok(data.publicNames.includes('example.test'));
    }
    passed++;
    console.log(JSON.stringify({ case: options, ...data }));
  }
  // The independent OpenSSL server must actually receive client Finished.
  const receivedFinished = logs.match(/<<< TLS 1\.3, Handshake[^\n]*Finished/g) ?? [];
  assert.ok(receivedFinished.length >= 3, `OpenSSL must receive Finished from the baseline and both successful Workers (${receivedFinished.length})`);
  console.log(`ECH probe OpenSSL/workerd interoperability: ${passed} passed; ${receivedFinished.length} client Finished records received (no nodejs_compat)`);
} catch (error) {
  await fs.writeFile(path.join(temp, 'server.log'), logs);
  console.error(`Interop logs retained at ${path.join(temp, 'server.log')}`);
  throw error;
} finally {
  await mf?.dispose();
  if (server && server.exitCode === null) {
    const ended = new Promise(resolve => server.once('exit', resolve));
    server.kill();
    await ended;
  }
}
