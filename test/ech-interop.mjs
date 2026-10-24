import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import net from 'node:net';
import tls from 'node:tls';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { test } from 'node:test';
import { Miniflare, Log, LogLevel } from 'miniflare';
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { query, decode } from './helpers/dns-wire.mjs';

const openssl = process.env.ECH_PROBE_OPENSSL;
if (!openssl) {
  throw new Error('Set ECH_PROBE_OPENSSL to an OpenSSL build that supports `ech` and `s_server -ech_key`; this opt-in test fails rather than skipping.');
}

const root = fileURLToPath(new URL('../', import.meta.url));
const hostname = 'example.test';
const rootPemPath = path.join(root, 'lib/ech-probe/test/fixtures/certificates.json');
const fixture = JSON.parse(await fs.readFile(rootPemPath, 'utf8'));
const pem = (type, base64) => `-----BEGIN ${type}-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END ${type}-----\n`;
const queryDns = async response => {
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal(response.headers.get('Content-Type'), 'application/dns-message');
  return decode(new Uint8Array(await response.arrayBuffer()));
};

/** Decode the HTTPS RDATA ServiceParam vector without dns-wasm. */
function echSvcParam(message) {
  const record = message.records.find(row => row.section === 0 && row.type === 65 && row.name === hostname);
  assert.ok(record, 'public DoH response must contain an HTTPS answer');
  const data = record.data;
  assert.ok(data.length >= 3, 'HTTPS RDATA must contain priority and TargetName');
  let offset = 2;
  while (true) {
    assert.ok(offset < data.length, 'TargetName is truncated');
    const size = data[offset++];
    assert.equal(size & 0xc0, 0, 'TargetName must not use compression');
    if (size === 0) break;
    assert.ok(size <= 63 && offset + size <= data.length, 'TargetName label is malformed');
    offset += size;
  }
  const params = new Map();
  while (offset < data.length) {
    assert.ok(offset + 4 <= data.length, 'ServiceParam header is truncated');
    const key = data[offset] * 256 + data[offset + 1];
    const size = data[offset + 2] * 256 + data[offset + 3];
    offset += 4;
    assert.ok(offset + size <= data.length, 'ServiceParam value is truncated');
    assert.ok(!params.has(key), `duplicate ServiceParam key ${key}`);
    params.set(key, Uint8Array.from(data.slice(offset, offset + size)));
    offset += size;
  }
  const ech = params.get(5);
  assert.ok(ech?.length, 'HTTPS answer must contain the ECH (key 5) ServiceParam');
  return ech;
}

/** Independently parse enough of the ECHConfigList to verify its public_name. */
function publicNames(bytes) {
  const read16 = (data, offset) => {
    assert.ok(offset + 2 <= data.length, 'ECH vector length is truncated');
    return data[offset] * 256 + data[offset + 1];
  };
  const listLength = read16(bytes, 0);
  assert.equal(listLength, bytes.length - 2, 'ECHConfigList length prefix must cover the complete value');
  const names = [];
  let offset = 2;
  while (offset < bytes.length) {
    const version = read16(bytes, offset); offset += 2;
    const size = read16(bytes, offset); offset += 2;
    assert.ok(offset + size <= bytes.length, 'ECHConfig contents are truncated');
    const config = bytes.subarray(offset, offset + size); offset += size;
    if (version !== 0xfe0d) continue;
    let cursor = 0;
    assert.ok(config.length >= 1 + 2 + 2, 'ECHConfig is too short');
    cursor += 1 + 2;
    const keySize = read16(config, cursor); cursor += 2 + keySize;
    const suitesSize = read16(config, cursor); cursor += 2 + suitesSize;
    assert.ok(cursor + 2 <= config.length, 'ECHConfig maximum name length or public_name is truncated');
    cursor += 1;
    const nameSize = config[cursor++];
    assert.ok(cursor + nameSize + 2 <= config.length, 'ECHConfig public_name or extensions are truncated');
    const nameBytes = config.subarray(cursor, cursor + nameSize); cursor += nameSize;
    const extensionsSize = read16(config, cursor); cursor += 2 + extensionsSize;
    assert.equal(cursor, config.length, 'ECHConfig has trailing bytes');
    names.push(Buffer.from(nameBytes).toString('ascii'));
  }
  assert.ok(names.length > 0, 'server retry config must contain a supported ECHConfig');
  return names;
}

const serviceAnswer = {
  type: 'answer',
  records: [{ name: hostname, type: 'HTTPS', ttl: 60, rdata: { Https: { priority: 1, target: '.', params: [] } } }],
};
const group = actions => ({ order: 0, rules: [{ actions }] });
const request = () => query(hostname, 65);

class TestLog extends Log {
  constructor(logs) { super(LogLevel.ERROR); this.logs = logs; }
  log(message) { this.logs.push(String(message)); }
}

async function waitForFinished(getCount, count, server, logs) {
  const deadline = Date.now() + 3000;
  while (getCount() < count && Date.now() < deadline) {
    if (server.exitCode !== null) throw new Error(`ECH OpenSSL server exited early: ${logs.join('')}`);
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.equal(getCount(), count, `OpenSSL must receive client Finished; observed ${getCount()}, expected ${count}`);
}

test('public DoH obtains authenticated ECH retry configs from a local TLS server', async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'superdoh-ech-public-'));
  const logs = [];
  const serverLogs = [];
  let server;
  let mf;
  try {
    await fs.writeFile(path.join(temp, 'leaf.pem'), fixture.leafPem);
    await fs.writeFile(path.join(temp, 'intermediate.pem'), fixture.intermediatePem);
    await fs.writeFile(path.join(temp, 'root.pem'), fixture.rootPem);
    await fs.writeFile(path.join(temp, 'key.pem'), pem('PRIVATE KEY', fixture.leafPrivateKeyPkcs8Base64));

    const generated = spawnSync(openssl, ['ech', '-public_name', hostname, '-suite', '0x20,1,1',
      '-ech_version', '65037', '-out', path.join(temp, 'ech.pem')], { env: { ...process.env, OPENSSL_CONF: '' }, encoding: 'utf8', timeout: 10000 });
    assert.equal(generated.status, 0,
      `ECH_PROBE_OPENSSL must support the ` + '`ech`' + ` command; it exited ${generated.status}: ${generated.stderr || generated.error?.message || ''}`);

    const reservation = net.createServer();
    await new Promise((resolve, reject) => {
      reservation.once('error', reject);
      reservation.listen(0, '127.0.0.1', resolve);
    });
    const port = reservation.address().port;
    await new Promise((resolve, reject) => reservation.close(error => error ? reject(error) : resolve()));

    server = spawn(openssl, ['s_server', '-accept', `127.0.0.1:${port}`, '-tls1_3', '-ciphersuites', 'TLS_AES_128_GCM_SHA256',
      '-cert', path.join(temp, 'leaf.pem'), '-key', path.join(temp, 'key.pem'), '-cert_chain', path.join(temp, 'intermediate.pem'),
      '-ech_key', path.join(temp, 'ech.pem'), '-verify', '1', '-CAfile', path.join(temp, 'root.pem'), '-www', '-no_ticket', '-msg'],
    { env: { ...process.env, OPENSSL_CONF: '' }, stdio: ['ignore', 'pipe', 'pipe'] });
    for (const stream of [server.stdout, server.stderr]) stream.setEncoding('utf8').on('data', text => {
      if (serverLogs.join('').length < 1048576) serverLogs.push(text);
    });
    server.on('error', error => serverLogs.push(String(error)));

    // Wait for OpenSSL to report a bound listener rather than probing the port
    // just released by the reservation before the actual service is listening.
    const readyDeadline = Date.now() + 10000;
    while (!serverLogs.join('').split(/\r?\n/).includes('ACCEPT')) {
      if (server.exitCode !== null || server.signalCode !== null) throw new Error(`OpenSSL ECH server exited early: ${serverLogs.join('')}`);
      assert.ok(Date.now() < readyDeadline, `OpenSSL ECH server did not start: ${serverLogs.join('')}`);
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    // Independent TLS baseline verifies that the generated server cert/service are usable.
    await new Promise((resolve, reject) => {
      const client = tls.connect({ host: '127.0.0.1', port, servername: hostname, ca: fixture.rootPem,
        ciphers: 'TLS_AES_128_GCM_SHA256', minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
      client.setTimeout(3000, () => client.destroy(new Error('OpenSSL baseline TLS timed out')));
      client.once('secureConnect', () => { client.end(); resolve(); });
      client.once('error', reject);
    });

    const bundle = await build({
      entryPoints: [path.join(root, 'src/worker.js')], bundle: true, write: false,
      external: ['cloudflare:sockets'], format: 'esm', platform: 'browser',
      plugins: [{ name: 'wasm-external', setup(buildApi) {
        buildApi.onResolve({ filter: /\.wasm$/ }, args => ({
          path: '../' + path.relative(root, path.resolve(args.resolveDir, args.path)).split(path.sep).join('/'), external: true,
        }));
      } }],
    });
    const script = bundle.outputFiles[0].text;
    const runtimeOptions = {
      modules: true, modulesRoot: root, scriptPath: path.join(root, 'test/ech-public-bundle.js'), script,
      compatibilityDate: '2026-10-19', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public', 'no_nodejs_compat', 'no_nodejs_compat_v2'],
      bindings: { DNS_CACHE: { read: false, write: false } },
      outboundService: { network: { allow: ['private'] } },
      log: new TestLog(logs),
      handleRuntimeStdio(stdout, stderr) {
        for (const stream of [stdout, stderr]) stream.setEncoding('utf8').on('data', text => logs.push(text));
      },
      modulesRules: [
        { type: 'ESModule', include: ['**/*.js'], fallthrough: true },
        { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true },
      ],
    };
    mf = new Miniflare(runtimeOptions);

    const finishedCount = () => (serverLogs.join('').match(/<<< TLS 1\.3, Handshake[^\r\n]*Finished/g) ?? []).length;
    await waitForFinished(finishedCount, 1, server, serverLogs);
    const baselineFinished = finishedCount();
    const options = (overrides = {}) => ({
      hostname: '127.0.0.1', port, serverName: hostname, timeoutMs: 10000, maxBytes: 65536,
      verifyCertificate: true, caCertificates: [fixture.rootPem], ...overrides,
    });
    const actions = probeOptions => group([serviceAnswer, { type: 'probeEch', options: probeOptions }, { type: 'applyEch' }]);
    async function configure(probeOptions) {
      logs.length = 0;
      await mf.setOptions({
        ...runtimeOptions,
        bindings: {
          DNS_CACHE: { read: false, write: false },
          DNS_LIMITS: { maxExecutionTimeMs: 15000, maxEchProbeTimeoutMs: 10000 },
          DNS_RULE_MAIN: JSON.stringify(actions(probeOptions)),
        },
      });
    }
    async function requestPublic() {
      return queryDns(await mf.dispatchFetch('https://doh.test/dns-query', {
        method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: request(),
      }));
    }
    function assertEchAnswer(message) {
      assert.equal(message.flags & 15, 0, logs.join(''));
      const ech = echSvcParam(message);
      assert.ok(publicNames(ech).includes(hostname), 'ECHConfigList in the response must identify the configured public_name');
      return ech;
    }

    // Authenticated success also proves a cache hit does not perform another TLS handshake.
    await configure(options());
    const first = assertEchAnswer(await requestPublic());
    await waitForFinished(finishedCount, baselineFinished + 1, server, logs);
    const beforeHit = finishedCount();
    const second = assertEchAnswer(await requestPublic());
    assert.deepEqual(second, first);
    assert.ok(logs.join('').includes('"state":"hit"'), 'omitted cacheTtl must enable the Cache API hit path');
    assert.equal(finishedCount(), beforeHit, 'a valid cache hit must not start another TLS handshake');

    // A wrong DNS identity must fail closed, with no retry using disabled verification.
    await configure(options({ serverName: 'wrong.invalid' }));
    const wrongName = await requestPublic();
    assert.equal(wrongName.flags & 15, 2, logs.join(''));
    assert.equal(finishedCount(), beforeHit, 'wrong serverName must fail before client Finished');
    assert.ok(logs.join('').includes('ECH_PROBE_FAILED'), 'wrong serverName must emit the stable probe failure code');

    // The local fixture root is intentionally not in the library's bundled trust store.
    await configure(options({ caCertificates: undefined }));
    const untrusted = await requestPublic();
    assert.equal(untrusted.flags & 15, 2, logs.join(''));
    assert.equal(finishedCount(), beforeHit, 'default trust failure must not finish or downgrade the handshake');
    assert.ok(logs.join('').includes('ECH_PROBE_FAILED'), 'default trust failure must emit the stable probe failure code');

    // Explicitly disabling identity verification follows the public library contract;
    // the resulting successful handshake still has to send client Finished.
    await configure(options({ verifyCertificate: false, caCertificates: undefined }));
    const unauthenticated = assertEchAnswer(await requestPublic());
    assert.ok(publicNames(unauthenticated).includes(hostname));
    await waitForFinished(finishedCount, beforeHit + 1, server, logs);

    // Explicit opt-out must execute two complete handshakes despite earlier cached results.
    await configure(options({ cacheTtl: 0 }));
    const beforeUncached = finishedCount();
    for (let i = 1; i <= 2; i++) {
      assertEchAnswer(await requestPublic());
      await waitForFinished(finishedCount, beforeUncached + i, server, logs);
    }
    assert.ok(!logs.join('').includes('"state":"hit"'), 'cacheTtl:0 must bypass the Cache API');

    // The connection target participates in cache identity, not just the SNI.
    const unused = net.createServer();
    await new Promise(resolve => unused.listen(0, '127.0.0.1', resolve));
    const closedPort = unused.address().port;
    await new Promise(resolve => unused.close(resolve));
    await configure(options({ port: closedPort }));
    assert.equal((await requestPublic()).flags & 15, 2, 'another target must not receive cached ECH');

    // A short explicit lifetime is honored and renewal actually performs TLS.
    await configure(options({ cacheTtl: 1 }));
    const beforeExpiry = finishedCount();
    assertEchAnswer(await requestPublic());
    await waitForFinished(finishedCount, beforeExpiry + 1, server, logs);
    assertEchAnswer(await requestPublic());
    assert.equal(finishedCount(), beforeExpiry + 1, 'fresh short-TTL entry should hit');
    await new Promise(resolve => setTimeout(resolve, 1200));
    assertEchAnswer(await requestPublic());
    await waitForFinished(finishedCount, beforeExpiry + 2, server, logs);

    // Expired data must never mask a failed renewal, and failures must not become hits.
    const ended = once(server, 'exit');
    server.kill();
    await ended;
    server = undefined;
    await new Promise(resolve => setTimeout(resolve, 1200));
    for (let i = 0; i < 2; i++) {
      logs.length = 0;
      assert.equal((await requestPublic()).flags & 15, 2, 'expired ECH must not be returned after renewal fails');
      assert.ok(logs.join('').includes('ECH_PROBE_FAILED'));
      assert.ok(!logs.join('').includes('"state":"hit"'), 'a failed probe must not be cached');
      assert.ok(/"state":"(?:miss|expired)"/.test(logs.join('')), 'failed renewal must revisit the acquisition path');
    }

  } catch (error) {
    const diagnostics = [...serverLogs, ...logs].join('').split(/\r?\n/)
      .filter(line => !/^    [0-9a-f ]+$/.test(line)).join('\n').slice(-12000);
    throw new Error(`Independent ECH interop failed: ${error.message}\n${diagnostics}`, { cause: error });
  } finally {
    await mf?.dispose();
    if (server && server.exitCode === null) {
      const ended = once(server, 'exit');
      server.kill();
      await ended;
    }
    await fs.rm(temp, { recursive: true, force: true });
  }
});
