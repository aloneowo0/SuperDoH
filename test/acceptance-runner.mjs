import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const manifest = overrides => ({ version: 1, metadata: { commit: '8fb13e8', worker: 'local', accountPlan: 'local', approvalRef: 'local' }, intervalMs: 0, timeoutMs: 2000,
  scenarios: [{ name: 'fixed', phase: 'warm', count: 5, query: { name: 'example.com', type: 1 }, expected: { rcode: 0, answerCount: 1 } }], ...overrides });
async function invoke(config, extra = [], env = {}) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'superdoh-measure-'));
  try {
    const input = path.join(dir, 'manifest.json');
    await writeFile(input, JSON.stringify(config));
    return await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [path.join(root, 'scripts/acceptance-runner.mjs'), input, ...extra], {
        env: { ...process.env, DNS_ACCEPTANCE_URL: '', ...env }, stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = '', stderr = '';
      child.stdout.on('data', data => { stdout += data; });
      child.stderr.on('data', data => { stderr += data; });
      child.on('error', reject);
      child.on('close', code => resolve({ code, stdout, stderr }));
    });
  } finally { await rm(dir, { recursive: true, force: true }); }
}
test('measurement plan validates a bounded local manifest without an endpoint or network', async () => {
  const result = await invoke(manifest(), ['--plan', '--local']);
  assert.equal(result.code, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.totalRequests, 5);
  assert.equal(output.networkPerformed, false);
  assert.ok(!result.stdout.includes('example.com'));
});

test('measurement runner observes the production DoH HTTP entry and never exports its secret endpoint', async () => {
  const { Miniflare, Log, LogLevel } = await import('miniflare');
  const { build } = await import('esbuild');
  const { createServer } = await import('node:http');
  const bundled = await build({ entryPoints: [path.join(root, 'src/worker.js')], bundle: true, write: false,
    external: ['cloudflare:sockets'], format: 'esm', platform: 'browser', plugins: [{ name: 'wasm', setup(api) {
      api.onResolve({ filter: /[.]wasm$/ }, args => ({ path: '../' + path.relative(root, path.resolve(args.resolveDir, args.path)).split(path.sep).join('/'), external: true }));
    } }] });
  const mf = new Miniflare({ modules: true, modulesRoot: root, scriptPath: path.join(root, 'test/measure-worker.js'), script: bundled.outputFiles[0].text,
    compatibilityDate: '2026-10-19', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public', 'no_nodejs_compat', 'no_nodejs_compat_v2'], log: new Log(LogLevel.NONE),
    bindings: { DNS_PATH_KEY: 'private-test-key', DNS_RULE_MAIN: { order: 0, rules: [{ actions: [{ type: 'answer', records: [
      { name: 'example.com', type: 'A', ttl: 60, rdata: { A: { addr: '192.0.2.8' } } },
    ] }] }] } }, modulesRules: [{ type: 'ESModule', include: ['**/*.js'], fallthrough: true }, { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true }] });
  let calls = 0;
  const ids = new Set();
  const server = createServer(async (request, response) => {
    calls++;
    ids.add(request.headers['x-acceptance-sample-id']);
    try {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const result = await mf.dispatchFetch('https://doh.test' + request.url, { method: request.method, headers: request.headers, body: Buffer.concat(chunks) });
      response.writeHead(result.status, Object.fromEntries(result.headers));
      response.end(Buffer.from(await result.arrayBuffer()));
    } catch { response.writeHead(500); response.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const result = await invoke(manifest(), ['--local'], { DNS_ACCEPTANCE_URL: `http://127.0.0.1:${server.address().port}/private-test-key/dns-query` });
    assert.equal(result.code, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.mode, 'local');
    assert.equal(output.samples.length, 5);
    assert.ok(output.samples.every(row => row.correct && row.dnsRcode === 0 && row.latencyMs >= 0));
    assert.equal(calls, 5);
    assert.equal(ids.size, 5);
    assert.ok(!result.stdout.includes('private-test-key'));
    assert.ok(!result.stdout.includes('example.com'));
    assert.ok(!result.stdout.includes('cpuMs'));
    const dir = await mkdtemp(path.join(os.tmpdir(), 'superdoh-measure-report-'));
    try {
      const samples = path.join(dir, 'samples.json');
      await writeFile(samples, result.stdout);
      const report = await new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [path.join(root, 'scripts/acceptance-report.mjs'), samples]);
        let stdout = '', stderr = '';
        child.stdout.on('data', data => { stdout += data; });
        child.stderr.on('data', data => { stderr += data; });
        child.on('error', reject);
        child.on('close', code => resolve({ code, stdout, stderr }));
      });
      assert.equal(report.code, 0, report.stderr);
      const summary = JSON.parse(report.stdout);
      assert.equal(summary.cases[0].sampleCount, 5);
      assert.equal(summary.cases[0].conclusion, 'blocked');
      assert.equal(summary.cases[0].cpuMs.median, null);
      assert.equal(summary.completeAcceptance, false);
    } finally { await rm(dir, { recursive: true, force: true }); }

  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await mf.dispose();
  }
});

async function withServer(handler, run) {
  const { createServer } = await import('node:http');
  const server = createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await run(`http://127.0.0.1:${server.address().port}/private-key/dns-query`); }
  finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}
test('measurement preflight rejects excess traffic, unknown secret fields and unacknowledged targets without requests', async () => {
  let calls = 0;
  await withServer((_req, res) => { calls++; res.end(); }, async endpoint => {
    const invalid = [
      manifest({ scenarios: [{ ...manifest().scenarios[0], count: 501 }] }),
      manifest({ endpoint: 'https://private.test/secret-value' }),
      manifest({ metadata: { ...manifest().metadata, token: 'secret-value' } }),
      manifest({ scenarios: [{ ...manifest().scenarios[0], expected: { rcode: 0, private: 'secret-value' } }] }),
    ];
    for (const config of invalid) {
      const result = await invoke(config, ['--local'], { DNS_ACCEPTANCE_URL: endpoint });
      assert.equal(result.code, 1);
      assert.deepEqual(JSON.parse(result.stderr), { error: { code: 'INVALID_INPUT' } });
      assert.ok(!result.stderr.includes('secret-value'));
    }
    const missingMode = await invoke(manifest(), [], { DNS_ACCEPTANCE_URL: endpoint });
    assert.equal(missingMode.code, 1);
    for (const target of ['https://example.com/private-key', 'http://localhost/private-key', endpoint + '?token=secret-value', endpoint.replace('http://', 'http://user:password@')]) {
      const result = await invoke(manifest(), ['--local'], { DNS_ACCEPTANCE_URL: target });
      assert.equal(result.code, 1);
      assert.deepEqual(JSON.parse(result.stderr), { error: { code: 'INVALID_ENDPOINT' } });
    }
    const remote = await invoke(manifest({ metadata: { ...manifest().metadata, accountPlan: 'free' }, intervalMs: 0 }), ['--authorized-online', '--plan']);
    assert.equal(remote.code, 1, 'online plans cannot disable the one-second interval');
    assert.equal(calls, 0);
  });
});
test('measurement failures retain safe evidence, do not retry or follow redirects, and stop the smoke run', async () => {
  const { responseWire } = await import('./helpers/dns-wire.mjs');
  const cases = [
    ['HTTP_FAILED', (_wire, res) => { res.writeHead(302, { Location: '/redirect-secret' }); res.end('private body'); }],
    ['DNS_INVALID', (_wire, res) => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('private body'); }],
    ['DNS_INVALID', (wire, res) => { const wrong = Buffer.from(responseWire(wire)); wrong.writeUInt16BE(0); res.writeHead(200, { 'Content-Type': 'application/dns-message' }); res.end(wrong); }],
    ['DNS_UNEXPECTED', (wire, res) => { res.writeHead(200, { 'Content-Type': 'application/dns-message' }); res.end(responseWire(wire, { rcode: 2 })); }],
    ['BODY_LIMIT', (_wire, res) => { res.writeHead(200, { 'Content-Type': 'application/dns-message' }); res.end(Buffer.alloc(65536)); }],
    ['TIMEOUT', (_wire, res) => { res.writeHead(200, { 'Content-Type': 'application/dns-message' }); res.flushHeaders(); }],
  ];
  for (const [code, reply] of cases) {
    let calls = 0;
    await withServer(async (req, res) => {
      calls++;
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      reply(Buffer.concat(chunks), res);
    }, async endpoint => {
      const result = await invoke(manifest({ timeoutMs: 100 }), ['--local'], { DNS_ACCEPTANCE_URL: endpoint });
      assert.equal(result.code, 2, result.stderr);
      const output = JSON.parse(result.stdout);
      assert.equal(output.samples.length, 1);
      assert.equal(output.samples[0].errorCode, code);
      assert.equal(output.samples[0].correct, false);
      assert.deepEqual(output.stopped, ['fixed']);
      assert.equal(calls, 1);
      for (const secret of ['private-key', 'private body', 'redirect-secret']) assert.ok(!result.stdout.includes(secret));
    });
  }
});
test('measurement schedules sequential starts and treats expected legal SERVFAIL as DNS data', async () => {
  const { responseWire } = await import('./helpers/dns-wire.mjs');
  const starts = [];
  let active = 0, peak = 0;
  await withServer(async (req, res) => {
    active++; peak = Math.max(peak, active); starts.push(performance.now());
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    await new Promise(resolve => setTimeout(resolve, 10));
    res.writeHead(200, { 'Content-Type': 'application/dns-message' });
    res.end(responseWire(Buffer.concat(chunks), { rcode: 2, records: [] })); active--;
  }, async endpoint => {
    const result = await invoke(manifest({ intervalMs: 50, scenarios: [{ ...manifest().scenarios[0], expected: { rcode: 2, answerCount: 0 } }] }), ['--local'], { DNS_ACCEPTANCE_URL: endpoint });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(peak, 1);
    assert.ok(starts.slice(1).every((time, i) => time - starts[i] >= 40));
    assert.ok(JSON.parse(result.stdout).samples.every(row => row.correct && row.dnsRcode === 2));
  });
});

test('after smoke success a failed scenario stops only itself and preserves later explicit scenarios', async () => {
  const { responseWire, decode } = await import('./helpers/dns-wire.mjs');
  let calls = 0;
  await withServer(async (req, res) => {
    calls++;
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const wire = Buffer.concat(chunks);
    res.writeHead(200, { 'Content-Type': 'application/dns-message' });
    res.end(responseWire(wire, { rcode: decode(wire).questions[0].name === 'bad.example' ? 2 : 0 }));
  }, async endpoint => {
    const base = manifest().scenarios[0];
    const config = manifest({ scenarios: [base, { ...base, name: 'bad', count: 3, query: { name: 'bad.example', type: 1 } }, { ...base, name: 'after', count: 2 }] });
    const result = await invoke(config, ['--local'], { DNS_ACCEPTANCE_URL: endpoint });
    assert.equal(result.code, 2, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.deepEqual(output.stopped, ['bad']);
    assert.equal(output.samples.filter(row => row.scenario === 'bad').length, 1);
    assert.equal(output.samples.filter(row => row.scenario === 'after' && row.correct).length, 2);
    assert.equal(calls, 8);
  });
});

test('measurement checks an explicitly expected answer TTL instead of accepting an unmodified answer', async () => {
  const { responseWire } = await import('./helpers/dns-wire.mjs');
  await withServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    res.writeHead(200, { 'Content-Type': 'application/dns-message' });
    res.end(responseWire(Buffer.concat(chunks)));
  }, async endpoint => {
    const scenario = { ...manifest().scenarios[0], expected: { rcode: 0, answerCount: 1, ttl: 30 } };
    const result = await invoke(manifest({ scenarios: [scenario] }), ['--local'], { DNS_ACCEPTANCE_URL: endpoint });
    assert.equal(result.code, 2, result.stderr);
    assert.equal(JSON.parse(result.stdout).samples[0].errorCode, 'DNS_UNEXPECTED');
  });
});
