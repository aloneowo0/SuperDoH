import { open } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

const fail = code => { throw Object.assign(new Error(code), { code }); };
const slug = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const integer = (value, low, high) => Number.isInteger(value) && value >= low && value <= high;
function fields(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || required.some(key => !Object.hasOwn(value, key)) ||
    Object.keys(value).some(key => ![...required, ...optional].includes(key))) fail('INVALID_INPUT');
}
async function readManifest(file, local) {
  const handle = await open(file, 'r');
  let value;
  try {
    if ((await handle.stat()).size > 524288) fail('INVALID_INPUT');
    const bytes = Buffer.alloc(524289);
    let length = 0;
    while (length < bytes.length) {
      const read = await handle.read(bytes, length, bytes.length - length, null);
      if (!read.bytesRead) break;
      length += read.bytesRead;
    }
    if (length > 524288) fail('INVALID_INPUT');
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length)));
  } finally { await handle.close(); }
  fields(value, ['version', 'metadata', 'intervalMs', 'timeoutMs', 'scenarios']);
  fields(value.metadata, ['commit', 'worker', 'accountPlan', 'approvalRef']);
  const meta = value.metadata;
  if (value.version !== 1 || typeof meta.commit !== 'string' || !/^[0-9a-f]{7,40}$/.test(meta.commit) || !slug(meta.worker) || !slug(meta.approvalRef) ||
    meta.accountPlan !== (local ? 'local' : 'free') || !integer(value.intervalMs, local ? 0 : 1000, 60000) ||
    !integer(value.timeoutMs, 1, 30000) || !Array.isArray(value.scenarios) || !integer(value.scenarios.length, 1, 100)) fail('INVALID_INPUT');
  const names = new Set();
  let total = 0;
  for (const scenario of value.scenarios) {
    fields(scenario, ['name', 'phase', 'count', 'query', 'expected']);
    fields(scenario.query, ['name', 'type']);
    fields(scenario.expected, ['rcode'], ['answerCount', 'ad']);
    const name = scenario.query.name;
    if (!slug(scenario.name) || names.has(scenario.name) || !['cold-candidate', 'warm', 'unspecified'].includes(scenario.phase) ||
      !integer(scenario.count, 1, 500) || typeof name !== 'string' || name.length < 1 || name.length > 254 ||
      !(name === '.' || name.replace(/\.$/, '').split('.').every(label => /^[A-Za-z0-9_-]{1,63}$/.test(label))) ||
      !integer(scenario.query.type, 0, 65535) || !integer(scenario.expected.rcode, 0, 4095) ||
      (Object.hasOwn(scenario.expected, 'answerCount') && !integer(scenario.expected.answerCount, 0, 65535)) ||
      (Object.hasOwn(scenario.expected, 'ad') && typeof scenario.expected.ad !== 'boolean')) fail('INVALID_INPUT');
    names.add(scenario.name);
    total += scenario.count;
  }
  if (!integer(total, 5, 500)) fail('INVALID_INPUT');
  return { manifest: value, total };
}

async function main() {
  const [file, ...flags] = process.argv.slice(2);
  if (!file || new Set(flags).size !== flags.length || flags.some(flag => !['--local', '--authorized-online', '--plan'].includes(flag)) ||
    flags.includes('--local') === flags.includes('--authorized-online')) fail('INVALID_INPUT');
  const local = flags.includes('--local');
  const { manifest, total } = await readManifest(file, local);
  if (flags.includes('--plan')) {
    console.log(JSON.stringify({ version: 1, mode: local ? 'local' : 'authorized-online', totalRequests: total, networkPerformed: false,
      scenarios: manifest.scenarios.map(row => ({ name: row.name, phase: row.phase, count: row.count })) }));
    return;
  }
  const result = await collect(manifest, local);
  console.log(JSON.stringify(result));
  if (result.samples.some(row => !row.correct) || result.stopped.length) process.exitCode = 2;
}
try { await main(); }
catch (error) { console.error(JSON.stringify({ error: { code: ['INVALID_INPUT', 'INVALID_ENDPOINT'].includes(error.code) ? error.code : 'INVALID_INPUT' } })); process.exitCode = 1; }

async function loadDns() {
  const { build } = await import('esbuild');
  const { readFile } = await import('node:fs/promises');
  const bundle = await build({ entryPoints: [fileURLToPath(new URL('../lib/dns-wasm/index.js', import.meta.url))],
    bundle: true, write: false, format: 'esm', platform: 'node', logLevel: 'silent', plugins: [{ name: 'local-dns-wasm', setup(api) {
      api.onLoad({ filter: /[.]wasm$/ }, async args => ({ contents:
        `export default new WebAssembly.Module(Uint8Array.from(${JSON.stringify([...await readFile(args.path)])}));`, loader: 'js' }));
    } }] });
  return import('data:text/javascript;base64,' + Buffer.from(bundle.outputFiles[0].text).toString('base64'));
}
function endpoint(local) {
  let url;
  try { url = new URL(process.env.DNS_ACCEPTANCE_URL); } catch { fail('INVALID_ENDPOINT'); }
  if (url.username || url.password || url.search || url.hash ||
    (local ? !(url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)) : url.protocol !== 'https:')) fail('INVALID_ENDPOINT');
  return url;
}
async function responseBytes(response) {
  const reader = response.body?.getReader();
  if (!reader) fail('DNS_INVALID');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > 65535) fail('BODY_LIMIT');
      chunks.push(value);
    }
    return Buffer.concat(chunks, total);
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
}
async function collect(manifest, local) {
  const url = endpoint(local);
  const dns = await loadDns();
  const prepared = manifest.scenarios.map(row => ({ ...row, wire: dns.buildQuery(row.query.name.toLowerCase(), row.query.type, 0),
    name: row.name }));
  const result = { version: 1, mode: local ? 'local' : 'authorized-online', runId: randomUUID(), metadata: manifest.metadata, samples: [], stopped: [] };
  let nextStart = 0;
  let stopAll = false;
  const deadline = performance.now() + 900000;
  for (const scenario of prepared) {
    if (stopAll) { result.stopped.push(scenario.name); continue; }
    for (let i = 0; i < scenario.count; i++) {
      const target = Math.min(nextStart, deadline);
      while (performance.now() < target) await delay(Math.max(1, Math.ceil(target - performance.now())));
      if (performance.now() >= deadline) { result.stopped.push(scenario.name); stopAll = true; break; }
      const id = randomUUID();
      const wire = Buffer.from(scenario.wire);
      wire.writeUInt16BE(result.samples.length + 1);
      const original = dns.parseMessage(wire);
      const started = performance.now();

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), Math.min(manifest.timeoutMs, deadline - started));
      const sample = { id, scenario: scenario.name, phase: scenario.phase, startedAt: new Date().toISOString(),
        latencyMs: 0, correct: false, errorCode: null, httpStatus: null, dnsRcode: null };
      try {
        const response = await fetch(url, { method: 'POST', body: wire, signal: controller.signal, redirect: 'manual',
          headers: { 'Content-Type': 'application/dns-message', Accept: 'application/dns-message', 'X-Acceptance-Sample-Id': id } });
        sample.httpStatus = response.status;
        if (response.status !== 200) { await response.body?.cancel(); fail('HTTP_FAILED'); }
        if (response.headers.get('Content-Type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/dns-message') {
          await response.body?.cancel(); fail('DNS_INVALID');
        }
        const bytes = await responseBytes(response);
        let message;
        try { message = dns.parseMessage(bytes); } catch { fail('DNS_INVALID'); }
        if (!message.is_response || message.truncated || message.opcode !== 0 || message.id !== original.id ||
          JSON.stringify(message.questions) !== JSON.stringify(original.questions)) fail('DNS_INVALID');
        sample.dnsRcode = dns.getRcode(message);
        const expected = scenario.expected;
        if (sample.dnsRcode !== expected.rcode || (Object.hasOwn(expected, 'answerCount') && message.answers.length !== expected.answerCount) ||
          (Object.hasOwn(expected, 'ad') && !!(message.flags & dns.FLAGS.AD) !== expected.ad)) fail('DNS_UNEXPECTED');
        sample.correct = true;
      } catch (error) {
        sample.errorCode = controller.signal.aborted ? 'TIMEOUT' :
          ['HTTP_FAILED', 'DNS_INVALID', 'DNS_UNEXPECTED', 'BODY_LIMIT'].includes(error.code) ? error.code : 'NETWORK_FAILED';
      } finally { clearTimeout(timer); controller.abort(); sample.latencyMs = performance.now() - started; nextStart = performance.now() + manifest.intervalMs; }
      result.samples.push(sample);
      if (!sample.correct) {
        result.stopped.push(scenario.name);
        if (result.samples.length <= 5) stopAll = true;
        break;
      }
    }
  }
  return result;
}
