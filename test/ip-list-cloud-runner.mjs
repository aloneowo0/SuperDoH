import fs from 'node:fs/promises';
import { setGlobalProxyFromEnv } from 'node:http';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { query, decode } from './helpers/dns-wire.mjs';

const allowed = new Set(['superdoh-iplist-test-20261028.aloneowo0.workers.dev']);
const base = process.env.IP_LIST_TEST_URL ?? 'https://superdoh-iplist-test-20261028.aloneowo0.workers.dev';
const parsed = new URL(base);
if (parsed.protocol !== 'https:' || !allowed.has(parsed.hostname) || parsed.username || parsed.password || parsed.pathname !== '/') throw new Error('Refusing non-allowlisted test Worker URL');
if (typeof setGlobalProxyFromEnv === 'function') setGlobalProxyFromEnv();
const defaultLedgerPath = fileURLToPath(new URL('../.acceptance/ip-list-20261028/request-ledger.json', import.meta.url));
const ledgerPath = process.env.IP_LIST_TEST_LEDGER ?? defaultLedgerPath;
if (!path.isAbsolute(ledgerPath)) throw new Error('IP_LIST_TEST_LEDGER must be an absolute path');
const ledger = [];
await fs.mkdir(path.dirname(ledgerPath), { recursive: true });
await fs.writeFile(ledgerPath, '[]\n', { flag: 'wx' });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
let previous = 0;
async function request(path, init) {
  if (ledger.length >= 60) throw new Error('Hard request ceiling reached');
  if (!/^\/(suite|persistent|prepare\/(?:text|text2|json|fail|redirect|html|utf8|bad|large|slow|timeout|budget|cancel|entries|state|nullttl)|equivalence\/(?:cf|meta)|dns\/(?:cf|meta|meta-ip|non|negative|meta-domain|nov6|v4|v6|missing|unused|selector))$/.test(path)) throw new Error('Unapproved test path');
  if (previous) await delay(Math.max(0, 1050 - (Date.now() - previous)));
  const row = { number: ledger.length + 1, path, attemptedAt: new Date().toISOString(), status: 'attempted' };
  ledger.push(row); previous = Date.now();
  await fs.writeFile(ledgerPath, JSON.stringify(ledger, null, 2) + '\n');
  try {
    const response = await fetch(new URL(path, base), { ...init, redirect: 'error', signal: AbortSignal.timeout(12000) });
    row.status = response.status; row.finishedAt = new Date().toISOString();
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (path.startsWith('/dns/')) {
      const decoded = decode(bytes);
      row.body = JSON.stringify({ flags: decoded.flags, questions: decoded.questions, records: decoded.records, codes: response.headers.get('X-Ip-List-Codes') });
      await fs.writeFile(ledgerPath, JSON.stringify(ledger, null, 2) + '\n');
      if (!response.ok) throw new Error(`Cloud test failed at ${path}: HTTP ${response.status}`);
      return { ...decoded, code: response.headers.get('X-Ip-List-Codes') ?? '' };
    }
    const text = new TextDecoder().decode(bytes); row.body = text.slice(0, 12000);
    await fs.writeFile(ledgerPath, JSON.stringify(ledger, null, 2) + '\n');
    if (!response.ok) throw new Error(`Cloud test failed at ${path}: HTTP ${response.status}`);
    try { return JSON.parse(text); } catch { throw new Error(`Cloud test returned non-JSON at ${path}`); }
  } catch (error) {
    row.error = String(error?.message ?? error); row.finishedAt = new Date().toISOString();
    await fs.writeFile(ledgerPath, JSON.stringify(ledger, null, 2) + '\n'); throw error;
  }
}
function echParam(record) {
  if (record.type !== 65 && record.type !== 64) return undefined;
  const data = record.data;
  let offset = 2;
  while (offset < data.length) {
    const length = data[offset++];
    if ((length & 0xc0) === 0xc0) { offset++; break; }
    if (length === 0) break;
    offset += length;
  }
  while (offset + 4 <= data.length) {
    const key = data[offset] * 256 + data[offset + 1];
    const size = data[offset + 2] * 256 + data[offset + 3];
    offset += 4;
    if (offset + size > data.length) throw new Error('Malformed SvcParam boundary');
    if (key === 5) return data.slice(offset, offset + size);
    offset += size;
  }
  return undefined;
}
const suite = await request('/suite');
if (suite.passed !== true || !Array.isArray(suite.results) || suite.results.length < 20 || suite.results.some(test => test.passed !== true)) throw new Error('Suite did not pass all expected cases');
const persistent = await request('/persistent');
if (persistent.first !== 'origin' || persistent.second !== 'cache' || persistent.calls !== 1 || persistent.firstStoredAt !== persistent.secondStoredAt || persistent.match !== true) throw new Error('Workers Cache API did not demonstrate independent-store persistent reuse');
const expected = { text:'ok', text2:'ok', json:'ok', fail:'IP_LIST_FAILED', redirect:'IP_LIST_FAILED', html:'IP_LIST_INVALID', utf8:'IP_LIST_INVALID', bad:'IP_LIST_INVALID', large:'RESOURCE_LIMIT', entries:'RESOURCE_LIMIT', state:'RESOURCE_LIMIT', nullttl:'INVALID_CONFIG', slow:'IP_LIST_TIMEOUT', timeout:'EXECUTION_TIMEOUT', budget:'RESOURCE_LIMIT', cancel:'REQUEST_CANCELLED' };
const firstText = await request('/prepare/text2');
const secondText = await request('/prepare/text2');
for (const label of Object.keys(expected).filter(label => label !== 'text2')) {
  const result = await request('/prepare/' + label);
  if (result.code !== expected[label]) throw new Error(`Unexpected ${label} result ${result.code}`);
}
if (firstText.code !== 'ok' || secondText.code !== 'ok' || firstText.calls !== 1 || secondText.calls !== 0) throw new Error(`Cache API hit not demonstrated: first=${firstText.calls} second=${secondText.calls}`);
for (const label of ['cf','meta']) {
  const result = await request('/equivalence/' + label);
  const entries = label === 'cf' ? 780 : 118;
  if (result.passed !== true || result.entries !== entries || !Number.isSafeInteger(result.checked) || result.checked < entries * 2) throw new Error(`CIDR equivalence not established for ${label}`);
}
const dnsCases = {
  cf: ['www.cloudflare.com', 65, 0, 65],
  non: ['example.net', 65, 0, 65], negative: ['example.net', 65, 3, 0],
  'meta-domain': ['www.facebook.com', 65, 0, 65],
  'meta-ip': ['example.net', 65, 0, 65],
  v4: ['example.net', 1, 0, 1], v6: ['example.net', 28, 0, 28],
  nov6: ['www.pixiv.net', 28, 0, 0],
  missing: ['example.net', 1, 2, 0], unused: ['example.net', 1, 2, 0], selector: ['example.net', 1, 2, 0],
};
for (const [label, [name, type, rcode, expectedType]] of Object.entries(dnsCases)) {
  const result = await request('/dns/' + label, { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query(name, type) });
  if ((result.flags & 15) !== rcode || result.questions.length !== 1 || result.questions[0].name !== name) throw new Error(`DNS response mismatch for ${label}`);
  if (expectedType && !result.records.some(record => record.type === expectedType)) throw new Error(`Expected record type ${expectedType} for ${label}`);
  if ((label === 'v4' || label === 'v6') && !result.records.some(record => record.type === type)) throw new Error(`${label} did not return an address record`);
  if (label === 'meta-domain') {
    const ech = result.records.map(echParam).find(value => value !== undefined);
    if (!ech || ech.length !== 707) throw new Error(`Meta fixed-domain ECH list mismatch: ${ech?.length ?? 0} bytes`);
  }
  if (label === 'cf' || label === 'meta-ip') {
    const ech = result.records.map(echParam).find(value => value !== undefined);
    if (!ech || ech.length < 4 || ech[0] * 256 + ech[1] !== ech.length - 2) throw new Error(`${label} response lacks a valid ECH SvcParam 5`);
  }
  if (label === 'nov6' && result.records.some(record => record.type === 28)) throw new Error('X/Pixiv AAAA policy returned AAAA records');
  if (label === 'missing' && !result.code.includes('INVALID_CONFIG')) throw new Error('Missing list reference was not rejected during preflight');
  if (label === 'unused' && !result.code.includes('INVALID_CONFIG')) throw new Error('Unused malformed list definition was not rejected');
  if (label === 'selector' && !result.code.includes('INVALID_CONFIG')) throw new Error('Action selector IP list reference was not preflighted');
}
for (const name of ['pbs.twimg.com', 'www.pixiv.net']) {
  const result = await request('/dns/nov6', { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query(name, 28) });
  if ((result.flags & 15) !== 0 || result.records.some(record => record.type === 28)) throw new Error(`${name} AAAA should be empty NOERROR`);
}
console.log(JSON.stringify({ passed: true, requestCount: ledger.length, sameWorkerReuse: { first: firstText.calls, second: secondText.calls }, persistentCacheApi: { first: persistent.first, second: persistent.second, calls: persistent.calls, storedAtPreserved: persistent.firstStoredAt === persistent.secondStoredAt }, ledgerPath }));
