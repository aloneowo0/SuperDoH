import { readFile, writeFile } from 'node:fs/promises';
import { setTimeout } from 'node:timers/promises';
import { setGlobalProxyFromEnv } from 'node:http';
setGlobalProxyFromEnv();
const counts = { eligibility: 18, hits: 8, isolation: 7, sources: 1, bypass: 10, pipeline: 5, ecs: 3, 'parity/core': 9,
  ...Object.fromEntries(Array.from({ length: 6 }, (_, i) => ['parity/map' + i, i === 5 ? 4 : 5])),
  'parity/ipv6': 5, 'parity/https0': 3, 'parity/https1': 3, 'parity/https2': 3, 'parity/https3': 3, 'parity/fallback': 6, 'parity/addresses': 6, 'parity/controls': 5 };
const selected = process.argv.slice(2);
if (!selected.length || new Set(selected).size !== selected.length || selected.some(s => !(s in counts))) throw Error('Pass explicit nonduplicate approved suite names.');
const dir = new URL('../../../.acceptance/padding-cache-20261028/', import.meta.url);
const access = JSON.parse(await readFile(new URL('access.json', dir), 'utf8'));
const ledgerFile = new URL('ledger.json', dir);
const ledger = JSON.parse(await readFile(ledgerFile, 'utf8'));
if (ledger.budget !== 40 || !Number.isInteger(ledger.used) || ledger.used !== ledger.requests.length || ledger.used + selected.length > 40) throw Error('Cloud request budget invalid or exhausted.');
if (access.expires <= Date.now()) throw Error('Suite expired.');
const failed = [];
for (const suite of selected) {
  const previous = ledger.requests.at(-1);
  if (previous) await setTimeout(Math.max(0, 1050 - (Date.now() - Date.parse(previous.startedAt))));
  const number = ++ledger.used;
  const row = { number, suite, startedAt: new Date().toISOString(), status: 'attempted' };
  ledger.requests.push(row);
  await writeFile(ledgerFile, JSON.stringify(ledger, null, 2));
  try {
    const response = await fetch(`${access.endpoint}/${access.key}/${suite}`, { method: 'POST', headers: { authorization: `Bearer ${access.key}` }, redirect: 'error', signal: AbortSignal.timeout(60000) });
    row.http = response.status;
    const chunks = []; let size = 0;
    for await (const chunk of response.body) { size += chunk.length; if (size > 65536) throw Error('response-too-large'); chunks.push(chunk); }
    const text = Buffer.concat(chunks).toString('utf8');
    await writeFile(new URL(`response-${number}.json`, dir), text, { flag: 'wx' });
    const body = JSON.parse(text);
    row.body = body;
    row.status = response.ok && body.passed === true && body.results?.length === counts[suite] && body.results.every(r => r.passed === true) ? 'passed' : 'failed';
  } catch (error) {
    row.status = 'failed'; row.error = String(error.name ?? 'REQUEST_FAILED');
    row.cause = String(error.cause?.code ?? 'UNKNOWN');
  }
  if (row.status !== 'passed') failed.push(suite);
  await writeFile(ledgerFile, JSON.stringify(ledger, null, 2));
  console.log(JSON.stringify({ number, suite, status: row.status, http: row.http, count: row.body?.results?.length, failed: row.body?.results?.filter(r => !r.passed), error: row.error }));
}
console.log(JSON.stringify({ used: ledger.used, budget: ledger.budget, failed }));
if (failed.length) process.exitCode = 1;
