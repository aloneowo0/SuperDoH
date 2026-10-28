import * as http from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const endpoint = process.env.DNS_ECS_CHECK_URL;
const token = process.env.DNS_ECS_CHECK_KEY;
if (!endpoint || !token) throw new Error('Set DNS_ECS_CHECK_URL and DNS_ECS_CHECK_KEY before running the approved cloud suite.');
const target = new URL(endpoint);
if (target.protocol !== 'https:' || target.username || target.password || target.search || target.hash) throw new Error('The fixed suite endpoint must be HTTPS without credentials, query, or fragment.');
if (typeof http.setGlobalProxyFromEnv !== 'function') throw new Error('This runner requires a Node.js version exposing node:http setGlobalProxyFromEnv.');
http.setGlobalProxyFromEnv();

const here = path.dirname(fileURLToPath(import.meta.url));
const ledgerName = process.env.DNS_ECS_CHECK_LEDGER;
if (!ledgerName) throw new Error('Set DNS_ECS_CHECK_LEDGER explicitly (for this reviewed retry use ledger-v2.json).');
const versionMatch = /^ledger-v([2-9][0-9]*)\.json$/.exec(ledgerName);
if (!versionMatch) throw new Error('Use a new versioned ledger filename such as ledger-v2.json.');
const ledgerVersion = Number(versionMatch[1]);
const resultsName = process.env.DNS_ECS_CHECK_RESULTS ?? `results-v${ledgerVersion}.json`;
const localPath = (name, prefix) => {
  if (name !== path.basename(name) || !new RegExp(`^${prefix}[A-Za-z0-9._-]*\\.json$`).test(name)) throw new Error('Ledger/results names must be JSON basenames inside the harness directory.');
  const resolved = path.resolve(here, name);
  if (path.dirname(resolved) !== path.resolve(here)) throw new Error('Ledger/results file must remain inside the harness directory.');
  return resolved;
};
const ledgerPath = localPath(ledgerName, 'ledger-');
const resultsPath = localPath(resultsName, 'results-');
const previousLedgerName = process.env.DNS_ECS_CHECK_PREVIOUS_LEDGER;
if (!previousLedgerName || previousLedgerName !== path.basename(previousLedgerName)) throw new Error('Set DNS_ECS_CHECK_PREVIOUS_LEDGER to the prior ledger basename (for this retry: ledger-v2.json).');
const expectedPreviousName = ledgerVersion === 2 ? 'ledger.json' : `ledger-v${ledgerVersion - 1}.json`;
if (previousLedgerName !== expectedPreviousName) throw new Error(`Ledger ${ledgerName} must inherit from ${expectedPreviousName}.`);
const previousLedger = path.join(here, previousLedgerName);
for (const candidate of [ledgerPath, resultsPath]) {
  try { await readFile(candidate); throw new Error(`Refusing to overwrite existing ${path.basename(candidate)}.`); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
let previousUsed;
try {
  const previous = JSON.parse(await readFile(previousLedger, 'utf8'));
  if (previous.budget !== 40 || !Number.isInteger(previous.used) || previous.used < 1 || previous.used > 40) throw new Error(`Prior ledger ${previousLedgerName} has invalid budget accounting.`);
  const previousStartedAt = Date.parse(previous.startedAt);
  if (!Number.isFinite(previousStartedAt) || Date.now() - previousStartedAt < 1050) throw new Error('Prior request must be at least 1050 ms old before another runner request.');
  previousUsed = previous.used;
} catch (error) {
  if (error.code === 'ENOENT') throw new Error(`Required prior ledger ${previousLedgerName} is missing; refusing to reset the cumulative request budget.`);
  throw error;
}
const state = {
  budget: 40,
  used: previousUsed,
  inheritedUsed: previousUsed,
  inheritedFrom: previousLedgerName,
  startedAt: new Date().toISOString(),
  result: 'pending',
  resultsFile: resultsName,
};
await writeFile(ledgerPath, JSON.stringify(state, null, 2), { flag: 'wx' });
if (state.used >= state.budget) throw new Error('The approved cloud request budget is exhausted.');
state.used++;
state.startedAt = new Date().toISOString();
state.result = 'in-flight';
await writeFile(ledgerPath, JSON.stringify(state, null, 2));

const requiredChecks = [
  'disabledDefaults', 'fullUpstreamPreflight', 'clientPrefixesAndOptPreservation', 'ipv6Truncation', 'nonBytePrefix', 'fixedNormalization',
  'incomingZeroAndPrefixCaps', 'invalidIncomingEcsRejected', 'badResponsesRejected', 'nonBytePaddingRejected', 'responseIdentityRestore', 'untrustedRequestHeadersIgnored',
  'cloudClientIpv4', 'cloudClientIpv6', 'cloudFixedSubnet', 'cloudMissingTrustedIp', 'cloudConfiguredPrefixZero', 'cloudInboundZero',
  'responseSanitized', 'notSelectedUpstreamUnaffected', 'cloudDefaultDisabled', 'doAdOtherOptAndExtendedRcode', 'extendedRcodeWithoutClientOptRejected', 'optionalRollback',
  'queryEchIsolated', 'cancelledBeforeNetwork', 'responseIdentityMismatchRejected', 'cacheResultsSuccessful', 'cacheStatsSameColo',
  'cacheStatsSameIsolate', 'cacheSameSubnetHitAndCrossSubnetMiss', 'fixedResolverBoundary',
];
let resultSaved = false;
let parsedBody;
try {
  const response = await fetch(target, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
    redirect: 'error',
    signal: AbortSignal.timeout(20000),
  });
  const text = await response.text();
  await writeFile(resultsPath, text, { flag: 'wx' });
  resultSaved = true;
  let body;
  try { body = JSON.parse(text); } catch { throw new Error(`Suite returned non-JSON HTTP ${response.status}.`); }
  parsedBody = body;
  state.checks = body.checks ?? null;
  state.httpStatus = response.status;
  if (!response.ok) throw new Error(`Suite returned HTTP ${response.status}.`);
  if (body.suite !== 'ecs-fixed-fixtures-v2' || !body.checks || typeof body.checks !== 'object' || Array.isArray(body.checks)) {
    throw new Error('Suite response identity or checks object is invalid.');
  }
  const missing = requiredChecks.filter(name => body.checks[name] !== true);
  const unexpected = Object.keys(body.checks).filter(name => !requiredChecks.includes(name));
  const failed = [...missing, ...unexpected.map(name => `unexpected:${name}`)];
  if (failed.length || body.missing?.length) {
    state.result = 'failed';
    state.failedChecks = failed.length ? failed : body.missing;
    state.cacheStats = body.cacheStats ?? null;
    state.googleResolverError = body.googleResolverError ?? null;
    state.error = 'CHECKS_FAILED';
    await writeFile(ledgerPath, JSON.stringify(state, null, 2));
    throw new Error(`Cloud ECS suite failed checks: ${state.failedChecks.join(', ')}.`);
  }
  state.result = 'completed';
  state.checks = body.checks;
  state.cacheStats = body.cacheStats ?? null;
  state.googleResolverError = body.googleResolverError ?? null;
  state.limitation = body.limitation ?? null;
  await writeFile(ledgerPath, JSON.stringify(state, null, 2));
  console.log(JSON.stringify({ suite: body.suite, checks: body.checks, cacheStats: body.cacheStats, googleResolverError: body.googleResolverError, limitation: body.limitation, requestCount: state.used, ledger: ledgerName, results: resultsName }, null, 2));
} catch (error) {
  if (!resultSaved) {
    try {
      await writeFile(resultsPath, JSON.stringify({ result: 'no-response-body', error: { name: error?.name ?? 'Error', code: error?.code ?? 'REQUEST_FAILED', message: String(error?.message ?? 'Request failed').replace(/https?:\/\/[^\s)]+/gi, '[redacted-url]').slice(0, 200) } }, null, 2), { flag: 'wx' });
      resultSaved = true;
    } catch (writeError) {
      state.resultsWriteError = String(writeError?.code ?? 'WRITE_FAILED');
    }
  }
  if (parsedBody) {
    state.checks = parsedBody.checks ?? null;
    state.cacheStats = parsedBody.cacheStats ?? null;
    state.googleResolverError = parsedBody.googleResolverError ?? null;
  }
  if (state.result !== 'failed') {
    state.result = 'failed';
    state.error = error?.name === 'TimeoutError' ? 'TIMEOUT' : String(error?.code ?? 'REQUEST_FAILED');
  }
  try { await writeFile(ledgerPath, JSON.stringify(state, null, 2)); }
  catch (ledgerError) { console.error(`Ledger write failed (${ledgerName}): ${ledgerError?.code ?? 'WRITE_FAILED'}`); }
  throw error;
}
