import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));
const cli = path.join(root, 'scripts', 'acceptance-report.mjs');
const runId = '00000000-0000-4000-8000-000000000001';
const sampleId = '00000000-0000-4000-8000-000000000002';
const base = {
  version: 1,
  mode: 'authorized-online',
  runId,
  metadata: { commit: 'abcdef1', worker: 'test-worker', accountPlan: 'free', approvalRef: 'approved-run' },
  samples: [{ id: sampleId, scenario: 'simple-case', phase: 'warm', startedAt: '2026-10-22T12:00:00.000Z', latencyMs: 31, correct: true, errorCode: null, httpStatus: 200, dnsRcode: 0 }],
  stopped: [],
};

async function invoke(t, input, telemetry) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'acceptance-report-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const samplesPath = path.join(dir, 'samples.json');
  await writeFile(samplesPath, JSON.stringify(input));
  let telemetryPath;
  if (telemetry !== undefined) {
    telemetryPath = path.join(dir, 'telemetry.json');
    await writeFile(telemetryPath, JSON.stringify(telemetry));
  }
  return spawnSync(process.execPath, [cli, samplesPath, ...(telemetryPath ? [telemetryPath] : [])], { encoding: 'utf8' });
}

const telemetry = outcome => ({
  version: 1,
  cpuLimitMs: 10,
  verifiedOn: '2026-10-22',
  samples: [{ sampleId, cpuMs: 2, wallMs: 12, outcome }],
});

test('reports client latency separately from observed platform CPU and never calls local evidence complete', async t => {
  const result = await invoke(t, base, telemetry('ok'));
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.completeAcceptance, false);
  assert.equal(report.cases[0].clientLatencyMs.median, 31);
  assert.equal(report.cases[0].clientLatencyMs.p95, null);
  assert.equal(report.cases[0].cpuMs.median, 2);
  assert.equal(report.cases[0].conclusion, 'observed-within-declared-limit');
  assert.match(report.caveats.join(' '), /client latency.*not.*CPU/i);
});

test('does not infer CPU from client latency and retains absent measurements as blocked', async t => {
  const result = await invoke(t, { ...base, mode: 'local' });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.deepEqual(report.cases[0].cpuMs, { count: 0, min: null, median: null, p95: null, max: null });
  assert.equal(report.cases[0].clientLatencyMs.median, 31);
  assert.equal(report.cases[0].missingTelemetryCount, 1);
  assert.equal(report.cases[0].conclusion, 'blocked');
});

test('preserves failing outcomes and counts unmatched telemetry without exposing its contents', async t => {
  const extraId = '00000000-0000-4000-8000-000000000003';
  const telemetryWithOrphan = { ...telemetry('exceededCpu'), samples: [
    { sampleId, cpuMs: 15, wallMs: 20, outcome: 'exceededCpu' },
    { sampleId: extraId, cpuMs: 1, wallMs: 2, outcome: 'ok' },
  ] };
  const result = await invoke(t, base, telemetryWithOrphan);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.cases[0].conclusion, 'failed');
  assert.equal(report.cases[0].cpuMs.median, 15);
  assert.equal(report.telemetry.orphanTelemetryCount, 1);
  assert.equal(report.telemetry.cpuLimitVerifiedFreePlan, false);
  assert.ok(!result.stdout.includes('https://') && !result.stderr.includes('https://'));
});

test('rejects unknown input keys and duplicate telemetry correlations with a sanitized error', async t => {
  const invalidCollection = { ...base, requestUrl: 'https://secret.example/key' };
  const invalidTelemetry = { ...telemetry('ok'), samples: [telemetry('ok').samples[0], telemetry('ok').samples[0]] };
  for (const [input, timing] of [[invalidCollection, undefined], [base, invalidTelemetry]]) {
    const result = await invoke(t, input, timing);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '{"error":{"code":"INVALID_INPUT"}}\n');
    assert.ok(!result.stderr.includes('secret.example'));
  }
});

test('reports partial missing and unknown telemetry as unavailable instead of dropping samples', async t => {
  const missingSampleId = '00000000-0000-4000-8000-000000000004';
  const collection = { ...base, samples: [
    base.samples[0],
    { ...base.samples[0], id: missingSampleId, latencyMs: 42 },
  ] };
  const evidence = { ...telemetry('unknown'), samples: [telemetry('unknown').samples[0]] };
  const result = await invoke(t, collection, evidence);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.cases[0].sampleCount, 2);
  assert.equal(report.cases[0].missingTelemetryCount, 1);
  assert.equal(report.cases[0].unknownOutcomeCount, 1);
  assert.equal(report.telemetry.missingSampleCount, 1);
  assert.equal(report.telemetry.unknownOutcomeCount, 1);
  assert.equal(report.cases[0].conclusion, 'blocked');
});

test('unknown telemetry alone blocks, while its measured CPU overage remains a failure', async t => {
  const result = await invoke(t, base, telemetry('unknown'));
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.cases[0].unknownOutcomeCount, 1);
  assert.equal(report.cases[0].missingTelemetryCount, 0);
  assert.equal(report.cases[0].conclusion, 'blocked');

  const overLimit = { ...telemetry('unknown'), samples: [{ sampleId, cpuMs: 11, wallMs: 12, outcome: 'unknown' }] };
  const exceeded = await invoke(t, base, overLimit);
  assert.equal(exceeded.status, 0, exceeded.stderr);
  assert.equal(JSON.parse(exceeded.stdout).cases[0].conclusion, 'failed');
});

test('rejects inconsistent correctness and outcome fields through the public CLI', async t => {
  const inconsistent = [
    { ...base.samples[0], correct: true, httpStatus: 503 },
    { ...base.samples[0], correct: true, dnsRcode: null },
    { ...base.samples[0], correct: true, errorCode: 'HTTP_FAILED' },
    { ...base.samples[0], correct: false, errorCode: null },
  ];
  for (const sample of inconsistent) {
    const result = await invoke(t, { ...base, samples: [sample] }, telemetry('ok'));
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '{"error":{"code":"INVALID_INPUT"}}\n');
  }
});

test('bounds file reads and rejects oversized or invalid UTF-8 input safely', async t => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'acceptance-report-bytes-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const samplesPath = path.join(dir, 'samples.json');
  for (const bytes of [Buffer.alloc(2 * 1024 * 1024 + 1, 0x20), Buffer.from([0x7b, 0xff, 0x7d])]) {
    await writeFile(samplesPath, bytes);
    const result = spawnSync(process.execPath, [cli, samplesPath], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '{"error":{"code":"INVALID_INPUT"}}\n');
  }
});

test('stopped scenarios stay blocked even with good samples and complete telemetry', async t => {
  const collection = { ...base, stopped: ['simple-case'] };
  const result = await invoke(t, collection, telemetry('ok'));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).cases[0].conclusion, 'blocked');

  const failed = { ...base, stopped: ['simple-case'], samples: [{ ...base.samples[0], correct: false, errorCode: 'NETWORK_FAILED', httpStatus: null, dnsRcode: null }] };
  const failedResult = await invoke(t, failed, telemetry('exception'));
  assert.equal(failedResult.status, 0, failedResult.stderr);
  assert.equal(JSON.parse(failedResult.stdout).cases[0].conclusion, 'failed');
});

test('reports p95 only at one hundred samples and flags a declared CPU overage', async t => {
  const samples = Array.from({ length: 100 }, (_, index) => ({
    ...base.samples[0],
    id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`,
    latencyMs: index + 1,
  }));
  const timing = {
    version: 1,
    cpuLimitMs: 94,
    verifiedOn: '2026-10-22',
    samples: samples.map((sample, index) => ({ sampleId: sample.id, cpuMs: index + 1, wallMs: index + 2, outcome: 'ok' })),
  };
  const result = await invoke(t, { ...base, samples }, timing);
  assert.equal(result.status, 0, result.stderr);
  const row = JSON.parse(result.stdout).cases[0];
  assert.equal(row.sampleCount, 100);
  assert.equal(row.clientLatencyMs.p95, 95);
  assert.equal(row.cpuMs.p95, 95);
  assert.equal(row.conclusion, 'failed');
});
