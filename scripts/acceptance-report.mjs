#!/usr/bin/env node
import { open } from 'node:fs/promises';

const MAX_BYTES = 2 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SLUG = /^[a-zA-Z0-9_-]{1,64}$/;
const SAMPLE_PHASES = new Set(['cold-candidate', 'warm', 'unspecified']);
const ERROR_CODES = new Set(['HTTP_FAILED', 'DNS_INVALID', 'DNS_UNEXPECTED', 'NETWORK_FAILED', 'TIMEOUT', 'BODY_LIMIT']);
const OUTCOMES = new Set(['ok', 'exception', 'exceededCpu', 'exceededMemory', 'canceled', 'unknown']);

function fail() { throw new Error('INVALID_INPUT'); }
function object(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail();
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail();
}
function finite(value, min = 0) { return typeof value === 'number' && Number.isFinite(value) && value >= min; }
function slug(value) { return typeof value === 'string' && SLUG.test(value); }
function dateOnly(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const [year, month, day] = value.split('-').map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}
function iso(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) &&
    dateOnly(value.slice(0, 10)) && Number.isFinite(Date.parse(value));
}
function uuid(value) { return typeof value === 'string' && UUID.test(value); }
function nullable(value, predicate) { return value === null || predicate(value); }

async function readJson(file) {
  let handle;
  try {
    handle = await open(file, 'r');
    const info = await handle.stat();
    if (!info.isFile() || info.size > MAX_BYTES) fail();
    const bytes = Buffer.alloc(MAX_BYTES + 1);
    let length = 0;
    while (length < bytes.length) {
      const { bytesRead } = await handle.read(bytes, length, bytes.length - length, null);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length > MAX_BYTES) fail();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length));
    return JSON.parse(text);
  } catch {
    fail();
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

function validateCollection(data) {
  object(data, ['version', 'mode', 'runId', 'metadata', 'samples', 'stopped']);
  if (data.version !== 1 || !['local', 'authorized-online'].includes(data.mode) || !uuid(data.runId)) fail();
  object(data.metadata, ['commit', 'worker', 'accountPlan', 'approvalRef']);
  if (typeof data.metadata.commit !== 'string' || !/^[a-f\d]{7,40}$/i.test(data.metadata.commit) ||
      !slug(data.metadata.worker) || !['free', 'local'].includes(data.metadata.accountPlan) || !slug(data.metadata.approvalRef)) fail();
  if (!Array.isArray(data.samples) || data.samples.length > 500 || !Array.isArray(data.stopped) || data.stopped.length > 100 || !data.stopped.every(slug)) fail();
  const scenarios = new Set();
  const ids = new Set();
  for (const sample of data.samples) {
    object(sample, ['id', 'scenario', 'phase', 'startedAt', 'latencyMs', 'correct', 'errorCode', 'httpStatus', 'dnsRcode']);
    if (!uuid(sample.id) || ids.has(sample.id) || !slug(sample.scenario) || !SAMPLE_PHASES.has(sample.phase) || !iso(sample.startedAt) ||
        !finite(sample.latencyMs) || typeof sample.correct !== 'boolean' || !nullable(sample.errorCode, code => ERROR_CODES.has(code)) ||
        !nullable(sample.httpStatus, status => Number.isInteger(status) && status >= 100 && status <= 599) ||
        !nullable(sample.dnsRcode, code => Number.isInteger(code) && code >= 0 && code <= 4095) ||
        (sample.correct && (sample.errorCode !== null || sample.httpStatus !== 200 || sample.dnsRcode === null)) ||
        (!sample.correct && sample.errorCode === null)) fail();
    ids.add(sample.id);
    scenarios.add(JSON.stringify([sample.scenario, sample.phase]));
  }
  if (scenarios.size > 100) fail();
  return { ...data, ids };
}

function validateTelemetry(data, sampleIds) {
  object(data, ['version', 'cpuLimitMs', 'verifiedOn', 'samples']);
  if (data.version !== 1 || !finite(data.cpuLimitMs, Number.MIN_VALUE) || !dateOnly(data.verifiedOn) ||
      !Array.isArray(data.samples) || data.samples.length > 1000) fail();
  const byId = new Map();
  for (const item of data.samples) {
    object(item, ['sampleId', 'cpuMs', 'wallMs', 'outcome']);
    if (!uuid(item.sampleId) || byId.has(item.sampleId) || !finite(item.cpuMs) || !finite(item.wallMs) || !OUTCOMES.has(item.outcome)) fail();
    byId.set(item.sampleId, item);
  }
  return { limit: data.cpuLimitMs, verifiedOn: data.verifiedOn, byId, orphans: [...byId.keys()].filter(id => !sampleIds.has(id)).length };
}

function distribution(values) {
  if (!values.length) return { count: 0, min: null, median: null, p95: null, max: null };
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return {
    count: sorted.length,
    min: sorted[0],
    median: sorted.length % 2 ? sorted[middle] : sorted[middle - 1] / 2 + sorted[middle] / 2,
    p95: sorted.length >= 100 ? sorted[Math.ceil(sorted.length * 0.95) - 1] : null,
    max: sorted[sorted.length - 1],
  };
}

function buildReport(collection, telemetry) {
  const groups = new Map();
  for (const sample of collection.samples) {
    const key = JSON.stringify([sample.scenario, sample.phase]);
    if (!groups.has(key)) groups.set(key, { scenario: sample.scenario, phase: sample.phase, samples: [] });
    groups.get(key).samples.push(sample);
  }
  const cases = [...groups.values()].map(group => {
    const records = group.samples.map(sample => ({ sample, measured: telemetry?.byId.get(sample.id) }));
    const cpu = records.filter(row => row.measured).map(row => row.measured.cpuMs);
    const wall = records.filter(row => row.measured).map(row => row.measured.wallMs);
    const missingTelemetryCount = records.filter(row => !row.measured).length;
    const unknownOutcomeCount = records.filter(row => row.measured?.outcome === 'unknown').length;
    const failed = records.some(({ sample, measured }) => !sample.correct ||
      (measured && ['exception', 'exceededCpu', 'exceededMemory', 'canceled'].includes(measured.outcome)) ||
      (measured && telemetry && measured.cpuMs > telemetry.limit));
    let conclusion;
    if (failed) conclusion = 'failed';
    else if (collection.mode === 'local' || collection.stopped.includes(group.scenario) || !telemetry || missingTelemetryCount || unknownOutcomeCount) conclusion = 'blocked';
    else conclusion = 'observed-within-declared-limit';
    return {
      scenario: group.scenario,
      phase: group.phase,
      sampleCount: records.length,
      correctCount: records.filter(row => row.sample.correct).length,
      incorrectCount: records.filter(row => !row.sample.correct).length,
      errorCount: records.filter(row => !row.sample.correct || row.sample.errorCode !== null).length,
      missingTelemetryCount,
      unknownOutcomeCount,
      clientLatencyMs: distribution(records.map(row => row.sample.latencyMs)),
      cpuMs: distribution(cpu),
      wallMs: distribution(wall),
      conclusion,
    };
  });
  return {
    version: 1,
    runId: collection.runId,
    mode: collection.mode,
    metadata: collection.metadata,
    stopped: collection.stopped,
    telemetry: telemetry ? {
      declaredCpuLimitMs: telemetry.limit,
      verifiedOn: telemetry.verifiedOn,
      correlatedSampleCount: [...telemetry.byId.keys()].filter(id => collection.ids.has(id)).length,
      missingSampleCount: cases.reduce((sum, item) => sum + item.missingTelemetryCount, 0),
      unknownOutcomeCount: cases.reduce((sum, item) => sum + item.unknownOutcomeCount, 0),
      orphanTelemetryCount: telemetry.orphans,
      cpuLimitVerifiedFreePlan: false,
    } : null,
    cases,
    completeAcceptance: false,
    caveats: [
      'Client latency is end-to-end latency, not Worker CPU or platform wall time.',
      'Cold-candidate samples are not verified cold starts.',
      'External telemetry correlation is normalized, sampled, and not independently verified; missing measurements remain unavailable.',
      'The CPU threshold is user-provided and is not programmatically verified against the Free plan; a self-declared account plan does not establish plan status.',
      'A per-case observation within a declared CPU limit is not complete version acceptance.',
    ],
  };
}

async function main(args) {
  if (args.length < 1 || args.length > 2) fail();
  const collection = validateCollection(await readJson(args[0]));
  const telemetry = args.length === 2 ? validateTelemetry(await readJson(args[1]), collection.ids) : null;
  return buildReport(collection, telemetry);
}

try {
  const report = await main(process.argv.slice(2));
  process.stdout.write(JSON.stringify(report) + '\n');
} catch {
  process.stderr.write('{"error":{"code":"INVALID_INPUT"}}\n');
  process.exitCode = 1;
}
