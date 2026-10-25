import assert from 'node:assert/strict';
import { test, after } from 'node:test';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';
import { query, decode } from './helpers/dns-wire.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const bundle = await build({
  stdin: { contents: `import { executeQuery } from './src/index.js';
    const clone = globalThis.structuredClone;
    globalThis.structuredClone = value => { globalThis.clones++; return clone(value); };
    export default { async fetch(request, env) {
      globalThis.finalizations = 0; globalThis.clones = 0;
      const events = [];
      try {
        const result = await executeQuery(new Uint8Array(await request.arrayBuffer()), env, { onEvent: event => events.push(event) });
        return Response.json({ ...result, response: Array.from(result.response), finalizations: globalThis.finalizations, clones: globalThis.clones, events });
      } catch (error) { return Response.json({ code: error.code }, { status: 500 }); }
    } };`, resolveDir: root, sourcefile: 'ownership-worker.js' },
  bundle: true, write: false, external: ['cloudflare:sockets'], format: 'esm', platform: 'browser',
  plugins: [{ name: 'ownership-probes', setup(build) {
    build.onResolve({ filter: /\.wasm$/ }, args => ({ path: '../' + path.relative(root, path.resolve(args.resolveDir, args.path)).split(path.sep).join('/'), external: true }));
    build.onLoad({ filter: /protocol[.]js$/ }, async args => ({
      contents: (await fs.readFile(args.path, 'utf8')).replace(
        'export function finalizeResponse(response, original, originalWire, maximum, location = {}) {',
        'export function finalizeResponse(response, original, originalWire, maximum, location = {}) { globalThis.finalizations++;'),
      loader: 'js',
    }));
  } }],
});
const options = bindings => ({ modules: true, modulesRoot: root, scriptPath: path.join(root, 'test/ownership-bundle.js'),
  script: bundle.outputFiles[0].text, compatibilityDate: '2026-10-19',
  compatibilityFlags: ['no_nodejs_compat', 'no_nodejs_compat_v2'], bindings,
  modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true }],
  outboundService: () => { throw new Error('Unexpected network access'); },
});
const mf = new Miniflare(options({}));
after(() => mf.dispose());
const answer = { type: 'answer', records: [{ name: 'example.com', type: 'A', ttl: 60, rdata: { A: { addr: '192.0.2.1' } } }] };
async function executeRules(rules, extra = {}) {
  await mf.setOptions(options({ DNS_RULE_MAIN: { order: 0, rules }, ...extra }));
  const response = await mf.dispatchFetch('https://ownership.test/', { method: 'POST', body: query() });
  assert.equal(response.status, 200);
  return response.json();
}
async function execute(actions, extra = {}) { return executeRules([{ actions }], extra); }

test('unchanged responses reuse per-action validation and final wire on every termination path', async () => {
  for (const end of [[], [{ type: 'stop' }], [{ type: 'return' }]]) {
    const result = await execute([answer, ...Array.from({ length: 64 }, () => ({ type: 'setCache', read: false, write: false })), ...end]);
    assert.equal(result.finalizations, 1);
    assert.ok(result.clones <= 2, `Unchanged responses should not be copied per action: ${result.clones}`);
    assert.equal(decode(result.response).records[0].ttl, 60);
  }
});

test('query rewriting after an answer never mutates the original query or cached response identity', async () => {
  const result = await execute([answer, { type: 'rewriteQuery', name: 'other.example' }, { type: 'setCache', write: false }]);
  assert.equal(result.finalizations, 1);
  assert.equal(result.query.questions[0].name, 'other.example');
  assert.equal(result.originalQuery.questions[0].name, 'example.com');
  assert.equal(decode(result.response).questions[0].name, 'example.com');
});

test('a failed edit preserves the earlier response and wire while later successful edits replace both', async () => {
  const invalid = { type: 'addRecords', onError: 'continue', records: [{ name: 'example.com', type: 'TXT', ttl: 60, rdata: { Txt: ['x'.repeat(100)] } }] };
  const result = await execute([answer, invalid, { type: 'setCache', write: false }], { DNS_LIMITS: { maxResponseBytes: 80 } });
  assert.equal(decode(result.response).records.length, 1);
  assert.equal(decode(result.response).records[0].ttl, 60);
  assert.deepEqual(result.events.map(({ event, actionType, code, location, disposition, rolledBack }) => ({ event, actionType, code, location, disposition, rolledBack })), [{
    event: 'action_failed', actionType: 'addRecords', code: 'RESOURCE_LIMIT',
    location: { group: 'DNS_RULE_MAIN', rule: 0, action: 1 }, disposition: 'rolled_back_continue', rolledBack: true,
  }]);
  assert.equal(result.finalizations, 2);
  const changed = await execute([answer, { type: 'setTtl', ttl: 17 }, { type: 'setCache', write: false }]);
  assert.equal(decode(changed.response).records[0].ttl, 17);
  assert.equal(changed.finalizations, 2);
});

test('failed query rewrite retains committed query and validated response', async () => {
  const result = await execute([answer, { type: 'rewriteQuery', name: 'longer-name.example', onError: 'continue' }], { DNS_LIMITS: { maxQueryBytes: 30 } });
  assert.equal(result.query.questions[0].name, 'example.com');
  assert.equal(result.lastAction.code, 'RESOURCE_LIMIT');
  assert.equal(result.lastAction.success, false);
  assert.equal(result.finalizations, 1);
  assert.equal(decode(result.response).records[0].ttl, 60);
});

test('failed response edits leave lastAction and response matching on committed state', async () => {
  const invalid = { type: 'addRecords', onError: 'continue', records: [{ name: 'example.com', type: 'TXT', ttl: 60, rdata: { Txt: ['x'.repeat(100)] } }] };
  const result = await executeRules([
    { actions: [answer, invalid] },
    { when: { all: [
      { field: 'lastAction.success', op: 'eq', value: false },
      { field: 'lastAction.actionType', op: 'eq', value: 'addRecords' },
      { field: 'lastAction.code', op: 'eq', value: 'RESOURCE_LIMIT' },
      { field: 'query.name', op: 'eq', value: 'example.com' },
      { collection: 'response.records', quantifier: 'any', where: { field: 'item.type', op: 'eq', value: 'A' } },
    ] }, actions: [{ type: 'setTtl', ttl: 23 }] },
  ], { DNS_LIMITS: { maxResponseBytes: 80 } });
  assert.deepEqual(result.events.map(({ code, location, disposition, rolledBack }) => ({ code, location, disposition, rolledBack })), [{
    code: 'RESOURCE_LIMIT', location: { group: 'DNS_RULE_MAIN', rule: 0, action: 1 }, disposition: 'rolled_back_continue', rolledBack: true,
  }]);
  assert.equal(result.query.questions[0].name, 'example.com');
  assert.equal(decode(result.response).records[0].ttl, 23);
  assert.deepEqual(result.lastAction, { success: true, actionType: 'setTtl', location: { group: 'DNS_RULE_MAIN', rule: 1, action: 0 } });
  assert.equal(result.finalizations, 3);
});

test('failed query rewrites leave lastAction and query matching on committed state', async () => {
  const result = await executeRules([
    { actions: [answer, { type: 'rewriteQuery', name: 'longer-name.example', onError: 'continue' }] },
    { when: { all: [
      { field: 'lastAction.success', op: 'eq', value: false },
      { field: 'lastAction.actionType', op: 'eq', value: 'rewriteQuery' },
      { field: 'lastAction.code', op: 'eq', value: 'RESOURCE_LIMIT' },
      { field: 'query.name', op: 'eq', value: 'example.com' },
      { collection: 'response.records', quantifier: 'any', where: { field: 'item.type', op: 'eq', value: 'A' } },
    ] }, actions: [{ type: 'setTtl', ttl: 31 }] },
  ], { DNS_LIMITS: { maxQueryBytes: 30 } });
  assert.deepEqual(result.events.map(({ code, location, disposition, rolledBack }) => ({ code, location, disposition, rolledBack })), [{
    code: 'RESOURCE_LIMIT', location: { group: 'DNS_RULE_MAIN', rule: 0, action: 1 }, disposition: 'rolled_back_continue', rolledBack: true,
  }]);
  assert.equal(result.query.questions[0].name, 'example.com');
  assert.equal(decode(result.response).records[0].ttl, 31);
  assert.deepEqual(result.lastAction, { success: true, actionType: 'setTtl', location: { group: 'DNS_RULE_MAIN', rule: 1, action: 0 } });
  assert.equal(result.finalizations, 2);
});
