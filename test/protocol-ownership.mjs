import assert from 'node:assert/strict';
import { test, after } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';
import { query, decode, responseWire, nameWire } from './helpers/dns-wire.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const bundle = await build({
  stdin: { resolveDir: root, sourcefile: 'protocol-worker.js', contents: `
    import { finalizeResponse, invalidateResponse } from './src/doh/protocol.js';
    import { parseMessage } from './lib/dns-wasm/index.js';
    function freeze(value) {
      if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
      return value;
    }
    export default { async fetch(request) {
      const input = await request.json();
      const originalWire = Uint8Array.from(input.query);
      const original = freeze(parseMessage(originalWire));
      const response = freeze(parseMessage(Uint8Array.from(input.response)));
      const before = JSON.stringify(response), clone = globalThis.structuredClone;
      let clones = 0, output;
      globalThis.structuredClone = value => { clones++; return clone(value); };
      try {
        output = input.finalize ? Array.from(finalizeResponse(response, original, originalWire, 4096))
          : invalidateResponse(response, input.rrsets);
      } finally { globalThis.structuredClone = clone; }
      const unchanged = JSON.stringify(response) === before;
      if (!input.finalize) output.answers[0].ttl = 7;
      return Response.json({ output, clones, unchanged, originalTtl: response.answers[0].ttl });
    } };` },
  bundle: true, write: false, format: 'esm', platform: 'browser',
  plugins: [{ name: 'wasm-external', setup(build) {
    build.onResolve({ filter: /[.]wasm$/ }, args => ({
      path: '../' + path.relative(root, path.resolve(args.resolveDir, args.path)).split(path.sep).join('/'), external: true,
    }));
  } }],
});
const mf = new Miniflare({ modules: true, modulesRoot: root, scriptPath: path.join(root, 'test/protocol-bundle.js'),
  script: bundle.outputFiles[0].text, compatibilityDate: '2026-10-19',
  compatibilityFlags: ['no_nodejs_compat', 'no_nodejs_compat_v2'],
  modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true }],
  outboundService: () => { throw new Error('Unexpected network access'); },
});
after(() => mf.dispose());
const q = query();
const signature = [0,1,8,2,0,0,0,60,119,53,148,0,59,154,202,0,0,1,...nameWire('example.com'),1];
const wire = responseWire(q, { flags: 0x85b0, records: [
  { name: 'example.com', type: 1, ttl: 60, data: [192,0,2,8] },
  { name: 'example.com', type: 46, ttl: 60, data: signature },
  { name: 'example.com', type: 46, ttl: 60, data: [0,28,...signature.slice(2)] },
] });
async function execute(options) {
  const r = await mf.dispatchFetch('https://protocol.test/', { method: 'POST', body: JSON.stringify({ query: [...q], response: [...wire], ...options }) });
  assert.equal(r.status, 200);
  const result = await r.json();
  assert.equal(result.unchanged, true);
  assert.equal(result.originalTtl, 60);
  assert.equal(result.clones, 0, 'Protocol normalization must not deep-copy read-only record data');
  return result.output;
}

test('finalization rewrites only an isolated envelope without copying immutable records', async () => {
  const result = decode(await execute({ finalize: true }));
  assert.equal(result.id, 0x4242);
  assert.deepEqual(result.questions, [{ name: 'example.com', type: 1, class: 1 }]);
  assert.equal(result.flags & 0x0110, ((q[2] << 8) | q[3]) & 0x0110);
  assert.equal(result.records.length, 3);
});

test('invalidation uses private section arrays and returns independently owned normalized records', async () => {
  const result = await execute({});
  assert.equal(result.flags & 0x20, 0);
  assert.deepEqual(result.answers.map(r => r.rtype), [1]);
  assert.equal(result.answers[0].ttl, 7);
});

test('targeted invalidation retains unrelated signatures without editing frozen inputs', async () => {
  const result = await execute({ rrsets: [{ name: 'example.com', rtype: 1, class: 1 }] });
  assert.equal(result.flags & 0x20, 0);
  assert.deepEqual(result.answers.map(r => r.rtype), [1,46]);
  assert.equal(result.answers[1].rdata.Rrsig.type_covered, 'AAAA');
});
