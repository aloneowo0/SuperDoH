import { executeQuery, RuleError, defineCondition, defineAction } from '../src/index.js';

/** @param {unknown} value */
function ttl(value) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error('private parameter');
  return value;
}
/** @param {unknown} value */
function mode(value) {
  if (typeof value !== 'string') throw new Error();
  return value;
}
// Test-only hostile retention: prove the executor never lends live request state.
/** @type {import('../src/rules/types.js').ActionContext | undefined} */
let retained;
const sharedParams = { count: 0 };
/** @param {unknown} value */
function counter(value) {
  if (!value || typeof value !== 'object' || !('count' in value)) throw new Error();
  return { count: ttl(value.count) };
}
const extensions = {
  conditions: {
    // @ts-expect-error Deliberately invalid return from trusted code.
    broken: defineCondition(mode, (_ctx, value) => {
      if (value === 'throw') throw new TypeError('Bearer secret https://user:password@private.test/path-key');
      return value;
    }),
    isolated: defineCondition(counter, (ctx, params) => {
      // @ts-expect-error Hostile code deliberately ignores the readonly type.
      ctx.query.questions[0].name = 'polluted.example';
      // @ts-expect-error Original data is readonly to extension authors.
      ctx.originalQuery.questions[0].name = 'polluted.example';
      if (ctx.response) {
        // @ts-expect-error Conditions cannot modify engine state.
        ctx.response.answers[0].ttl = 999;
      }
      return params.count++ === 0 && ctx.item?.ttl === 60;
    }),
    initialContext: defineCondition(ttl, (ctx, expected) => ctx.context.client?.asn === expected),
    delayed: defineCondition(ttl, async (_ctx, value) => {
      await new Promise(resolve => setTimeout(resolve, value));
      return true;
    }),
    ttlIs: defineCondition(ttl, async (ctx, value) => ctx.response?.answers[0]?.ttl === value) },
  actions: {
    asyncParams: defineAction(async () => { throw new Error('private-parser-secret'); }, () => {}),
    metadata: defineAction(() => ({ then: 'metadata' }), (ctx, params) => {
      if (ctx.response && params.then === 'metadata') ctx.response.answers[0].ttl = 27;
    }),
    detached: defineAction(ttl, (ctx, value) => {
      // Deliberately broken extension: late work must not retain live DNS state.
      setTimeout(() => {
        ctx.query.questions[0].name = 'late.example';
        if (ctx.response) ctx.response.answers[0].ttl = 999;
      }, value);
    }),
    protocol: defineAction(mode, (ctx, value) => {
      if (!ctx.response) throw new Error();
      const rr = ctx.response.answers[0];
      if (value === 'extra') {
        // @ts-expect-error Extra native fields must not be silently ignored.
        rr.rdata = { A: { addr: '192.0.2.9', secret: true } };
      }
      if (value === 'opt') ctx.response.additional.push({ name: '.', rtype: 41, class: 1232, ttl: 0, rdata: { Opt: { options: [] } } });
      if (value === 'signature') ctx.response.answers.push({ ...rr, rtype: 46, rdata: { Rrsig: {
        type_covered: 'A', algorithm: 8, labels: 2, original_ttl: 60, expiration: 2000000000,
        inception: 1000000000, key_tag: 1, signer_name: 'example.com', signature: 'AQ==',
      } } });
      if (value === 'undefined') {
        // @ts-expect-error Invalid response deletion by trusted code.
        ctx.response = undefined;
      }
    }),
    shared: defineAction(() => sharedParams, (ctx, params) => { if (ctx.response) ctx.response.answers[0].ttl = ++params.count; }),
    hold: defineAction(mode, ctx => { retained = ctx; }),
    poke: defineAction(mode, () => {
      if (retained) {
        retained.query.questions[0].name = 'polluted.example';
        if (retained.response) retained.response.answers[0].ttl = 999;
        // @ts-expect-error Hostile code deliberately ignores readonly original data.
        retained.originalQuery.questions[0].name = 'polluted.example';
      }
    }),
    delay: defineAction(ttl, async (ctx, value) => {
      await new Promise(resolve => setTimeout(resolve, value));
      ctx.query.questions[0].name = 'late.example';
      if (ctx.response) ctx.response.answers[0].ttl = ctx.signal.aborted ? 888 : 777;
      throw new Error('late secret');
    }),
    pause: defineAction(ttl, async (_ctx, value) => { await new Promise(resolve => setTimeout(resolve, value)); }),
    edit: defineAction(mode, (ctx, value) => {
      if (ctx.response) ctx.response.answers[0].ttl = 999;
      ctx.query.questions[0].name = 'changed.example';
      if (value === 'throw') throw new RangeError('Bearer secret https://user:password@private.test/path-key');
      if (value === 'query') ctx.query.questions = [];
      if (value === 'response' && ctx.response) ctx.response.answers[0].rdata = { A: { addr: 'bad ip secret' } };
      if (value === 'records' && ctx.response) ctx.response.answers.push(structuredClone(ctx.response.answers[0]));
      if (value === 'oversize' && ctx.response) for (let i = 0; i < 20; i++) ctx.response.answers.push(structuredClone(ctx.response.answers[0]));
    }),
    ttl: defineAction(ttl, async (ctx, value) => { if (ctx.response) ctx.response.answers[0].ttl = value; }) },
};

// Test adapter only: this is not the application's DoH endpoint.
export default {
  /** @param {Request} request @param {Record<string, unknown>} env */
  async fetch(request, env) {
    /** @type {unknown[]} */
    const events = [];
    /** @type {unknown[][]} */
    const logs = [];
    let unhandled = 0;
    /** @param {PromiseRejectionEvent} event */
    const onUnhandled = event => { unhandled++; event.preventDefault(); };
    if (request.headers.has('x-test-rejections')) addEventListener('unhandledrejection', onUnhandled);
    const input = new Uint8Array(await request.arrayBuffer());
    const mode = request.headers.get('x-test-observer');
    const originalConsole = console.error;
    // Tests dispatch serially while capturing default diagnostics.
    console.error = (...args) => { logs.push(args); };
    const contextMode = request.headers.get('x-test-context-mode');
    try {
      const context = request.headers.has('x-test-context') ? JSON.parse(request.headers.get('x-test-context') ?? '') : undefined;
      // This getter deliberately fails inside the public context validation boundary.
      const suppliedContext = contextMode === 'throw' ? Object.defineProperty({}, 'client', { enumerable: true, get() { throw new Error('https://user:password@private.test/path-key'); } }) : context;
      const result = await executeQuery(input, env, {
        extensions,
        requestId: request.headers.get('x-test-request-id') ?? 'test-request',
        context: suppliedContext,
        onEvent: mode === 'default' ? undefined : event => {
          events.push(event);
          if (contextMode === 'mutate') context.client.asn = 64513;
          if (mode === 'throw') throw new Error('Bearer observer-secret https://user:password@private.test/path-key');
          if (mode === 'reject') return Promise.reject(new Error('observer-secret'));
          if (mode === 'input') input.fill(0);
          if (mode === 'mutate') {
            // @ts-expect-error Event metadata is deliberately read-only.
            event.location.group = 'changed';
          }
        },
      });
      if (request.headers.has('x-test-settle')) await new Promise(resolve => setTimeout(resolve, 100));
      if (request.headers.has('x-test-mutate-result')) {
        try {
          // @ts-expect-error This is the behavior under test.
          result.originalQuery.questions[0].name = 'mutated.example';
        } catch (error) {
          if (!(error instanceof TypeError)) throw error;
        }
        result.query.questions[0].name = 'mutable.example';
      }
      if (request.headers.has('x-test-mutate-edns')) {
        const option = result.query.additional[0].rdata;
        if ('Opt' in option) option.Opt.options[0].data[0] = 99;
      }
      return Response.json({ ...result, response: result.response && Array.from(result.response), events, logs, unhandled });
    } catch (error) {
      if (!(error instanceof RuleError)) throw error;
      if (request.headers.has('x-test-rejections')) await new Promise(resolve => setTimeout(resolve, 0));
      return Response.json({ code: error.code, message: error.message, location: error.location, events, logs, unhandled }, { status: 400 });
    } finally {
      if (request.headers.has('x-test-rejections')) removeEventListener('unhandledrejection', onUnhandled);
      console.error = originalConsole;
    }
  },
};
