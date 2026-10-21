import { handleRequest } from '../src/worker.js';
import { defineAction, defineCondition } from '../src/index.js';

/** @param {unknown} value */
function nonNegativeInteger(value) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new Error();
  return value;
}
const extensions = { conditions: {
  candidate: defineCondition(nonNegativeInteger, (ctx, minimum) => {
    const ttl = ctx.response?.answers[0]?.ttl ?? 0;
    // Attempted mutation affects only this invocation's snapshot.
    const mutable = /** @type {import('../lib/dns-wasm/index.js').DnsMessage} */ (ctx.response);
    if (mutable) mutable.answers.length = 0;
    return ttl >= minimum && ctx.query.questions[0].name === 'alias.example' && ctx.originalQuery.questions[0].name === 'example.com';
  }),
  explode: defineCondition(() => undefined, () => { throw new Error('private-adoption-exception'); }),
  nonBoolean: defineCondition(() => undefined, () => /** @type {boolean} */ (/** @type {unknown} */ ('private-invalid-result'))),
  slow: defineCondition(nonNegativeInteger, async (_ctx, delay) => { await new Promise(resolve => setTimeout(resolve, delay)); return false; }),
}, actions: {
  ttl: defineAction(nonNegativeInteger, (ctx, value) => { if (ctx.response) ctx.response.answers[0].ttl = value; }),
  pause: defineAction(nonNegativeInteger, async (_ctx, value) => { await new Promise(resolve => setTimeout(resolve, value)); }),
  edns: defineAction(() => undefined, ctx => { ctx.query.additional = [{ name: '.', rtype: 41, class: 1232, ttl: 0x8000, rdata: { Opt: { options: [] } } }]; }),
  noop: defineAction(() => undefined, () => {}),
  inject: defineAction(() => undefined, ctx => {
    if (ctx.response) ctx.response.additional.push({ name: '.', rtype: 41, class: 1232, ttl: 1, rdata: { Opt: { options: [] } } });
  }),
} };

// A code-composition fixture using the public handler, never a private testing API.
export default {
  /** @param {Request} request @param {Record<string, unknown>} env */
  async fetch(request, env) {
    const controller = new AbortController();
    const timer = request.headers.has('x-test-cancel') ? setTimeout(() => controller.abort('private-cancel-reason'), 20) : undefined;
    try { return await handleRequest(request, env, { extensions, signal: controller.signal }); }
    finally { if (timer !== undefined) clearTimeout(timer); }
  },
};
