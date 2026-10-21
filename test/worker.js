import { executeQuery, RuleError } from '../src/index.js';

// Test adapter only: this is not the application's DoH endpoint.
export default {
  /** @param {Request} request @param {Record<string, unknown>} env */
  async fetch(request, env) {
    /** @type {unknown[]} */
    const events = [];
    /** @type {unknown[][]} */
    const logs = [];
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
      return Response.json({ ...result, response: result.response && Array.from(result.response), events, logs });
    } catch (error) {
      if (!(error instanceof RuleError)) throw error;
      return Response.json({ code: error.code, message: error.message, location: error.location, events, logs }, { status: 400 });
    } finally {
      console.error = originalConsole;
    }
  },
};
