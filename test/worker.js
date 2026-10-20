import { executeQuery, RuleError } from '../src/index.js';

// Test adapter only: this is not the application's DoH endpoint.
export default {
  /** @param {Request} request @param {Record<string, unknown>} env */
  async fetch(request, env) {
    try {
      const result = executeQuery(new Uint8Array(await request.arrayBuffer()), env);
      if (request.headers.has('x-test-mutate-result')) {
        try {
          // Deliberately violate the public read-only contract at runtime.
          // @ts-expect-error This is the behavior under test.
          result.originalQuery.questions[0].name = 'mutated.example';
        } catch (error) {
          if (!(error instanceof TypeError)) throw error;
        }
        result.query.questions[0].name = 'mutable.example';
      }
      return Response.json({ ...result, response: result.response && Array.from(result.response) });
    } catch (error) {
      if (!(error instanceof RuleError)) throw error;
      return Response.json({ code: error.code, message: error.message, location: error.location }, { status: 400 });
    }
  },
};
