import worker from '../src/worker.js';

// Test-only wall clock. DNS work still enters the unmodified public HTTP handler.
const realNow = Date.now;
/** @type {number | undefined} */
let now;
Date.now = () => now ?? realNow();
export default {
  /** @param {Request} request @param {Record<string, unknown>} env */
  fetch(request, env) {
    const value = request.headers.get('x-test-time');
    now = value === null ? undefined : Number(value);
    return worker.fetch(request, env);
  },
};
