import { handleRequest } from '../src/worker.js';

// Only this local fixture can remove metadata added by the development ingress.
export default {
  /** @param {Request} request @param {Record<string, unknown>} env */
  fetch(request, env) {
    if (request.headers.has('x-test-missing-client-ip')) {
      request = new Request(request);
      request.headers.delete('x-test-missing-client-ip');
      request.headers.delete('CF-Connecting-IP');
    }
    return handleRequest(request, env);
  },
};
