import { handleRequest } from '../src/worker.js';
import * as api from '../src/index.js';

// Only trusted caller options; DNS conditions/actions in this fixture are JSON.
export default {
  /** @param {Request} request @param {Record<string, unknown>} env */
  async fetch(request, env) {
    if (request.headers.has('x-test-exports')) return Response.json(Object.keys(api));
    const controller = new AbortController();
    const timer = request.headers.has('x-test-cancel') ? setTimeout(() => controller.abort('private-cancel-reason'), 20) : undefined;
    try {
      return await handleRequest(request, env, {
        signal: controller.signal,
        onEvent: request.headers.has('x-test-observer') ? () => {
          if (request.headers.get('x-test-observer') === 'reject') return Promise.reject(new Error('private-observer-rejection'));
          throw new Error('private-observer-exception');
        } : undefined,
        ...(request.headers.has('x-test-registry') ? { extensions: {} } : {}),
      });
    } finally { if (timer !== undefined) clearTimeout(timer); }
  },
};
