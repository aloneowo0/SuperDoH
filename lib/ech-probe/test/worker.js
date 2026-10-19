import { probeEch } from '../index.js';
import { runSuite } from './suite.js';

export default {
  async fetch(request) {
    if (request.method !== 'POST') return new Response('POST fixture JSON', { status: 405 });
    try {
      const fixture = await request.json();
      const result = await runSuite(fixture.meta ? fixture : { meta: fixture });
      const controller = new AbortController(); controller.abort();
      let cancelled;
      try { await probeEch({ hostname: 'example.test', signal: controller.signal }); }
      catch (error) { cancelled = error; }
      if (!cancelled || cancelled.code !== 'ABORTED') throw new Error('pre-cancelled probe did not abort');
      return Response.json({ ...result, preCancelledProbe: 'ABORTED' });
    } catch (error) {
      return Response.json({ error: error?.stack || String(error) }, { status: 500 });
    }
  },
};
