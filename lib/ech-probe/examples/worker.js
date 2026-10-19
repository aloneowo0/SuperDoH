import { EchProbeError, probeEch } from '../index.js';

// Keep the destination in server-side code. Do not map untrusted request
// parameters or bodies directly to socket destinations.
const target = { hostname: 'example.com', port: 443 };
// For an IP destination, provide an explicit DNS SNI name, e.g.
// { hostname: '192.0.2.10', serverName: 'ech.example.com' }.

// Certificate verification is enabled by default. Keep this endpoint protected.
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== '/ech-probe') return new Response('Not Found', { status: 404 });
    if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST' } });
    try {
      const result = await probeEch({ ...target, signal: request.signal });
      return Response.json({ authenticated: result.authenticated, target: result.target,
        port: result.port, serverName: result.serverName, handshakeComplete: result.handshakeComplete,
        elapsedMs: result.elapsedMs, bytesReceived: result.bytesReceived, base64: result.base64,
        configs: result.configs.map(config => config.known ? {
          version: config.version, configId: config.configId, kemId: config.kemId, publicName: config.publicName,
        } : { version: config.version, known: false }),
      }, { headers: { 'Cache-Control': 'no-store' } });
    } catch (error) {
      if (!(error instanceof EchProbeError)) throw error;
      const status = error.code === 'TIMEOUT' ? 504 : error.code === 'ABORTED' ? 408 : 502;
      return Response.json({ authenticated: false, error: error.code, message: error.message },
        { status, headers: { 'Cache-Control': 'no-store' } });
    }
  },
};
