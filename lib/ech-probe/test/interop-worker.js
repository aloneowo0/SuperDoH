import { probeEch } from '../index.js';

// Local test harness only, never deploy: loopback is the OpenSSL test server.
export default {
  async fetch(request) {
    const { port, rootPem, verifyCertificate, serverName = 'example.test', defaultRoots = false } = await request.json();
    try {
      const result = await probeEch({ hostname: '127.0.0.1', port, serverName,
        ...(verifyCertificate === undefined ? {} : { verifyCertificate }),
        ...(!defaultRoots && verifyCertificate === true ? { caCertificates: [rootPem] } : {}),
        timeoutMs: 10000,
      });
      return Response.json({ authenticated: result.authenticated, handshakeComplete: result.handshakeComplete,
        configCount: result.configs.length, bytes: result.bytes.length, elapsedMs: result.elapsedMs,
        publicNames: result.configs.map(config => config.publicName),
      });
    } catch (error) {
      return Response.json({ code: error.code, message: error.message, cause: error.cause?.message }, { status: 502 });
    }
  },
};
