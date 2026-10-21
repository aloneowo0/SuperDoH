import { connect } from 'cloudflare:sockets';
import { probeWithConnect } from './internal/probe.js';
export { EchProbeError, parseEchConfigList } from './config.js';
// Structural PEM/DER validation shared by callers that preflight configuration.
export { prepareTrustAnchors as parseTrustAnchors } from './internal/certificate.js';

/** TLS 1.3 ECH retry probe. Certificate verification defaults to enabled. */
export function probeEch(options) {
  return probeWithConnect(connect, options);
}
