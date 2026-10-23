import type { ByteInput, EchProbeErrorCode, EchConfigList } from '../config.js';
import type { ProbeOptions, AuthenticatedEchProbeResult, UnauthenticatedEchProbeResult } from '../index.js';
import { EchProbeError, parseEchConfigList, probeEch } from '../index.js';

const input: ByteInput = new Uint8Array([0, 0]);
const parsed: EchConfigList = parseEchConfigList(input);
const options: ProbeOptions & { verifyCertificate: true } = {
  hostname: 'example.com', port: 8443, serverName: 'ech.example.com',
  alpn: ['h2', 'http/1.1'], verifyCertificate: true,
  caCertificates: ['-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----', input],
  timeoutMs: 1000, maxBytes: 4096, signal: new AbortController().signal,
};
const trusted: Promise<AuthenticatedEchProbeResult> = probeEch(options);
const defaultUntrusted: Promise<UnauthenticatedEchProbeResult> = probeEch({ hostname: 'example.com' });
const untrusted: Promise<UnauthenticatedEchProbeResult> = probeEch({ hostname: 'example.com', verifyCertificate: false });
declare const dynamicVerification: boolean;
const dynamicOptions: ProbeOptions = { hostname: 'example.com', verifyCertificate: dynamicVerification };
const dynamicResult: Promise<AuthenticatedEchProbeResult | UnauthenticatedEchProbeResult> = probeEch(dynamicOptions);
// @ts-expect-error hostname is required.
const missingHostname: ProbeOptions = {};
// IP addresses require an explicit DNS serverName at runtime.
const ipOptions: ProbeOptions = { hostname: '192.0.2.1', serverName: 'ech.example.com' };
// @ts-expect-error trust anchors cannot be supplied while authentication is disabled.
const disabledWithCa: ProbeOptions = { hostname: 'example.com', verifyCertificate: false, caCertificates: [input] };
// @ts-expect-error custom trust requires explicitly enabling authentication.
const implicitCa: ProbeOptions = { hostname: 'example.com', caCertificates: [input] };
void implicitCa;
const error: EchProbeError = new EchProbeError('ABORTED' satisfies EchProbeErrorCode, 'cancelled');
void [parsed, missingHostname, ipOptions, disabledWithCa, trusted, defaultUntrusted, untrusted, dynamicOptions, dynamicResult, error, parseEchConfigList as (value: ByteInput) => EchConfigList];

function checkTrusted(value: AuthenticatedEchProbeResult) {
  const flag: true = value.authenticated;
  const complete: true = value.handshakeComplete;
  const target: string = value.target;
  const port: number = value.port;
  const serverName: string = value.serverName;
  // @ts-expect-error An authenticated result cannot be downgraded.
  value.authenticated = false;
  void [flag, complete, target, port, serverName];
}
function checkUntrusted(value: UnauthenticatedEchProbeResult) {
  const flag: false = value.authenticated;
  const complete: true = value.handshakeComplete;
  // @ts-expect-error An experimental probe cannot claim authentication.
  value.authenticated = true;
  void [flag, complete];
}
void [checkTrusted, checkUntrusted];
