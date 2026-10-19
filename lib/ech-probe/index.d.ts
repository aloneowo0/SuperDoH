import type { ByteInput, EchConfigList } from './config.js';
export * from './config.js';

export interface CommonProbeOptions {
  hostname: string;
  /** Default 443; integer in 1..65535. */
  port?: number;
  /** Defaults to DNS hostname; required when connecting to an IP. */
  serverName?: string;
  /** Unique ASCII 0x01..0x7f protocol names, each 1..255 bytes. Default []. */
  alpn?: readonly string[];
  /** Total deadline including certificate checks and handshake writes. Default 8000. */
  timeoutMs?: number;
  /** Total received TLS bytes. Default 65536. */
  maxBytes?: number;
  signal?: AbortSignal;
}
export type ProbeOptions = CommonProbeOptions & (
  | { verifyCertificate?: true; caCertificates?: readonly (string | ByteInput)[] }
  | { verifyCertificate: boolean; caCertificates?: never }
);

export interface EchProbeResult extends EchConfigList {
  target: string;
  port: number;
  serverName: string;
  /** Server handshake verified and client Finished written locally. Not ECH acceptance. */
  handshakeComplete: true;
  /** Coarse elapsed time, not CPU time or caller HTTP round-trip. */
  elapsedMs: number;
  bytesReceived: number;
}
export interface AuthenticatedEchProbeResult extends EchProbeResult {
  authenticated: true;
}
export interface UnauthenticatedEchProbeResult extends EchProbeResult {
  /** Trust chain and hostname validation explicitly disabled. CV and Finished still verified. */
  authenticated: false;
}
export function probeEch(options: ProbeOptions & { verifyCertificate: false }): Promise<UnauthenticatedEchProbeResult>;
export function probeEch(options: ProbeOptions & { verifyCertificate?: true }): Promise<AuthenticatedEchProbeResult>;
export function probeEch(options: ProbeOptions): Promise<AuthenticatedEchProbeResult | UnauthenticatedEchProbeResult>;
