export type ByteInput = ArrayBuffer | ArrayBufferView | readonly number[];
export type EchProbeErrorCode = 'MALFORMED' | 'LIMIT' | 'UNSUPPORTED' | 'TLS_ALERT' |
  'NO_RETRY_CONFIG' | 'DECRYPT' | 'CRYPTO' | 'TRUNCATED' | 'TIMEOUT' | 'ABORTED' | 'IO' | 'CERTIFICATE' | 'HOSTNAME' | 'CERTIFICATE_VERIFY' | 'FINISHED';

export class EchProbeError extends Error {
  readonly code: EchProbeErrorCode;
  constructor(code: EchProbeErrorCode, message: string, options?: ErrorOptions);
}

export interface UnknownEchConfig {
  version: number;
  known: false;
  contents: Uint8Array;
}
export interface KnownEchConfig {
  version: number;
  known: true;
  contents: Uint8Array;
  configId: number;
  kemId: number;
  publicKey: Uint8Array;
  cipherSuites: { kdfId: number; aeadId: number }[];
  maximumNameLength: number;
  publicName: string;
  extensions: { type: number; data: Uint8Array }[];
}
export interface EchConfigList {
  bytes: Uint8Array;
  base64: string;
  configs: (KnownEchConfig | UnknownEchConfig)[];
}
/** Structure only. Does not verify identity, freshness, supported algorithms or ECH acceptance. */
export function parseEchConfigList(input: ByteInput): EchConfigList;
