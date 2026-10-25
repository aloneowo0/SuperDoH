import type { NativeRdataMap } from './native-rdata.js';
export type { NativeRdataMap } from './native-rdata.js';
export type Bytes = ArrayBuffer | ArrayBufferView | readonly number[];
export type ByteData = number[] | Uint8Array;
export interface EdnsOption { code: number; data: ByteData; }
export interface SvcParam { key: number; data: ByteData; }
export interface ServiceBinding { priority: number; target: string; params: SvcParam[]; }
export type NativeRdata = { [K in keyof NativeRdataMap]: { [P in K]: NativeRdataMap[K] } }[keyof NativeRdataMap];
/** Native record variants or explicit lossless opaque bytes. Exactly one key is allowed. */
export type Rdata = NativeRdata | { Raw: ByteData } | { Opt: { options: EdnsOption[] } } | { Svcb: ServiceBinding } | { Https: ServiceBinding };
export interface DnsQuestion { name: string; rtype: number; class: number; }
export interface DnsRecord extends DnsQuestion {
  ttl: number;
  rdata: Rdata;
  /** Presentation format computed by parseMessage. Ignored during encoding. */
  data?: string;
}
export interface DnsMessage {
  id: number;
  /** Full 16-bit wire flags. This is the authoritative editable value. */
  flags: number;
  questions: DnsQuestion[];
  answers: DnsRecord[];
  authority: DnsRecord[];
  additional: DnsRecord[];
}
export interface ParsedMessage extends DnsMessage {
  /** Read-only snapshots; edit flags, not these derived fields. */
  readonly is_response: boolean;
  readonly opcode: number;
  /** Header-only RCODE. Use getRcode for extended EDNS RCODE. */
  readonly rcode: number;
  readonly truncated: boolean;
}
export interface EncodeOptions {
  strip_message_authentication?: boolean;
  /** Clear AD and remove signatures covering exactly these RRsets. */
  invalidate_rrsets?: DnsQuestion[];
}
export interface Edns {
  udp_payload_size: number;
  extended_rcode: number;
  version: number;
  flags: number;
  options: EdnsOption[];
}
export interface Ecs { address: string; source_prefix: number; scope_prefix?: number; }
export interface Ede { code: number; text?: string; }
export interface Validation { valid: true; id: number; is_response: boolean; rcode: number; question_count: number; answer_count: number; }
export interface DnsJsonRecord { name: string; type: number; class: number; TTL: number; data: string; }
export interface DnsJson {
  Status: number; TC: boolean; RD: boolean; RA: boolean; AD: boolean; CD: boolean;
  Question: Array<{ name: string; type: number; class: number }>;
  Answer: DnsJsonRecord[]; Authority: DnsJsonRecord[]; Additional: DnsJsonRecord[];
}
export const FLAGS: Readonly<{ QR: number; AA: number; TC: number; RD: number; RA: number; AD: number; CD: number }>;
export const TYPES: Readonly<{ A: 1; NS: 2; CNAME: 5; SOA: 6; PTR: 12; MX: 15; TXT: 16; AAAA: 28; SRV: 33; DNAME: 39; OPT: 41; DS: 43; RRSIG: 46; NSEC: 47; DNSKEY: 48; NSEC3: 50; TLSA: 52; SVCB: 64; HTTPS: 65; TSIG: 250; ANY: 255; CAA: 257 }>;
export function createMessage(options?: Partial<DnsMessage>): DnsMessage;
export function parseMessage(packet: Bytes): ParsedMessage;
/** @internal Encode and fully parse once, preserving normal encoding validation. */
export function normalizeMessage(message: DnsMessage, options?: EncodeOptions): ParsedMessage;
/** @internal Encode, strip message authentication and match the query. Null means the size limit failed before correspondence checking. */
export function encodeResponse(message: DnsMessage, query: Bytes, maximum: number): Uint8Array | null;
export function encodeMessage(message: DnsMessage, options?: EncodeOptions): Uint8Array;
export function buildQuery(name: string, rtype?: number, id?: number, options?: { flags?: number; class?: number }): Uint8Array;
export function buildResponse(query: Bytes | DnsMessage, options?: Partial<DnsMessage> & { rcode?: number; udp_payload_size?: number }): Uint8Array;
export function decodeRdata(rtype: number, bytes: Bytes): Rdata;
export function encodeRdata(rtype: number, value: Rdata): Uint8Array;
export function encodeEcs(value: Ecs): Uint8Array;
export function decodeEcs(value: Bytes): Required<Ecs>;
export function encodeEde(value: Ede): Uint8Array;
export function decodeEde(value: Bytes): Required<Ede>;
export function encodeSvcParam(key: number, value: unknown): Uint8Array;
export function decodeSvcParam(key: 0, value: Bytes): number[];
export function decodeSvcParam(key: 1, value: Bytes): number[][];
export function decodeSvcParam(key: 2, value: Bytes): null;
export function decodeSvcParam(key: 3, value: Bytes): number;
export function decodeSvcParam(key: 4 | 6, value: Bytes): string[];
export function decodeSvcParam(key: 5, value: Bytes): string;
export function decodeSvcParam(key: number, value: Bytes): unknown;
export function validateMessage(packet: Bytes): Validation;
export function matchResponse(response: Bytes, query: Bytes): Validation;
export function extractIPs(packet: Bytes): Array<{ name: string; rtype: number; address: string; bytes: number[] }>;
export function toDnsJson(packet: Bytes): DnsJson;
export function typeCode(name: string): number;
export function typeName(code: number): string;
export function getEdns(message: DnsMessage): Edns | null;
/** udp_payload_size must be explicit when creating an OPT record. */
export function setEdns<T extends DnsMessage>(message: T, value: Partial<Edns>): T;
export function removeEdns<T extends DnsMessage>(message: T): T;
export function setEdnsOption<T extends DnsMessage>(message: T, code: number, data: Bytes): T;
export function removeEdnsOption<T extends DnsMessage>(message: T, code: number): T;
export function setEcs<T extends DnsMessage>(message: T, value: Ecs): T;
export function getEcs(message: DnsMessage): Required<Ecs> | null;
export function getRcode(message: DnsMessage): number;
export function setRcode<T extends DnsMessage>(message: T, rcode: number, udpPayloadSize?: number): T;
export function getSvcParam(record: DnsRecord, key: number): unknown;
export function setSvcParam<T extends DnsRecord>(record: T, key: number, value: unknown): T;
export function removeSvcParam<T extends DnsRecord>(record: T, key: number): T;
