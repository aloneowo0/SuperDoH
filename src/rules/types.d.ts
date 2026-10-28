import type { DnsRecord } from '../../lib/dns-wasm/index.js';
export type NameValue = string | { from: 'original.name' | 'query.name' };
export type RecordConfig = Omit<DnsRecord, 'name' | 'rtype' | 'class' | 'data'> & { name: NameValue; type: string | number; class?: number };
export interface CachePolicy { read: boolean; write: boolean; maxTtl: number; }
export type RecordSection = 'answer' | 'authority' | 'additional';
type ActionValue =
  | { type: 'replaceRecords'; where: RecordCondition; section?: RecordSection; records: RecordConfig[] }
  | { type: 'removeRecords'; where: RecordCondition }
  | { type: 'addRecords'; section?: RecordSection; records: RecordConfig[] }
  | { type: 'answer'; records: RecordConfig[]; rcode?: number }
  | { type: 'setTtl'; ttl: number; where?: RecordCondition }
  | { type: 'setRecordName'; name: NameValue; where: RecordCondition }
  | { type: 'stop' | 'return' }
  | { type: 'probeEch'; options: EchProbeConfig }
  | { type: 'loadEch'; config: string }
  | { type: 'queryEch'; name: string; upstream: string; cache?: Partial<CachePolicy> }
  | { type: 'applyEch'; where?: RecordCondition }
  | { type: 'enrichAddresses'; source: string }
  | { type: 'queryUpstream'; upstream: string; cache?: Partial<CachePolicy> }
  | ({ type: 'setCache' } & Partial<CachePolicy>)
  | { type: 'rewriteQuery'; name?: NameValue; queryType?: number | string };
export type Action = ActionValue & { onError?: 'fail' | 'continue' };
type Compare<F, V> = { field: F; op: 'eq' | 'ne'; value: V } | { field: F; op: 'in'; value: V[] };
type Presence<F> = { field: F; op: 'exists'; value: boolean };
type NamePredicate<F> = Compare<F, string> | Presence<F>
  | { field: F; op: 'inList' | 'inListSuffix'; value: string }
  | { field: F; op: 'exact' | 'suffix' | 'subdomain' | 'wildcard' | 'regex'; value: string };
type NumberPredicate<F> = Compare<F, number> | Presence<F>
  | { field: F; op: 'lt' | 'lte' | 'gt' | 'gte'; value: number };
type TypePredicate<F> = Compare<F, number | string> | Presence<F>;
type TextPredicate<F> = Compare<F, string> | Presence<F>;
type IpPredicate<F> = Compare<F, string> | Presence<F> | { field: F; op: 'cidr' | 'inList'; value: string };
type GlobalPredicate =
  | NamePredicate<'query.name' | 'original.name'>
  | TypePredicate<'query.type' | 'original.type'>
  | NumberPredicate<'response.rcode' | 'client.asn' | 'edge.asn' | 'lastAction.rule' | 'lastAction.action'>
  | TextPredicate<'client.country' | 'client.region' | 'client.city' | 'client.colo' | 'edge.country' | 'edge.region' | 'edge.city' | 'edge.colo'>
  | IpPredicate<'client.ip' | 'edge.ip'>
  | TextPredicate<'lastAction.actionType' | 'lastAction.code' | 'lastAction.group'>
  | Compare<'lastAction.success', boolean> | Presence<'lastAction.success'>
  | Compare<'response.exists', boolean> | Presence<'response.exists'>;
type RecordPredicate = NamePredicate<'item.name'> | TypePredicate<'item.type'> | NumberPredicate<'item.ttl'>
  | Compare<'item.section', 'answer' | 'authority' | 'additional'> | Presence<'item.section'>;
export type RecordCondition = { all: RecordCondition[] } | { any: RecordCondition[] } | { not: RecordCondition } | GlobalPredicate | RecordPredicate | NamePredicate<'item.target'> | IpPredicate<'item.ip'>;
export type AddressCondition = { all: AddressCondition[] } | { any: AddressCondition[] } | { not: AddressCondition } | GlobalPredicate | RecordPredicate
  | IpPredicate<'item.ip'> | NumberPredicate<'item.asn'> | TextPredicate<'item.country' | 'item.region' | 'item.city'>;
export type Condition = { all: Condition[] } | { any: Condition[] } | { not: Condition } | GlobalPredicate
  | { collection: 'response.records'; quantifier: 'any' | 'all'; where: RecordCondition }
  | { collection: 'response.addresses'; quantifier: 'any' | 'all'; where: AddressCondition };
export interface Rule { when?: Condition; actions: Action[] }
export interface Group { name: string; order: number; rules: Array<{ when?: import('./conditions.js').Predicate; actions: CompiledAction[] }> }
export type CompiledAction = Action & { selector?: import('./conditions.js').Predicate };

export type DeepReadonly<T> = T extends object ? { readonly [K in keyof T]: DeepReadonly<T[K]> } : T;
export interface ActionResult {
  readonly success: boolean;
  readonly actionType: Action['type'];
  readonly location: Readonly<{ group: string; rule: number; action: number }>;
  readonly code?: string;
}
export interface ExecutionResult {
  readonly lastAction?: ActionResult;
  termination: 'completed' | 'stopped' | 'returned';
  /** All successful executions have a response, including empty DNS answers. */
  response: Uint8Array;
  originalQuery: DeepReadonly<import('../../lib/dns-wasm/index.js').ParsedMessage>;
  query: import('../../lib/dns-wasm/index.js').DnsMessage;
}

export interface FailureEvent {
  readonly event: 'action_failed' | 'execution_failed' | 'observer_failed';
  readonly level: 'error';
  readonly requestId: string;
  readonly location: Readonly<{ group?: string; rule?: number; action?: number; source?: string }>;
  readonly actionType?: Action['type'];
  readonly code: string;
  readonly message: string;
  readonly reason?: FailureReason;
  readonly disposition: 'terminated' | 'rolled_back_continue';
  readonly rolledBack: boolean;
}
export interface NetworkAttributes {
  ip?: string; asn?: number; country?: string; region?: string; city?: string; colo?: string;
}
export interface MatchingContext {
  client?: NetworkAttributes;
  edge?: NetworkAttributes;
  addresses?: Record<string, Pick<NetworkAttributes, 'asn' | 'country' | 'region' | 'city'>>;
}
export interface ExecutionOptions {
  signal?: AbortSignal;
  context?: DeepReadonly<MatchingContext>;
  requestId?: string;
  onEvent?: (event: FailureEvent) => void;
}

export interface FailureReason {
  readonly kind: 'Error' | 'TypeError' | 'RangeError';
  readonly message: string;
}

export type DnsEcsConfig =
  | { mode: 'client'; upstreams: string[]; ipv4Prefix?: number; ipv6Prefix?: number }
  | { mode: 'fixed'; upstreams: string[]; subnet: string };

export type UpstreamConfig = ({ transport: 'https' } & ({ url: string; urlSecret?: never } | { urlSecret: string; url?: never }))
  | { transport: 'tcp'; address: string; port?: number };
export type ResolvedUpstream = { transport: 'https'; url: string } | { transport: 'tcp'; address: string; port: number };

export interface AddressSourceFields {
  ip: string[];
  asn?: string[];
  country?: string[];
  region?: string[];
  city?: string[];
}
export type AddressSourceConfig = ({ url: string; urlSecret?: never } | { urlSecret: string; url?: never }) & {
  ipParam: string;
  params?: Record<string, string>;
  fields: AddressSourceFields;
  /** Explicit reuse cap in seconds; zero (the default) disables shared caching. */
  cacheTtl?: number;
};

export type DomainListConfig = { domains: string[] } | (({ url: string; urlSecret?: never } | { urlSecret: string; url?: never }) & { format: 'text' | 'json'; refreshIntervalMs: number });

export type EchProbeConfig = {
  hostname: string; port?: number; serverName?: string; alpn?: string[]; timeoutMs?: number; maxBytes?: number;
  cacheTtl?: number;
} & (
  | { verifyCertificate: true; caCertificates?: (string | number[])[] }
  | { verifyCertificate?: false; caCertificates?: never }
  | { verifyCertificate: boolean; caCertificates?: never }
);

export type IpListConfig = ({ url: string; urlSecret?: never } | { urlSecret: string; url?: never }) & { format: 'text' | 'json'; cacheTtl?: number };
