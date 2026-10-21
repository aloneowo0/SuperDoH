import type { DnsRecord } from '../../lib/dns-wasm/index.js';
export type RecordConfig = Omit<DnsRecord, 'rtype' | 'class' | 'data'> & { type: string | number; class?: number };
type ActionValue =
  | { type: 'custom'; name: string; params?: unknown }
  | { type: 'answer'; records: RecordConfig[]; rcode?: number }
  | { type: 'setTtl'; ttl: number }
  | { type: 'stop' | 'return' }
  | { type: 'queryUpstream'; group?: string }
  | { type: 'rewriteQuery'; name?: string; queryType?: number | string };
export type Action = ActionValue & { onError?: 'fail' | 'continue' };
type Compare<F, V> = { field: F; op: 'eq' | 'ne'; value: V } | { field: F; op: 'in'; value: V[] };
type Presence<F> = { field: F; op: 'exists'; value: boolean };
type NamePredicate<F> = Compare<F, string> | Presence<F>
  | { field: F; op: 'exact' | 'suffix' | 'subdomain' | 'wildcard' | 'regex'; value: string };
type NumberPredicate<F> = Compare<F, number> | Presence<F>
  | { field: F; op: 'lt' | 'lte' | 'gt' | 'gte'; value: number };
type TypePredicate<F> = Compare<F, number | string> | Presence<F>;
type TextPredicate<F> = Compare<F, string> | Presence<F>;
type IpPredicate<F> = Compare<F, string> | Presence<F> | { field: F; op: 'cidr'; value: string };
type GlobalPredicate =
  | NamePredicate<'query.name' | 'original.name'>
  | TypePredicate<'query.type' | 'original.type'>
  | NumberPredicate<'response.rcode' | 'client.asn' | 'edge.asn'>
  | TextPredicate<'client.country' | 'client.region' | 'client.city' | 'client.colo' | 'edge.country' | 'edge.region' | 'edge.city' | 'edge.colo'>
  | IpPredicate<'client.ip' | 'edge.ip'>
  | Compare<'response.exists', boolean> | Presence<'response.exists'>;
type RecordPredicate = NamePredicate<'item.name'> | TypePredicate<'item.type'> | NumberPredicate<'item.ttl'>
  | Compare<'item.section', 'answer' | 'authority' | 'additional'> | Presence<'item.section'>;
export type CustomCondition = { custom: { name: string; params?: unknown } };
export type RecordCondition = CustomCondition | { all: RecordCondition[] } | { any: RecordCondition[] } | { not: RecordCondition } | GlobalPredicate | RecordPredicate | NamePredicate<'item.target'>;
export type AddressCondition = CustomCondition | { all: AddressCondition[] } | { any: AddressCondition[] } | { not: AddressCondition } | GlobalPredicate | RecordPredicate
  | IpPredicate<'item.ip'> | NumberPredicate<'item.asn'> | TextPredicate<'item.country' | 'item.region' | 'item.city'>;
export type Condition = CustomCondition | { all: Condition[] } | { any: Condition[] } | { not: Condition } | GlobalPredicate
  | { collection: 'response.records'; quantifier: 'any' | 'all'; where: RecordCondition }
  | { collection: 'response.addresses'; quantifier: 'any' | 'all'; where: AddressCondition };
export interface Rule { when?: Condition; actions: Action[] }
export interface Group { name: string; order: number; rules: Array<{ when?: import('./conditions.js').Predicate; actions: Array<Action & { run?: ActionHandler }> }> }

export type DeepReadonly<T> = T extends object ? { readonly [K in keyof T]: DeepReadonly<T[K]> } : T;
export interface ExecutionResult {
  termination: 'completed' | 'stopped' | 'returned';
  /** null means no response; NOERROR/NXDOMAIN with no records still have wire bytes. */
  response: Uint8Array | null;
  originalQuery: DeepReadonly<import('../../lib/dns-wasm/index.js').ParsedMessage>;
  query: import('../../lib/dns-wasm/index.js').DnsMessage;
}

export interface FailureEvent {
  readonly event: 'action_failed' | 'execution_failed' | 'observer_failed' | 'upstream_failed';
  readonly level: 'error';
  readonly requestId: string;
  readonly location: Readonly<{ group?: string; rule?: number; action?: number }>;
  readonly actionType?: Action['type'];
  readonly code: string;
  readonly message: string;
  readonly reason?: FailureReason;
  readonly disposition: 'terminated' | 'rolled_back_continue' | 'fallback' | 'exhausted';
  readonly upstream?: Readonly<{ groupIndex: number; memberIndex: number }>;
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
  extensions?: ExtensionRegistry;
  context?: DeepReadonly<MatchingContext>;
  requestId?: string;
  onEvent?: (event: FailureEvent) => void;
}

export interface FailureReason {
  readonly kind: 'Error' | 'TypeError' | 'RangeError';
  readonly message: string;
}

export interface ExtensionDefinition<C, R> {
  readonly bind: (params: unknown) => (context: C) => R | Promise<R>;
}
export interface ExtensionRegistry {
  readonly conditions?: Readonly<Record<string, ExtensionDefinition<ConditionContext, boolean>>>;
  readonly actions?: Readonly<Record<string, ExtensionDefinition<ActionContext, void>>>;
}
export interface ActionContext {
  query: import('../../lib/dns-wasm/index.js').DnsMessage;
  response: import('../../lib/dns-wasm/index.js').DnsMessage | null;
  readonly originalQuery: DeepReadonly<import('../../lib/dns-wasm/index.js').ParsedMessage>;
  readonly context: DeepReadonly<MatchingContext>;
  readonly signal: AbortSignal;
}
export type ConditionContext = Omit<DeepReadonly<ActionContext>, 'signal'> & {
  readonly signal: AbortSignal;
  readonly item?: Readonly<Record<string, string | number | boolean>>;
};
export type ConditionHandler = (context: ConditionContext) => boolean | Promise<boolean>;
export type ActionHandler = (context: ActionContext) => void | Promise<void>;

export type UpstreamConfig = { url: string; urlSecret?: never } | { urlSecret: string; url?: never };
export interface UpstreamGroupConfig { members: string[]; accept?: Condition }
