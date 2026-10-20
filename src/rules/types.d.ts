import type { DnsRecord } from '../../lib/dns-wasm/index.js';
export type RecordConfig = Omit<DnsRecord, 'rtype' | 'class' | 'data'> & { type: string | number; class?: number };
type ActionValue =
  | { type: 'answer'; records: RecordConfig[]; rcode?: number }
  | { type: 'setTtl'; ttl: number }
  | { type: 'stop' | 'return' }
  | { type: 'rewriteQuery'; name?: string; queryType?: number | string };
export type Action = ActionValue & { onError?: 'fail' | 'continue' };
export type Condition =
  | { all: Condition[] } | { any: Condition[] } | { not: Condition }
  | { field: 'query.name' | 'original.name'; op: 'exact' | 'suffix' | 'subdomain'; value: string }
  | { field: 'query.type' | 'original.type'; op: 'eq'; value: number | string }
  | { field: 'response.exists'; op: 'eq'; value: boolean }
  | { field: 'response.rcode'; op: 'eq'; value: number };
export interface Rule { when?: Condition; actions: Action[] }
export interface Group { name: string; order: number; rules: Rule[] }

export type DeepReadonly<T> = T extends object ? { readonly [K in keyof T]: DeepReadonly<T[K]> } : T;
export interface ExecutionResult {
  termination: 'completed' | 'stopped' | 'returned';
  /** null means no response; NOERROR/NXDOMAIN with no records still have wire bytes. */
  response: Uint8Array | null;
  originalQuery: DeepReadonly<import('../../lib/dns-wasm/index.js').ParsedMessage>;
  query: import('../../lib/dns-wasm/index.js').DnsMessage;
}

export interface FailureEvent {
  readonly event: 'action_failed' | 'execution_failed' | 'observer_failed';
  readonly level: 'error';
  readonly requestId: string;
  readonly location: Readonly<{ group?: string; rule?: number; action?: number }>;
  readonly actionType?: Action['type'];
  readonly code: string;
  readonly message: string;
  readonly reason?: FailureReason;
  readonly disposition: 'terminated' | 'rolled_back_continue';
  readonly rolledBack: boolean;
}
export interface ExecutionOptions {
  requestId?: string;
  onEvent?: (event: FailureEvent) => void;
}

export interface FailureReason {
  readonly kind: 'Error' | 'TypeError' | 'RangeError';
  readonly message: string;
}
