export { ip, cidr } from './ip.js';
export type Format = 'text' | 'json';
export interface Index {
  readonly entries: number;
  readonly bytes: number;
  containsKey(key: string, spend?: () => void): boolean;
  contains(address: string, spend?: () => void): boolean;
}
export interface StoredList { storedAt: number; text: string }
export interface CacheIO {
  onError?(error: unknown): void;
  get(identity: string): Promise<unknown>;
  put(identity: string, data: StoredList, ttl: number): Promise<void>;
}
export interface LoadOptions {
  source: string; format: Format; cacheTtl?: number;
  maxBytes: number; maxEntries: number; maxStates: number; maxStateBytes: number;
  load(): Promise<Uint8Array>;
  cache?: CacheIO; check?: () => void; now?: () => number;
}
export interface Snapshot { readonly index: Index; readonly storedAt: number; readonly via: 'memory' | 'cache' | 'origin' }
export class IpListError extends Error { readonly code: 'IP_LIST_INVALID' | 'RESOURCE_LIMIT'; constructor(code?: 'IP_LIST_INVALID' | 'RESOURCE_LIMIT'); }
export function compileList(bytes: Uint8Array, format: Format, maxEntries: number, maxBytes: number): Index;
export function createIpListStore(): { load(options: LoadOptions): Promise<Snapshot> };

export interface CompiledSnapshot { version: 1; entries: number; sourceBytes: number; ranges: string[][][] }
export function exportSnapshot(index: Index, sourceBytes: number): CompiledSnapshot;
export function restoreSnapshot(raw: unknown, maxEntries: number, maxBytes: number, maxStateBytes: number): Index;
