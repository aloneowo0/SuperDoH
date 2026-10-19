/* tslint:disable */
/* eslint-disable */

export function buildQuery(name: string, rtype: number, id: number): Uint8Array;

export function decodeEcsJson(bytes: Uint8Array): string;

export function decodeEdeJson(bytes: Uint8Array): string;

export function decodeRdataJson(rtype: number, bytes: Uint8Array): string;

export function decodeSvcParamJson(key: number, bytes: Uint8Array): string;

export function encodeEcsJson(json: string): Uint8Array;

export function encodeEdeJson(json: string): Uint8Array;

export function encodeMessageJson(json: string, options: string): Uint8Array;

export function encodeRdataJson(rtype: number, json: string): Uint8Array;

export function encodeSvcParamJson(key: number, json: string): Uint8Array;

export function extractIpsJson(bytes: Uint8Array): string;

export function matchResponseJson(bytes: Uint8Array, query: Uint8Array): string;

export function parseMessageJson(packet: Uint8Array): string;

export function toDnsJson(bytes: Uint8Array): string;

export function typeCode(name: string): number;

export function typeName(code: number): string;

export function validateMessageJson(bytes: Uint8Array): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly buildQuery: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly decodeEcsJson: (a: number, b: number) => [number, number, number, number];
    readonly decodeEdeJson: (a: number, b: number) => [number, number, number, number];
    readonly decodeRdataJson: (a: number, b: number, c: number) => [number, number, number, number];
    readonly decodeSvcParamJson: (a: number, b: number, c: number) => [number, number, number, number];
    readonly encodeEcsJson: (a: number, b: number) => [number, number, number, number];
    readonly encodeEdeJson: (a: number, b: number) => [number, number, number, number];
    readonly encodeMessageJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encodeRdataJson: (a: number, b: number, c: number) => [number, number, number, number];
    readonly encodeSvcParamJson: (a: number, b: number, c: number) => [number, number, number, number];
    readonly extractIpsJson: (a: number, b: number) => [number, number, number, number];
    readonly matchResponseJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly parseMessageJson: (a: number, b: number) => [number, number, number, number];
    readonly toDnsJson: (a: number, b: number) => [number, number, number, number];
    readonly typeCode: (a: number, b: number) => [number, number, number];
    readonly typeName: (a: number) => [number, number];
    readonly validateMessageJson: (a: number, b: number) => [number, number, number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
