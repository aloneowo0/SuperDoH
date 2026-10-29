import { ip, cidr } from './ip.js';
export { ip, cidr } from './ip.js';

export class IpListError extends Error {
  /** @param {'IP_LIST_INVALID' | 'RESOURCE_LIMIT'} [code] */
  constructor(code = 'IP_LIST_INVALID') { super('IP list data is invalid or exceeds its resource limits.'); this.code = code; }
}
/** @param {boolean} valid @param {'IP_LIST_INVALID' | 'RESOURCE_LIMIT'} [code] */
function require(valid, code) { if (!valid) throw new IpListError(code); }
/** @param {number} value */
function positive(value) { return Number.isSafeInteger(value) && value > 0; }
/** @param {string} text @param {import('./index.js').Format} format @param {number} maxEntries @returns {import('./index.js').Index} */
function compileText(text, format, maxEntries) {
  try {
    require(format === 'text' || format === 'json');
    const entries = format === 'json' ? JSON.parse(text) : text.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#'));
    require(Array.isArray(entries) && entries.length > 0);
    require(entries.length <= maxEntries, 'RESOURCE_LIMIT');
    /** @type {Map<number, Array<{ start: bigint, end: bigint }>>} */
    const families = new Map([[32, []], [128, []]]);
    for (const entry of entries) {
      require(typeof entry === 'string');
      const parsed = entry.includes('/') ? cidr(entry) : { ...ip(entry), shift: 0n, network: ip(entry).bits };
      const start = parsed.network << parsed.shift;
      families.get(parsed.family)?.push({ start, end: start + (1n << parsed.shift) - 1n });
    }
    for (const [family, ranges] of families) {
      ranges.sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0);
      /** @type {Array<{ start: bigint, end: bigint }>} */
      const merged = [];
      for (const range of ranges) {
        const last = merged[merged.length - 1];
        if (last && range.start <= last.end + 1n) { if (range.end > last.end) last.end = range.end; }
        else merged.push({ ...range });
      }
      families.set(family, merged);
    }
    return makeIndex(families, entries.length);
  } catch (error) { if (error instanceof IpListError) throw error; throw new IpListError(); }
}
/** @param {Uint8Array} bytes @param {import('./index.js').Format} format @param {number} maxEntries @param {number} maxBytes */
export function compileList(bytes, format, maxEntries, maxBytes) {
  require(positive(maxEntries) && positive(maxBytes));
  require(bytes.byteLength <= maxBytes, 'RESOURCE_LIMIT');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes); }
  catch { throw new IpListError(); }
  return compileText(text, format, maxEntries);
}

/** @type {WeakMap<import('./index.js').Index, Map<number, Array<{ start: bigint, end: bigint }>>>} */
const indexRanges = new WeakMap();
/** @param {Map<number, Array<{ start: bigint, end: bigint }>>} families @param {number} entryCount @returns {import('./index.js').Index} */
function makeIndex(families, entryCount) {
    /** @param {string} key @param {() => void} [spend] */
    function containsKey(key, spend = () => {}) {
      if (!/^(32:[0-9a-f]{1,8}|128:[0-9a-f]{1,32})$/.test(key)) return false;
      const [family, hex] = key.split(':');
      const bits = BigInt('0x' + hex), ranges = families.get(Number(family));
      if (!ranges) return false;
      let low = 0, high = ranges.length - 1;
      while (low <= high) {
        spend();
        const middle = (low + high) >>> 1, range = ranges[middle];
        if (bits < range.start) high = middle - 1;
        else if (bits > range.end) low = middle + 1;
        else return true;
      }
      return false;
    }
    const index = Object.freeze({ entries: entryCount, bytes: 256 + [...families.values()].reduce((n, ranges) => n + ranges.length, 0) * 128, containsKey,
      /** @param {string} address @param {() => void} [spend] */
      contains(address, spend) { return containsKey(ip(address).key, spend); } });
    indexRanges.set(index, families);
    return index;
}
/** @param {import('./index.js').Index} index @param {number} sourceBytes @returns {import('./index.js').CompiledSnapshot} */
export function exportSnapshot(index, sourceBytes) {
  const families = indexRanges.get(index);
  require(!!families && positive(sourceBytes));
  const ranges = [32, 128].map(family => /** @type {NonNullable<typeof families>} */ (families).get(family)?.map(r => [r.start.toString(16), r.end.toString(16)]) ?? []);
  return { version: 1, entries: index.entries, sourceBytes, ranges };
}
/** @param {unknown} raw @param {number} maxEntries @param {number} maxBytes @param {number} maxStateBytes @returns {import('./index.js').Index} */
export function restoreSnapshot(raw, maxEntries, maxBytes, maxStateBytes) {
  require(positive(maxEntries) && positive(maxBytes) && positive(maxStateBytes));
  require(!!raw && typeof raw === 'object' && !Array.isArray(raw));
  const s = /** @type {import('./index.js').CompiledSnapshot} */ (raw);
  require(Object.keys(s).sort().join(',') === 'entries,ranges,sourceBytes,version' && s.version === 1 && positive(s.entries) && positive(s.sourceBytes));
  require(s.entries <= maxEntries && s.sourceBytes <= maxBytes, 'RESOURCE_LIMIT');
  require(Array.isArray(s.ranges) && s.ranges.length === 2);
  const families = new Map(); let count = 0;
  for (const [i, family] of [32, 128].entries()) {
    const ranges = s.ranges[i];
    require(Array.isArray(ranges));
    count += ranges.length;
    require(count <= s.entries && 256 + count * 128 <= maxStateBytes, 'RESOURCE_LIMIT');
    const decoded = []; let previous = -2n;
    for (const pair of ranges) {
      require(Array.isArray(pair) && pair.length === 2 && pair.every(v => typeof v === 'string' && /^(0|[1-9a-f][0-9a-f]*)$/.test(v) && v.length <= family / 4));
      const start = BigInt('0x' + pair[0]), end = BigInt('0x' + pair[1]);
      require(start <= end && start > previous + 1n);
      decoded.push({ start, end }); previous = end;
    }
    families.set(family, decoded);
  }
  require(count > 0);
  return makeIndex(families, s.entries);
}

export { createIpListStore } from './store.js';
