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
    let intervals = 0;
    for (const [family, ranges] of families) {
      ranges.sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0);
      /** @type {Array<{ start: bigint, end: bigint }>} */
      const merged = [];
      for (const range of ranges) {
        const last = merged[merged.length - 1];
        if (last && range.start <= last.end + 1n) { if (range.end > last.end) last.end = range.end; }
        else merged.push({ ...range });
      }
      intervals += merged.length;
      families.set(family, merged);
    }
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
    return Object.freeze({ entries: entries.length, bytes: 256 + intervals * 128, containsKey,
      /** @param {string} address @param {() => void} [spend] */
      contains(address, spend) { return containsKey(ip(address).key, spend); } });
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

export { createIpListStore } from './store.js';
