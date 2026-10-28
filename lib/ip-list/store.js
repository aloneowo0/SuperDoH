import { compileList, IpListError } from './index.js';

/** Only immutable successful data is shared, never request-scoped I/O. */
export function createIpListStore() {
  /** @type {Map<string, { index: import('./index.js').Index, storedAt: number, expiresAt: number, size: number }>} */
  const memory = new Map();
  return {
    /** @param {import('./index.js').LoadOptions} o @returns {Promise<import('./index.js').Snapshot>} */
    async load(o) {
      const { source, format, maxBytes, maxEntries, maxStates, maxStateBytes, cache } = o;
      const ttl = o.cacheTtl === undefined ? 3600 : o.cacheTtl, now = o.now ?? Date.now, check = o.check ?? (() => {});
      if (typeof source !== 'string' || !source.length || source.length > 2048 || !['text','json'].includes(format) || !Number.isSafeInteger(ttl) || ttl < 0 || ttl > 86400 || ![maxBytes,maxEntries,maxStates,maxStateBytes].every(v => Number.isSafeInteger(v) && v > 0)) throw new IpListError();
      const key = JSON.stringify(['ip-list-v1', source, format, ttl, maxBytes, maxEntries, maxStates, maxStateBytes]);
      check();
      /** @param {number} timestamp */
      const fresh = timestamp => Number.isSafeInteger(timestamp) && timestamp >= 0 && timestamp <= now() && now() - timestamp < ttl * 1000;
      let total = 0;
      for (const [name, value] of memory) {
        if (value.expiresAt <= now() || value.storedAt > now()) memory.delete(name);
        else total += value.size;
      }
      /** @param {number} extra @param {number} count */
      function trim(extra, count) {
        while (memory.size + count > Math.min(64, maxStates) || total + extra > maxStateBytes) {
          const name = memory.keys().next().value;
          if (name === undefined) break;
          total -= /** @type {NonNullable<ReturnType<typeof memory.get>>} */ (memory.get(name)).size;
          memory.delete(name);
        }
      }
      trim(0, 0);
      const hit = ttl ? memory.get(key) : undefined;
      if (hit && fresh(hit.storedAt)) {
        memory.delete(key); memory.set(key, hit);
        return Object.freeze({ index: hit.index, storedAt: hit.storedAt, via: 'memory' });
      }
      /** @type {string | undefined} */ let text;
      let storedAt = 0;
      /** @type {'cache' | 'origin'} */ let via = 'origin';
      /** @type {import('./index.js').Index | undefined} */ let index;
      if (ttl && cache) {
        try {
          const data = await cache.get(key);
          check();
          if (data && typeof data === 'object' && Object.keys(data).length === 2 && 'storedAt' in data && 'text' in data && typeof data.storedAt === 'number' && typeof data.text === 'string' && fresh(data.storedAt)) {
            if (data.text.length > maxBytes) throw new IpListError('RESOURCE_LIMIT');
            index = compileList(new TextEncoder().encode(data.text), format, maxEntries, maxBytes);
            text = data.text; storedAt = data.storedAt; via = 'cache';
          }
        } catch (error) {
          if (error instanceof IpListError && error.code === 'RESOURCE_LIMIT') throw error;
          cache.onError?.(error); check(); /* Corrupt/unavailable cache is a miss, not an empty list. */
        }
      }
      if (!index) {
        const bytes = await o.load();
        check();
        index = compileList(bytes, format, maxEntries, maxBytes);
        text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
        storedAt = now();
      }
      check();
      const size = index.bytes + key.length * 2 + 256;
      if (size > maxStateBytes) throw new IpListError('RESOURCE_LIMIT');
      if (ttl) {
        total = 0; for (const value of memory.values()) total += value.size;
        const previous = memory.get(key);
        if (!previous || previous.storedAt <= storedAt) {
          if (previous) total -= previous.size;
          memory.delete(key); trim(size, 1);
          memory.set(key, { index, storedAt, expiresAt: storedAt + ttl * 1000, size });
        }
        if (cache && via === 'origin') {
          try { await cache.put(key, { storedAt, text: /** @type {string} */ (text) }, ttl); }
          catch (error) { cache.onError?.(error); check(); }
        }
      }
      check();
      return Object.freeze({ index, storedAt, via });
    },
  };
}
