import { upstreamName } from './values.js';
import { within } from './limits.js';

/** @param {import('./limits.js').Limits} limits */
export function createConfigBudget(limits) {
  let bytes = 0, nodes = 0, patterns = 0;
  /** @type {Set<string>} */
  const listReferences = new Set();
  /** @type {Set<string>} */
  const ipListReferences = new Set();
  return {
    ipListReferences,
    /** @param {unknown} name */
    ipList(name) { ipListReferences.add(upstreamName(name)); },
    listReferences,
    /** @param {unknown} name */
    list(name) { listReferences.add(upstreamName(name)); },
    /** @param {unknown} raw */
    parse(raw) {
      const text = typeof raw === 'string' ? raw : JSON.stringify(raw);
      if (typeof text !== 'string') throw new Error();
      within(text.length, limits.maxGroupBytes);
      const size = new TextEncoder().encode(text).byteLength;
      within(size, limits.maxGroupBytes);
      within(bytes += size, limits.maxConfigBytes);
      return JSON.parse(text);
    },
    node() { within(++nodes, limits.maxConditionNodes); },
    /** @param {number} size */
    pattern(size) { within(patterns += size, limits.maxPatternInstructions); },
  };
}
