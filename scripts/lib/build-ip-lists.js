import { compileList, exportSnapshot, restoreSnapshot } from '../../lib/ip-list/index.js';
import { readBody } from '../../src/doh/body.js';

const maxBytes = 262144, maxEntries = 4096, maxStateBytes = 4194304;
/** @param {unknown} raw */
export function sourceDefinitions(raw) {
  if (typeof raw !== 'string' || raw.length > 5000) throw Error('DNS_IP_LIST_SOURCES is required (JSON, at most 5000 characters).');
  const value = JSON.parse(raw);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid IP list sources.');
  const entries = Object.entries(value);
  if (!entries.length || entries.length > 16) throw Error('Invalid IP list source count.');
  return entries.map(([name, source]) => {
    if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(name) || !source || typeof source !== 'object' || Array.isArray(source) || Object.keys(source).sort().join(',') !== 'format,url') throw Error('Invalid IP list source definition.');
    const { url, format } = source;
    if (typeof url !== 'string' || url.length > 2048 || !['text', 'json'].includes(format)) throw Error('Invalid IP list URL or format.');
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) throw Error('IP list sources require HTTPS without credentials or fragments.');
    return { name, url, format };
  });
}
/** @param {string} raw @param {typeof fetch} [fetcher] */
export async function buildSnapshots(raw, fetcher = fetch) {
  const definitions = sourceDefinitions(raw);
  /** @type {Record<string, { snapshot: import('../../lib/ip-list/index.js').CompiledSnapshot, sha256: string, fetchedAt: string }>} */
  const lists = Object.create(null);
  let totalState = 0;
  for (const { name, url, format } of definitions) {
    const signal = AbortSignal.timeout(15000);
    const response = await fetcher(url, { redirect: 'manual', signal, headers: { Accept: format === 'text' ? 'text/plain' : 'application/json' } });
    try {
      if (!response.ok || response.redirected) throw Error('IP list download failed: ' + name);
      const media = response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
      if (media && (format === 'text' ? media !== 'text/plain' : media !== 'application/json' && !(media.startsWith('application/') && media.endsWith('+json')))) throw Error('Invalid IP list media type: ' + name);
      const length = response.headers.get('content-length');
      if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes)) throw Error('IP list body exceeds limit: ' + name);
      const bytes = await readBody(response.body, maxBytes, signal);
      const index = compileList(bytes, format, maxEntries, maxBytes);
      const snapshot = exportSnapshot(index, bytes.byteLength);
      restoreSnapshot(snapshot, maxEntries, maxBytes, maxStateBytes);
      totalState += index.bytes;
      if (totalState > maxStateBytes) throw Error('Total embedded IP list state exceeds limit.');
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
      lists[name] = { snapshot, sha256: Array.from(digest, b => b.toString(16).padStart(2, '0')).join(''), fetchedAt: new Date().toISOString() };
    } finally {
      if (!response.bodyUsed) { try { await response.body?.cancel(); } catch { /* Best-effort cleanup. */ } }
    }
  }
  return lists;
}
