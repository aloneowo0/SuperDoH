/**
 * Workers-DoH v2 — Entry point + orchestration
 *
 * Routes requests, handles special domains, dispatches to upstreams.
 * Imports clean modules for ECH, special-domain, multi-upstream racing.
 */

import { ECS_PROTECT_MS, HARD_TIMEOUT_MS, MIX_PROVIDER, UPSTREAMS, REGION, REGION_CONFIG } from './config.js';
import { prepareQuery, filterAnswers } from './edns.js';
import { serveHomepage, serveHomepageEn } from './homepage.js';
import { concurrentAll } from './mix.js';
import { fetchCFEch, injectECH } from './ech.js';
import { remapResponse, resolvePreferredIPs, probeOwner, isMetaDomain } from './special-domain.js';
import { dnsResponse, buildDNS, servfail } from './dns-utils.js';

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };
const JSON_HEADERS = { 'Content-Type': 'application/json;charset=utf-8' };

// ── Router (inlined) ───────────────────────────────────────────────

let _validProviders = null;
function validProviders() {
  if (!_validProviders) _validProviders = new Set([...Object.keys(UPSTREAMS), MIX_PROVIDER]);
  return _validProviders;
}

function resolveRoute(request) {
  const url = new URL(request.url);
  const { pathname, search } = url;
  // Homepage routes
  if (pathname === '/' || pathname === '/index.html' || pathname === '/en') {
    return { home: true };
  }
  if (pathname === '/health') {
    return { health: true };
  }
  // RFC 8484: bare /dns-query without a provider prefix → mix
  if (pathname === '/dns-query') {
    return { provider: MIX_PROVIDER, queryString: search };
  }
  // /<provider>/dns-query pattern
  const match = pathname.match(/^\/([^/]+)\/dns-query$/);
  if (!match) return { error: 'not_found' };
  const provider = match[1];
  if (!validProviders().has(provider)) return { error: 'unknown_provider' };
  return { provider, queryString: search };
}

// ── Main handler ───────────────────────────────────────────────────

export default {
  async fetch(request) {
    let body = null;
    try {
      const route = resolveRoute(request);
      const upstreamNames = [MIX_PROVIDER, ...Object.keys(UPSTREAMS)];
      if (route.home) {
        return new URL(request.url).pathname === '/en'
          ? serveHomepageEn(request, UPSTREAMS, upstreamNames)
          : serveHomepage(request, UPSTREAMS, upstreamNames);
      }
      if (route.health) return healthResponse(upstreamNames);
      if (route.error) return jsonError(route.error);

      const url = new URL(request.url);
      const qMeta = parseQueryMetaFromURL(url);
      const clientCountry = request.cf && request.cf.country || '';
      const regionCfg = REGION_CONFIG && REGION_CONFIG[clientCountry];
      const regionActive = !!(regionCfg && regionCfg.preferred);
      const activePref = regionCfg ? regionCfg.preferred : '';
      const echActive = !!(regionCfg && regionCfg.ech);

      if (qMeta) {
        const remapDomains = regionCfg ? regionCfg.remap.map(d => d.toLowerCase()) : [];
        const isRemap = regionActive && remapDomains.some(d => qMeta.name === d || qMeta.name.endsWith('.' + d));
        const isMeta = isMetaDomain(qMeta.name);

        if (isRemap || isMeta) {
          body = buildQueryWire(qMeta.name, qMeta.type, qMeta.id);
        }
        if (isRemap) {
          let echRdata = null;
          if (qMeta.type === 65 && echActive) {
            const cfEch = await fetchCFEch(null, null);
            if (cfEch && cfEch.rdata) echRdata = cfEch.rdata;
          }
          const remapped = await remapResponse(body, qMeta.name, qMeta.type, activePref, echRdata);
          if (remapped !== null) return dnsResponse(remapped);
          return dnsResponse(buildDNS(qMeta.id, qMeta.name, qMeta.type, [], 60));
        }
        if (regionActive && qMeta.type === 65 && isMeta) {
          const injected = await injectECH(body, qMeta.name, 'META', null);
          if (injected) {
            const bytes = injected instanceof Response ? await injected.arrayBuffer() : injected;
            if (bytes) return dnsResponse(bytes);
          }
        }
        if (isMeta && (qMeta.type === 1 || qMeta.type === 28)) {
          const ips = await resolvePreferredIPs(qMeta.name, qMeta.type);
          if (ips && ips.length > 0) return dnsResponse(buildDNS(qMeta.id, qMeta.name, qMeta.type, ips, 300));
          return dnsResponse(buildDNS(qMeta.id, qMeta.name, qMeta.type, [], 60));
        }
      }

      const acceptHeader = request.headers.get('Accept') || '';
      if (acceptHeader.includes('application/dns-json')) {
        return await rfc8484Passthrough(route, request);
      }

      if (request.method === 'GET') {
        body = body || buildQueryFromURL(url);
        if (!body) return jsonError('missing_name_or_type');
      } else {
        body = body || await request.clone().arrayBuffer();
      }
      const clientIP = request.headers.get('CF-Connecting-IP');
      const queryMeta = parseQueryMeta(body);

      if (route.provider === MIX_PROVIDER) {
        return await concurrentAll(body, clientIP, queryMeta, echActive, activePref);
      }
      return await singleUpstream(route.provider, body, clientIP, queryMeta, echActive);
    } catch (_) {
      return body ? dnsResponse(servfail(body)) : jsonError('internal_error', 500);
    }
  },
};

// ── DNS query construction ─────────────────────────────────────────

function buildQueryFromURL(url) {
  const dnsParam = url.searchParams.get('dns');
  if (dnsParam) {
    try {
      const b64 = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
      const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      return bin.buffer;
    } catch (_) {}
  }

  const name = url.searchParams.get('name');
  if (!name) return null;
  const typeStr = (url.searchParams.get('type') || 'A').toUpperCase();
  const typeMap = { A: 1, AAAA: 28, TXT: 16, MX: 15, CNAME: 5, NS: 2, SOA: 6, PTR: 12, HTTPS: 65, SVCB: 64 };
  const qtype = typeMap[typeStr] || parseInt(typeStr, 10) || 1;

  const buf = new ArrayBuffer(12);
  const view = new DataView(buf);
  view.setUint16(0, Math.floor(Math.random() * 65536));
  view.setUint16(2, 0x0100);
  view.setUint16(4, 1);
  view.setUint16(6, 0);
  view.setUint16(8, 0);
  view.setUint16(10, 0);

  const labels = name.replace(/\.+$/, '').split('.');
  const nameBytes = [];
  for (const label of labels) {
    if (label.length > 63) return null;
    nameBytes.push(label.length);
    for (let i = 0; i < label.length; i++) nameBytes.push(label.charCodeAt(i));
  }
  nameBytes.push(0);

  const question = new ArrayBuffer(4);
  const qv = new DataView(question);
  qv.setUint16(0, qtype);
  qv.setUint16(2, 1);

  const total = 12 + nameBytes.length + 4;
  const out = new Uint8Array(total);
  out.set(new Uint8Array(buf), 0);
  out.set(nameBytes, 12);
  out.set(new Uint8Array(question), 12 + nameBytes.length);
  return out.buffer;
}

function parseQueryMetaFromURL(url) {
  const dnsParam = url.searchParams.get('dns');
  const name = url.searchParams.get('name');
  if (!dnsParam && !name) return null;
  const typeStr = (url.searchParams.get('type') || 'A').toUpperCase();
  const typeMap = { A: 1, AAAA: 28, TXT: 16, MX: 15, CNAME: 5, NS: 2, SOA: 6, PTR: 12, HTTPS: 65, SVCB: 64 };
  const qtype = typeMap[typeStr] || parseInt(typeStr, 10) || 1;
  const qname = name || 'unknown.';
  return { id: Math.floor(Math.random() * 65536), name: qname.toLowerCase().replace(/\.+$/, ''), type: qtype };
}

function buildQueryWire(qname, qtype, id) {
  const labels = qname.replace(/\.+$/, '').split('.');
  const nameBytes = [];
  for (const label of labels) {
    if (label.length > 63) break;
    nameBytes.push(label.length);
    for (let i = 0; i < label.length; i++) nameBytes.push(label.charCodeAt(i));
  }
  nameBytes.push(0);
  const total = 12 + nameBytes.length + 4;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  view.setUint16(0, id);
  view.setUint16(2, 0x0100);
  view.setUint16(4, 1);
  view.setUint16(6, 0);
  view.setUint16(8, 0);
  view.setUint16(10, 0);
  let off = 12;
  out.set(nameBytes, off); off += nameBytes.length;
  view.setUint16(off, qtype); off += 2;
  view.setUint16(off, 1);
  return out.buffer;
}

function parseQueryMeta(body) {
  try {
    const bytes = body instanceof ArrayBuffer ? new Uint8Array(body) : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    if (bytes.length < 12) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const id = view.getUint16(0);
    let offset = 12;
    const labels = [];
    for (let jumps = 0; jumps < 128; jumps++) {
      if (offset >= bytes.length) return null;
      const len = bytes[offset];
      if ((len & 0xC0) === 0xC0) { offset += 2; break; }
      if (len === 0) { offset++; break; }
      offset++;
      labels.push(new TextDecoder().decode(bytes.subarray(offset, offset + len)));
      offset += len;
    }
    const qType = view.getUint16(offset);
    return { id, name: labels.join('.').toLowerCase(), type: qType };
  } catch (_) {
    return null;
  }
}

// ── RFC 8484 JSON passthrough ──────────────────────────────────────

async function rfc8484Passthrough(route, request) {
  let target = route.provider === MIX_PROVIDER
    ? Object.values(UPSTREAMS)[0]
    : UPSTREAMS[route.provider];
  if (!target) return jsonError('unknown_provider');

  const query = route.queryString;
  const upstreamReq = new Request(target.url + query, {
    method: request.method,
    headers: {
      'Accept': 'application/dns-json',
      ...(request.method !== 'GET' ? { 'Content-Type': request.headers.get('Content-Type') || 'application/dns-json' } : {}),
    },
    body: request.method !== 'GET' ? await request.clone().arrayBuffer() : null,
  });

  try {
    const response = await fetch(upstreamReq);
    const body = await response.arrayBuffer();
    return new Response(body, {
      status: response.status,
      headers: { 'Content-Type': 'application/dns-json' },
    });
  } catch (_) {
    return jsonError('upstream_error', 502);
  }
}

// ── Single upstream query ──────────────────────────────────────────

/** @param {string} echActive — whether ECH injection is enabled for this region */
async function singleUpstream(provider, body, clientIP, queryMeta, echActive) {
  const upstream = UPSTREAMS[provider];
  if (!upstream) return dnsResponse(servfail(body));
  const queryBody = prepareQuery(body, clientIP);
  const started = Date.now();
  try {
    const response = await fetch(upstream.url, {
      method: 'POST',
      headers: DNS_HEADERS,
      body: queryBody,
    });
    const responseBody = await response.arrayBuffer();
    const elapsed = Date.now() - started;
    let finalBody = responseBody;
    if (echActive && queryMeta && queryMeta.type === 65) {
      const ownerResult = await probeOwner(queryMeta.name);
      if (ownerResult && ownerResult.owner) {
        const cfEch = await fetchCFEch(null, null);
        const injected = await injectECH(finalBody, queryMeta.name, ownerResult.owner, cfEch);
        if (injected) {
          const injectedBytes = injected instanceof Response ? await injected.arrayBuffer() : injected;
          if (injectedBytes) finalBody = injectedBytes;
        }
      }
    }
    const fResult = filterAnswers(finalBody);
    if (response.status === 200 && fResult !== false && fResult?.passed !== false) return dnsResponse(finalBody, elapsed);
    return dnsResponse(servfail(body, 17, 'Filtered'), elapsed);
  } catch (_) {}
  return dnsResponse(servfail(body));
}

// ── Response helpers ───────────────────────────────────────────────

function jsonError(error, status = 400) {
  return new Response(JSON.stringify({ error }), { status, headers: JSON_HEADERS });
}

function healthResponse(upstreamNames) {
  return new Response(JSON.stringify({
    status: 'ok',
    upstreams: upstreamNames,
    hardTimeoutMs: HARD_TIMEOUT_MS,
    ecsProtectMs: ECS_PROTECT_MS,
    region: REGION || null,
    regionConfig: REGION_CONFIG || null,
    echEnabled: REGION_CONFIG ? Object.values(REGION_CONFIG).some(c => c.ech) : false,
  }), { headers: JSON_HEADERS });
}
