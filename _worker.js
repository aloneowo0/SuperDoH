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
import { remapResponse, probeOwner, isMetaDomain, filterReachableMeta, resolveMetaFromMap } from './special-domain.js';
import { dnsResponse, buildDNS, servfail, buildQueryFromURL, buildQueryWireId, parseQueryMeta, parseQueryMetaFromURL, resolveDNSWireGoogle, extractIPBytes } from './dns-lib.js';

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

      // Parse query metadata from URL (GET) or body (POST)
      const url = new URL(request.url);
      let qMeta = parseQueryMetaFromURL(url);
      if (request.method === 'POST') {
        const rawBody = await request.clone().arrayBuffer();
        qMeta = parseQueryMeta(rawBody);
        body = rawBody;
      }

      const clientCountry = request.cf && request.cf.country || '';
      const regionCfg = REGION_CONFIG && REGION_CONFIG[clientCountry];
      const regionActive = !!(regionCfg && regionCfg.preferred);
      const activePref = regionCfg ? regionCfg.preferred : '';
      const echActive = !!(regionCfg && regionCfg.ech);
      const preferredCft = regionCfg ? (regionCfg.preferredCft || '') : '';
      const preferredVrc = regionCfg ? (regionCfg.preferredVrc || '') : '';

      if (qMeta) {
        const remapDomains = regionCfg ? regionCfg.remap.map(d => d.toLowerCase()) : [];
        const isRemap = regionActive && remapDomains.some(d => qMeta.name === d || qMeta.name.endsWith('.' + d));
        const isMeta = isMetaDomain(qMeta.name);

        if (isRemap || isMeta) {
          body = body || buildQueryWireId(qMeta.name, qMeta.type, qMeta.id);
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
        if (qMeta.type === 65 && isMeta) {
          const injected = await injectECH(body, qMeta.name, 'META', null);
          if (injected) {
            const bytes = injected instanceof Response ? await injected.arrayBuffer() : injected;
            if (bytes) return dnsResponse(bytes);
          }
        }
        if (isMeta && (qMeta.type === 1 || qMeta.type === 28)) {
          // CN region: suppress AAAA to avoid IPv6 Happy Eyeballs adding parallel connections
          if (qMeta.type === 28 && regionActive) {
            return dnsResponse(buildDNS(qMeta.id, qMeta.name, qMeta.type, [], 300));
          }
          // Static map lookup for A records — no upstream dependency, instant
          if (qMeta.type === 1) {
            const staticIPs = resolveMetaFromMap(qMeta.name);
            if (staticIPs && staticIPs.length > 0) {
              return dnsResponse(buildDNS(qMeta.id, qMeta.name, qMeta.type, staticIPs, 600));
            }
          }
          // Fallback: Google DoH + reachability filter
          const buf = await resolveDNSWireGoogle(body);
          if (buf) {
            const ips = extractIPBytes(buf, qMeta.type);
            if (ips && ips.length > 0) {
              const filtered = regionActive ? filterReachableMeta(ips) : ips;
              if (filtered.length > 0) return dnsResponse(buildDNS(qMeta.id, qMeta.name, qMeta.type, filtered, 300));
            }
          }
          return dnsResponse(buildDNS(qMeta.id, qMeta.name, qMeta.type, [], 60));
        }
      }

      const acceptHeader = request.headers.get('Accept') || '';
      if (acceptHeader.includes('application/dns-json')) {
        return await rfc8484Passthrough(route, request);
      }

      if (!body) {
        if (request.method === 'GET') {
          body = buildQueryFromURL(url);
          if (!body) return jsonError('missing_name_or_type');
        } else {
          body = await request.clone().arrayBuffer();
        }
      }
      const clientIP = request.headers.get('CF-Connecting-IP');
      const queryMeta = qMeta || parseQueryMeta(body);

      if (route.provider === MIX_PROVIDER) {
        return await concurrentAll(body, clientIP, queryMeta, echActive, activePref, preferredCft, preferredVrc);
      }
      return await singleUpstream(route.provider, body, clientIP, queryMeta, echActive);
    } catch (_) {
      return body ? dnsResponse(servfail(body)) : jsonError('internal_error', 500);
    }
  },
};

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
