/**
 * Workers-DoH v2 — Entry point + orchestration
 *
 * Routes requests and dispatches DNS queries through upstream flows.
 */

import { ECS_PROTECT_MS, HARD_TIMEOUT_MS, MIX_PROVIDER, UPSTREAMS, REGION, REGION_CONFIG } from './config.js';
import { prepareQuery, filterAnswers } from './edns.js';
import { serveHomepage, serveHomepageEn } from './homepage.js';
import { concurrentAll } from './mix.js';
import { fetchCFEch, injectECH } from './ech.js';
import { probeOwner, filterReachableMeta, detectOwner, extractIps, isMetaDomain } from './cdn.js';
import { dnsResponse, servfail, buildDNS, buildQueryFromURL, parseQueryMeta, parseQueryMetaFromURL, extractIPBytes, resolvePreferredIPs } from './dns-lib.js';

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };
const JSON_HEADERS = { 'Content-Type': 'application/json;charset=utf-8' };
const CF_FORCE_DOMAINS = ['twimg.com', 'twitter.com', 'x.com', 't.co'];

function isCFDomain(name) {
  if (!name) return false;
  var n = name.toLowerCase().replace(/\.+$/, '');
  for (var i = 0; i < CF_FORCE_DOMAINS.length; i++) {
    if (n === CF_FORCE_DOMAINS[i] || n.endsWith('.' + CF_FORCE_DOMAINS[i])) return true;
  }
  return false;
}

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

async function preferredAnswer(queryMeta, prefDomain, ttl) {
  const ips = await resolvePreferredIPs(prefDomain, queryMeta.type);
  if (ips && ips.length > 0) {
    return dnsResponse(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, ips, ttl));
  }
  return null;
}

async function twoMixFlow(body, clientIP, queryMeta, regionActive, echActive, activePref, preferredCft, preferredVrc) {
  if (!queryMeta || (queryMeta.type !== 1 && queryMeta.type !== 28)) {
    return await concurrentAll(body, clientIP, queryMeta, echActive, activePref, preferredCft, preferredVrc);
  }

  // Known CF: combine preferred IPs + original domain IPs in parallel
  if (queryMeta._knownCF && regionActive && activePref) {
    const [prefIps, firstResult] = await Promise.all([
      resolvePreferredIPs(activePref, queryMeta.type),
      concurrentAll(body, clientIP, queryMeta, false, '', '', '', { skipPostProcess: true }),
    ]);
    const firstBuf = await firstResult.clone().arrayBuffer();
    const origIps = extractIPBytes(firstBuf, queryMeta.type);

    var seen = new Set();
    var allIps = [];
    for (var i = 0; i < prefIps.length; i++) {
      var key = Array.from(prefIps[i]).join(',');
      if (!seen.has(key)) { seen.add(key); allIps.push(prefIps[i]); }
    }
    for (var i = 0; i < origIps.length; i++) {
      var key = Array.from(origIps[i]).join(',');
      if (!seen.has(key)) { seen.add(key); allIps.push(origIps[i]); }
    }
    if (allIps.length > 0) {
      return dnsResponse(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, allIps, 60));
    }
    return firstResult;
  }

  // MIX 1: classify only — no filter, no post-processing
  const firstResult = await concurrentAll(body, clientIP, queryMeta, false, '', '', '', { skipPostProcess: true });

  if (!regionActive) {
    return firstResult;
  }

  const firstBuf = await firstResult.clone().arrayBuffer();
  const owner = classifyResponse(firstBuf, queryMeta.type);
  if (!owner) return firstResult;

  // MIX 2: optimize based on owner
  if (owner === 'META') {
    const second = await concurrentAll(body, clientIP, queryMeta, false, '', '', '', {
      acceptFilter: function(resp) {
        const ips = extractIPBytes(resp, queryMeta.type);
        const filtered = filterReachableMeta(ips);
        return filtered.length > 0;
      }
    });
    // Fail-open: if second mix failed, fall back to first result
    const secondBuf = await second.clone().arrayBuffer();
    if (secondBuf.byteLength >= 12) {
      const rcode = new DataView(secondBuf).getUint16(2) & 0xF;
        if (rcode === 0) {
        if (queryMeta.type === 1 || queryMeta.type === 28) {
          const allIps = extractIPBytes(secondBuf, queryMeta.type);
          const reachable = filterReachableMeta(allIps);
          if (reachable.length > 0) {
            return dnsResponse(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, reachable, 300));
          }
        }
        if (echActive && queryMeta.type === 65) {
          const injected = await injectECH(secondBuf, queryMeta.name, 'META', null);
          if (injected) {
            const bytes = injected instanceof Response ? await injected.arrayBuffer() : injected;
            if (bytes) return dnsResponse(bytes);
          }
        }
        return second;
      }
    }
    return firstResult;
  }

  if (owner === 'CF') {
    if (!activePref) return firstResult;
    const answer = await preferredAnswer(queryMeta, activePref, 60);
    if (answer) return answer;
    return firstResult;
  }

  if (owner === 'CFT') {
    if (!preferredCft) return firstResult;
    const answer = await preferredAnswer(queryMeta, preferredCft, 60);
    if (answer) return answer;
    return firstResult;
  }

  if (owner === 'VRC') {
    if (!preferredVrc) return firstResult;
    const answer = await preferredAnswer(queryMeta, preferredVrc, 60);
    if (answer) return answer;
    return firstResult;
  }

  return firstResult;
}

function classifyResponse(buffer, type) {
  try {
    if (type !== 1 && type !== 28) return null;
    const ips = extractIps(buffer);
    for (const ip of ips) {
      const owner = detectOwner(ip);
      if (owner) return owner;
    }
  } catch (_) {}
  return null;
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

      // Chrome DoH canary: must return NXDOMAIN, or Chrome disables DoH
      if (queryMeta && queryMeta.name && queryMeta.name.toLowerCase().replace(/\.+$/, '') === 'use-application-dns.net') {
        if (queryMeta.type === 1) {
          var nx = buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, [], 60);
          new DataView(nx).setUint16(2, 0x8183); // NOERROR → NXDOMAIN
          return dnsResponse(nx);
        }
      }

      // CF force domains: mark for twoMixFlow CF shunt (AAAA returns empty)
      if (queryMeta && regionActive && isCFDomain(queryMeta.name) && activePref) {
        if (queryMeta.type === 28) {
          return dnsResponse(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, [], 60));
        }
        queryMeta._knownCF = true;
      }

      if (route.provider === MIX_PROVIDER) {
        return await twoMixFlow(body, clientIP, queryMeta, regionActive, echActive, activePref, preferredCft, preferredVrc);
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
      var owner = null;
      if (isMetaDomain(queryMeta.name)) {
        owner = 'META';
      } else {
        const ownerResult = await probeOwner(queryMeta.name);
        if (ownerResult && ownerResult.owner) owner = ownerResult.owner;
      }
      if (owner) {
        const cfEch = owner === 'CF' ? await fetchCFEch(null, null) : null;
        const injected = await injectECH(finalBody, queryMeta.name, owner, cfEch);
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
