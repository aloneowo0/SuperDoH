/**
 * Workers-DoH v2 — Entry point + orchestration
 *
 * Routes requests and dispatches DNS queries through upstream flows.
 */

import { ECS_PROTECT_MS, HARD_TIMEOUT_MS, META_HARD_TIMEOUT_MS, META_COLLECT_WINDOW_MS, META_MAX_IPS, MIX_PROVIDER, UPSTREAMS, REGION, REGION_CONFIG } from './config.js';
import { prepareQuery, filterAnswers } from './edns.js';
import { serveHomepage, serveHomepageEn } from './homepage.js';
import { concurrentAll, queryUpstream } from './mix.js';
import { fetchCFEch, injectECH } from './ech.js';
import { probeOwner, filterReachableMeta, detectOwner, extractIps, isMetaDomain } from './cdn.js';
import { dnsResponse, servfail, buildDNS, buildQueryFromURL, parseQueryMeta, parseQueryMetaFromURL, extractIPBytes, resolvePreferredIPs, resolveDNSWireAll } from './dns-lib.js';
import { resolveMetaFromMap } from './meta-route.js';

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
  if (pathname === '/' || pathname === '/index.html' || pathname === '/en') {
    return { home: true };
  }
  if (pathname === '/health') {
    return { health: true };
  }
  if (pathname === '/dns-query') {
    return { provider: MIX_PROVIDER, queryString: search };
  }
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

// ── Preferred answer helper ────────────────────────────────────────

async function preferredAnswer(queryMeta, prefDomain, ttl, expectedOwner) {
  const ips = await resolvePreferredIPs(prefDomain, queryMeta.type, expectedOwner);
  if (ips && ips.length > 0) {
    return dnsResponse(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, ips, ttl));
  }
  return null;
}

// ── classifyResponse ───────────────────────────────────────────────

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

// ── Meta resolve: 800ms + 50ms collect ─────────────────────────────
//
// Tagged-promise + mask pattern:
//   Each upstream promise is wrapped at creation time to resolve as
//   { idx, result }.  A done[] mask tracks which indices have already
//   been consumed, so Promise.race always competes only on unresolved
//   promises.  No splice → no index-shifting bugs.

async function metaResolve(body, clientIP, queryMeta, echActive) {
  void echActive; // Meta type 65 ECH handled by postProcessBody()
  // Meta AAAA: no IPv6 reachability data, return NODATA immediately
  if (queryMeta.type === 28) {
    return dnsResponse(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, [], 60));
  }

  var startedAt = Date.now();
  var hardDeadline = startedAt + META_HARD_TIMEOUT_MS;
  var candidates = [];

  // Static route / cache hit — only use IPs matching query type
  var allRouteIPs = resolveMetaFromMap(queryMeta.name);
  if (allRouteIPs && allRouteIPs.length > 0) {
    var expectedLen = queryMeta.type === 1 ? 4 : queryMeta.type === 28 ? 16 : -1;
    for (var ri = 0; ri < allRouteIPs.length; ri++) {
      if (allRouteIPs[ri].length === expectedLen) candidates.push(allRouteIPs[ri]);
    }
  }

  // Prepare query with EDNS/ECS (same semantics as main MIX)
  var preparedBody = prepareQuery(body, clientIP);

  // Fire all upstreams — each tagged with its index
  var controllers = [];
  var tagged = [];
  var done = [];
  var upstreamKeys = Object.keys(UPSTREAMS);
  for (var i = 0; i < upstreamKeys.length; i++) {
    var ctrl = new AbortController();
    controllers.push(ctrl);
    done.push(false);
    (function (idx) {
      tagged.push(
        queryUpstream(UPSTREAMS[upstreamKeys[idx]].url, preparedBody, startedAt, controllers[idx].signal)
          .then(function (r) { return { idx: idx, result: r }; })
      );
    })(i);
  }

  function abortAll() {
    for (var i = 0; i < controllers.length; i++) {
      try { controllers[i].abort(); } catch (_) {}
    }
  }

  // Build a race list from unresolved tagged promises + timeout promise
  function raceList(deadline) {
    var list = [];
    for (var i = 0; i < tagged.length; i++) {
      if (!done[i]) list.push(tagged[i]);
    }
    var remaining = deadline - Date.now();
    if (remaining <= 0) return [];
    list.push(new Promise(function (resolve) { setTimeout(function () { resolve(null); }, remaining); }));
    return list;
  }

  // ── Phase 1: wait for first valid response within 800ms ──────────

  var firstValid = null;
  while (Date.now() < hardDeadline) {
    var racers = raceList(hardDeadline);
    if (racers.length <= 1) break; // nothing left except the timeout (or nothing at all)

    var winner = await Promise.race(racers);
    if (!winner) break; // timeout
    done[winner.idx] = true;

    if (winner.result.valid) {
      try {
        var rawIps = extractIPBytes(winner.result.response, queryMeta.type);
        var reachable = filterReachableMeta(rawIps, META_MAX_IPS);
        if (reachable.length > 0) {
          firstValid = winner.result;
          for (var j = 0; j < reachable.length; j++) candidates.push(reachable[j]);
          break;
        }
      } catch (_) {}
    }
  }

  // ── Phase 2: 50ms collect window after first valid ───────────────

  if (firstValid) {
    var collectDeadline = Math.min(Date.now() + META_COLLECT_WINDOW_MS, hardDeadline);
    while (Date.now() < collectDeadline) {
      var racers = raceList(collectDeadline);
      if (racers.length <= 1) break;

      var winner = await Promise.race(racers);
      if (!winner) break;
      done[winner.idx] = true;

      if (winner.result.valid) {
        try {
          var ips = extractIPBytes(winner.result.response, queryMeta.type);
          for (var j = 0; j < ips.length; j++) candidates.push(ips[j]);
        } catch (_) {}
      }
    }
  }

  abortAll();

  if (candidates.length === 0) {
    return dnsResponse(servfail(body, 22, 'No reachable Meta IP'));
  }

  // ── Dedup + Meta CIDR + max 4 ────────────────────────────────────

  var seen = new Set();
  var filtered = [];
  for (var i = 0; i < candidates.length; i++) {
    var key = Array.from(candidates[i]).join(',');
    if (!seen.has(key)) {
      seen.add(key);
      if (filterReachableMeta([candidates[i]], 1).length > 0) {
        filtered.push(candidates[i]);
      }
      if (filtered.length >= META_MAX_IPS) break;
    }
  }

  if (filtered.length === 0) {
    return dnsResponse(servfail(body, 22, 'No reachable Meta IP'));
  }

  // Meta type 65 ECH: handled by postProcessBody() in mix.js (twoMixFlow
  // routes non-A/AAAA to concurrentAll before metaResolve is reached).
  // Every IP must match expected RDATA length for the query type.
  var rdataLen = queryMeta.type === 1 ? 4 : queryMeta.type === 28 ? 16 : null;
  if (rdataLen) {
    var validFiltered = [];
    for (var fi = 0; fi < filtered.length; fi++) {
      if (filtered[fi].length === rdataLen) validFiltered.push(filtered[fi]);
    }
    filtered = validFiltered;
    if (filtered.length === 0) {
      return dnsResponse(servfail(body, 22, 'No reachable Meta IP'));
    }
  }

  return dnsResponse(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, filtered, 300));
}

// ── twoMixFlow ─────────────────────────────────────────────────────

async function twoMixFlow(body, clientIP, queryMeta, regionActive, echActive, activePref, preferredCft, preferredVrc) {
  // Non-A/AAAA → concurrentAll with post-processing (ECH)
  if (!queryMeta || (queryMeta.type !== 1 && queryMeta.type !== 28)) {
    return await concurrentAll(body, clientIP, queryMeta, echActive, activePref, preferredCft, preferredVrc);
  }

  // MIX 1: classify — only used for owner detection
  const firstResult = await concurrentAll(body, clientIP, queryMeta, false, '', '', '', { skipPostProcess: true });

  if (!regionActive) {
    return firstResult;
  }

  const firstBuf = await firstResult.clone().arrayBuffer();

  // Domain rules take priority over IP classification
  var owner;
  if (isCFDomain(queryMeta.name)) {
    owner = 'CF';
  } else if (isMetaDomain(queryMeta.name)) {
    owner = 'META';
  } else {
    owner = classifyResponse(firstBuf, queryMeta.type);
  }

  if (!owner) return firstResult;

  // MIX 2: optimize based on owner
  if (owner === 'META') {
    return await metaResolve(body, clientIP, queryMeta, echActive);
  }

  if (owner === 'CF') {
    if (!activePref) return firstResult;
    var answer = await preferredAnswer(queryMeta, activePref, 60, 'CF');
    if (answer) return answer;
    return firstResult;
  }

  if (owner === 'CFT') {
    if (!preferredCft) return firstResult;
    var answer = await preferredAnswer(queryMeta, preferredCft, 60, 'CFT');
    if (answer) return answer;
    return firstResult;
  }

  if (owner === 'VRC') {
    if (!preferredVrc) return firstResult;
    var answer = await preferredAnswer(queryMeta, preferredVrc, 60, 'VRC');
    if (answer) return answer;
    return firstResult;
  }

  return firstResult;
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
      let qMeta = parseQueryMetaFromURL(url);
      if (request.method === 'POST') {
        const rawBody = await request.clone().arrayBuffer();
        qMeta = parseQueryMeta(rawBody);
        body = rawBody;
      }

      const clientCountry = request.cf && request.cf.country || '';
      const regionCfg = REGION_CONFIG && REGION_CONFIG[clientCountry];
      const regionActive = !!(regionCfg && (regionCfg.preferred || regionCfg.preferredCft || regionCfg.preferredVrc || regionCfg.ech || (regionCfg.remap && regionCfg.remap.length)));
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
      if (queryMeta && queryMeta.name) {
        queryMeta.forcedOwner = isCFDomain(queryMeta.name) ? 'CF' : isMetaDomain(queryMeta.name) ? 'META' : null;
      }

      // Chrome DoH canary
      if (queryMeta && queryMeta.name && queryMeta.name.toLowerCase().replace(/\.+$/, '') === 'use-application-dns.net') {
        if (queryMeta.type === 1) {
          var nx = buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, [], 60);
          new DataView(nx).setUint16(2, 0x8183);
          return dnsResponse(nx);
        }
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

async function singleUpstream(provider, body, clientIP, queryMeta, echActive) {
  const upstream = UPSTREAMS[provider];
  if (!upstream) return dnsResponse(servfail(body));
  const queryBody = prepareQuery(body, clientIP);
  const started = Date.now();
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(function() { try { ctrl.abort(); } catch (_) {} }, HARD_TIMEOUT_MS);
    const response = await fetch(upstream.url, {
      method: 'POST',
      headers: DNS_HEADERS,
      body: queryBody,
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    const responseBody = await response.arrayBuffer();
    const elapsed = Date.now() - started;
    let finalBody = responseBody;
    if (echActive && queryMeta && queryMeta.type === 65) {
      var owner = null;
      if (queryMeta.forcedOwner) {
        owner = queryMeta.forcedOwner;
      } else if (isMetaDomain(queryMeta.name)) {
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
