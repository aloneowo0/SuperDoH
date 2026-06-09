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
import { logEvent } from './logger.js';

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };
const JSON_HEADERS = { 'Content-Type': 'application/json;charset=utf-8' };
const CF_FORCE_DOMAINS = ['twimg.com', 'twitter.com', 'x.com', 't.co'];

// ── Response helper with requestId ──────────────────────────────────

function respond(body, ctx, upstreamTime) {
  var r = dnsResponse(body, upstreamTime);
  r.headers.set('X-DoH-Request-ID', ctx.requestId);
  return r;
}

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

async function preferredAnswer(ctx, queryMeta, prefDomain, ttl, expectedOwner) {
  var startedAt = Date.now();
  const ips = await resolvePreferredIPs(prefDomain, queryMeta.type, expectedOwner, ctx);
  logEvent('info', 'preferred_result', { requestId: ctx.requestId, owner: expectedOwner, candidateCount: ips ? ips.length : 0, fallback: !ips || ips.length === 0 });
  if (ips && ips.length > 0) {
    return respond(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, ips, ttl), ctx);
  }
  if (!ips || ips.length === 0) {
    logEvent('warn', 'fallback', { requestId: ctx.requestId, stage: 'preferred_answer', owner: expectedOwner, reason: 'no_reachable_ips', from: 'preferred', to: 'first_result' });
  }
  return null;
}

// ── classifyResponse ───────────────────────────────────────────────

function classifyResponse(buffer, type, ctx) {
  try {
    if (type !== 1 && type !== 28) return null;
    const ips = extractIps(buffer);
    for (const ip of ips) {
      const owner = detectOwner(ip);
      if (owner) return owner;
    }
  } catch (err) {
    logEvent('error', 'classify_error', { requestId: ctx && ctx.requestId, errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
  }
  return null;
}

// ── Meta resolve: 800ms + 50ms collect ─────────────────────────────
//
// Tagged-promise + mask pattern:
//   Each upstream promise is wrapped at creation time to resolve as
//   { idx, result }.  A done[] mask tracks which indices have already
//   been consumed, so Promise.race always competes only on unresolved
//   promises.  No splice → no index-shifting bugs.

async function metaResolve(ctx, body, clientIP, queryMeta, echActive) {
  void echActive; // Meta type 65 ECH handled by postProcessBody()
  // Meta AAAA: no IPv6 reachability data, return NODATA immediately
  if (queryMeta.type === 28) {
    return respond(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, [], 60), ctx);
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
      } catch (err) {
        logEvent('error', 'meta_error', { requestId: ctx.requestId, stage: 'metaResolve_phase1_extract', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
      }
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
        } catch (err) {
          logEvent('error', 'meta_error', { requestId: ctx.requestId, stage: 'metaResolve_phase2_extract', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
        }
      }
    }
  }

  abortAll();

  logEvent('info', 'meta_collect', { requestId: ctx.requestId, firstValidMs: firstValid ? firstValid.time : 800, candidateCount: candidates.length, reachableCount: 0, staticCandidateCount: allRouteIPs ? allRouteIPs.length : 0 });

  if (candidates.length === 0) {
    return respond(servfail(body, 22, 'No reachable Meta IP'), ctx);
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
    return respond(servfail(body, 22, 'No reachable Meta IP'), ctx);
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
      return respond(servfail(body, 22, 'No reachable Meta IP'), ctx);
    }
  }

  logEvent('info', 'meta_collect', { requestId: ctx.requestId, firstValidMs: firstValid ? firstValid.time : 800, candidateCount: candidates.length, reachableCount: filtered.length, staticCandidateCount: allRouteIPs ? allRouteIPs.length : 0 });

  return respond(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, filtered, 300), ctx);
}

// ── twoMixFlow ─────────────────────────────────────────────────────

async function twoMixFlow(ctx, body, clientIP, queryMeta, regionActive, echActive, activePref, preferredCft, preferredVrc) {
  // Non-A/AAAA → concurrentAll with post-processing (ECH)
  if (!queryMeta || (queryMeta.type !== 1 && queryMeta.type !== 28)) {
    return await concurrentAll(body, clientIP, queryMeta, echActive, activePref, preferredCft, preferredVrc, {}, ctx);
  }

  // MIX 1: classify — only used for owner detection
  var startedAt = Date.now();
  const firstResult = await concurrentAll(body, clientIP, queryMeta, false, '', '', '', { skipPostProcess: true }, ctx);
  var mix1Buf = await firstResult.clone().arrayBuffer();
  var mix1AnswerCount = mix1Buf && mix1Buf.byteLength >= 12 ? new DataView(mix1Buf).getUint16(6) : 0;
  var mix1Rcode = mix1Buf && mix1Buf.byteLength >= 3 ? (new DataView(mix1Buf).getUint8(3) & 0x0F) : -1;
  logEvent('info', 'mix1_result', { requestId: ctx.requestId, elapsedMs: Date.now() - startedAt, rcode: mix1Rcode, answerCount: mix1AnswerCount });

  if (!regionActive) {
    // Add header to non-region response
    firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
    return firstResult;
  }

  const firstBuf = await firstResult.clone().arrayBuffer();

  // Domain rules take priority over IP classification
  var owner;
  var classifySource = '';
  if (isCFDomain(queryMeta.name)) {
    owner = 'CF';
    classifySource = 'domain_rule';
  } else if (isMetaDomain(queryMeta.name)) {
    owner = 'META';
    classifySource = 'domain_rule';
  } else {
    owner = classifyResponse(firstBuf, queryMeta.type, ctx);
    classifySource = 'response_ip';
  }
  logEvent('info', 'route_classified', { requestId: ctx.requestId, owner: owner, classifySource: classifySource });

  if (!owner) {
    firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
    return firstResult;
  }

  // MIX 2: optimize based on owner
  if (owner === 'META') {
    return await metaResolve(ctx, body, clientIP, queryMeta, echActive);
  }

  logEvent('info', 'mix2_start', { requestId: ctx.requestId, owner: owner, target: owner === 'CF' ? 'cf_preferred' : owner === 'CFT' ? 'cft_preferred' : owner === 'VRC' ? 'vrc_preferred' : 'meta_original' });

  if (owner === 'CF') {
    if (!activePref) {
      firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
      return firstResult;
    }
    var answer = await preferredAnswer(ctx, queryMeta, activePref, 60, 'CF');
    if (answer) {
      logEvent('info', 'request_end', { requestId: ctx.requestId, result: 'optimized', owner: owner, answerCount: 1 });
      return answer;
    }
    firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
    return firstResult;
  }

  if (owner === 'CFT') {
    if (!preferredCft) {
      firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
      return firstResult;
    }
    var answer = await preferredAnswer(ctx, queryMeta, preferredCft, 60, 'CFT');
    if (answer) {
      logEvent('info', 'request_end', { requestId: ctx.requestId, result: 'optimized', owner: owner, answerCount: 1 });
      return answer;
    }
    firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
    return firstResult;
  }

  if (owner === 'VRC') {
    if (!preferredVrc) {
      firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
      return firstResult;
    }
    var answer = await preferredAnswer(ctx, queryMeta, preferredVrc, 60, 'VRC');
    if (answer) {
      logEvent('info', 'request_end', { requestId: ctx.requestId, result: 'optimized', owner: owner, answerCount: 1 });
      return answer;
    }
    firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
    return firstResult;
  }

  firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
  return firstResult;
}

// ── Main handler ───────────────────────────────────────────────────

export default {
  async fetch(request) {
    var requestId = crypto.randomUUID().slice(0, 8);
    var startedAt = Date.now();
    let body = null;
    try {
      const route = resolveRoute(request);
      const upstreamNames = [MIX_PROVIDER, ...Object.keys(UPSTREAMS)];
      if (route.home) {
        var homeResp = new URL(request.url).pathname === '/en'
          ? serveHomepageEn(request, UPSTREAMS, upstreamNames)
          : serveHomepage(request, UPSTREAMS, upstreamNames);
        homeResp.headers.set('X-DoH-Request-ID', requestId);
        return homeResp;
      }
      if (route.health) {
        var hResp = healthResponse(upstreamNames);
        hResp.headers.set('X-DoH-Request-ID', requestId);
        return hResp;
      }
      if (route.error) {
        var errResp = jsonError(route.error);
        errResp.headers.set('X-DoH-Request-ID', requestId);
        return errResp;
      }

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
        var rfcResp = await rfc8484Passthrough(route, request);
        rfcResp.headers.set('X-DoH-Request-ID', requestId);
        return rfcResp;
      }

      if (!body) {
        if (request.method === 'GET') {
          body = buildQueryFromURL(url);
          if (!body) {
            var errR = jsonError('missing_name_or_type');
            errR.headers.set('X-DoH-Request-ID', requestId);
            return errR;
          }
        } else {
          body = await request.clone().arrayBuffer();
        }
      }
      const clientIP = request.headers.get('CF-Connecting-IP');
      const queryMeta = qMeta || parseQueryMeta(body);
      if (queryMeta && queryMeta.name) {
        queryMeta.forcedOwner = isCFDomain(queryMeta.name) ? 'CF' : isMetaDomain(queryMeta.name) ? 'META' : null;
      }

      var ctx = { requestId: requestId, region: clientCountry, qname: queryMeta ? queryMeta.name : '', qtype: queryMeta ? queryMeta.type : 0 };
      logEvent('info', 'request_start', { requestId: requestId, qname: ctx.qname, qtype: ctx.qtype, region: clientCountry });

      // Chrome DoH canary
      if (queryMeta && queryMeta.name && queryMeta.name.toLowerCase().replace(/\.+$/, '') === 'use-application-dns.net') {
        if (queryMeta.type === 1) {
          var nx = buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, [], 60);
          new DataView(nx).setUint16(2, 0x8183);
          var r = respond(nx, ctx);
          logEvent('info', 'request_end', { requestId: requestId, result: 'canary_nxdomain', owner: null, answerCount: 0 });
          return r;
        }
      }

      if (route.provider === MIX_PROVIDER) {
        var result = await twoMixFlow(ctx, body, clientIP, queryMeta, regionActive, echActive, activePref, preferredCft, preferredVrc);
        logEvent('info', 'request_end', { requestId: requestId, result: 'completed', owner: queryMeta && queryMeta.forcedOwner || null, answerCount: -1 });
        return result;
      }
      var sResult = await singleUpstream(ctx, route.provider, body, clientIP, queryMeta, echActive);
      logEvent('info', 'request_end', { requestId: requestId, result: 'single_upstream', owner: null, answerCount: -1 });
      return sResult;
    } catch (err) {
      logEvent('error', 'request_error', { requestId: requestId, errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err), elapsedMs: Date.now() - startedAt });
      if (body) {
        var sfResp = dnsResponse(servfail(body));
        sfResp.headers.set('X-DoH-Request-ID', requestId);
        return sfResp;
      }
      var errResp = jsonError('internal_error', 500);
      errResp.headers.set('X-DoH-Request-ID', requestId);
      return errResp;
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

async function singleUpstream(ctx, provider, body, clientIP, queryMeta, echActive) {
  const upstream = UPSTREAMS[provider];
  if (!upstream) return respond(servfail(body), ctx);
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
        const injected = await injectECH(finalBody, queryMeta.name, owner, cfEch, ctx);
        if (injected) {
          const injectedBytes = injected instanceof Response ? await injected.arrayBuffer() : injected;
          if (injectedBytes) finalBody = injectedBytes;
        }
      }
    }
    const fResult = filterAnswers(finalBody);
    if (response.status === 200 && fResult !== false && fResult?.passed !== false) return respond(finalBody, ctx, elapsed);
    return respond(servfail(body, 17, 'Filtered'), ctx, elapsed);
  } catch (err) {
    logEvent('error', 'single_upstream_error', { requestId: ctx.requestId, stage: 'singleUpstream', provider: provider, errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
  }
  return respond(servfail(body), ctx);
}
