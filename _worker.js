/**
 * SuperDoH — Entry point + orchestration
 *
 * Routes requests and dispatches DNS queries through upstream flows.
 */

import { ECS_PROTECT_MS, HARD_TIMEOUT_MS, META_HARD_TIMEOUT_MS, META_COLLECT_WINDOW_MS, META_MAX_IPS, AUTO_CONCURRENCY, AUTO_PROVIDER, UPSTREAMS, REGION, REGION_CONFIG, LOG_LEVEL } from './config.js';
import { prepareQuery } from './edns.js';
import { serveHomepage, serveHomepageEn } from './homepage.js';
import { answersPass, concurrentAll, queryUpstream, resolvePreferred } from './auto.js';
import { fetchCFEch, injectECH } from './ech.js';
import { probeOwner, detectOwner, extractIps, isMetaDomain } from './cdn.js';
import { dnsResponse, servfail, buildDNS, parseDns, extractIPBytes, decodeName } from './dns-lib.js';
import { resolveMetaFromMap } from './meta-route.js';
import { logEvent, setLogLevel } from './logger.js';
import { parseDohRequest } from './doh-request.js';
setLogLevel(LOG_LEVEL);

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };
const JSON_HEADERS = { 'Content-Type': 'application/json;charset=utf-8' };
// ── Response helper with requestId ──────────────────────────────────

function respond(body, ctx, upstreamTime) {
  var r = dnsResponse(body, upstreamTime);
  r.headers.set('X-DoH-Request-ID', ctx.requestId);
  return r;
}

/** Check if domain should be force-routed to CF via region remap. */
function isCFDomain(name, remapList) {
  if (!name || !remapList || !remapList.length) return false;
  var n = name.toLowerCase().replace(/\.+$/, '');
  for (var i = 0; i < remapList.length; i++) {
    var rd = remapList[i].toLowerCase().replace(/\.+$/, '');
    if (n === rd || n.endsWith('.' + rd)) return true;
  }
  return false;
}

function ipToBytes(ip) {
  if (!ip) return null;
  if (ip.indexOf(':') >= 0) {
    // IPv6 parsing deferred — no Google proxy uses IPv6
    return null;
  }
  var parts = ip.split('.');
  if (parts.length !== 4) return null;
  var bytes = new Uint8Array(4);
  for (var i = 0; i < parts.length; i++) {
    if (!/^\d{1,3}$/.test(parts[i])) return null;
    var octet = Number(parts[i]);
    if (octet > 255) return null;
    bytes[i] = octet;
  }
  return bytes;
}

function matchGoogleProxy(name, googleConf) {
  if (!name || !googleConf || !googleConf.length) return null;
  for (var i = 0; i < googleConf.length; i++) {
    var entry = googleConf[i];
    var patterns = entry.match || [];
    for (var j = 0; j < patterns.length; j++) {
      var p = patterns[j];
      if (p instanceof RegExp) {
        if (p.test(name)) return entry;
      } else if (typeof p === 'string') {
        var n = name.toLowerCase().replace(/\.+$/, '');
        var rd = p.toLowerCase().replace(/\.+$/, '');
        var suffix = rd.startsWith('.') ? rd : '.' + rd;
        if (n === rd || n.endsWith(suffix)) return entry;
      }
    }
  }
  return null;
}

// ── Router (inlined) ───────────────────────────────────────────────

let _validProviders = null;
function validProviders() {
  if (!_validProviders) _validProviders = new Set([...Object.keys(UPSTREAMS), AUTO_PROVIDER]);
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
    return { provider: AUTO_PROVIDER, queryString: search };
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

function bytesToBase64(bytes) {
  var s = '';
  for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function rdataToJsonData(view, record) {
  var rdata = new Uint8Array(view.buffer, view.byteOffset + record.rdataOffset, record.rdlength);
  if (record.type === 1 && rdata.length === 4) {
    return rdata[0] + '.' + rdata[1] + '.' + rdata[2] + '.' + rdata[3];
  }
  if (record.type === 28 && rdata.length === 16) {
    var parts = [];
    for (var i = 0; i < 16; i += 2) parts.push(((rdata[i] << 8) | rdata[i + 1]).toString(16));
    return parts.join(':');
  }
  return bytesToBase64(rdata);
}

async function dnsWireToJsonResponse(response) {
  try {
    var buf = await response.arrayBuffer();
    var packet = parseDns(buf);
    var view = packet.view;
    var flags = packet.header.flags;
    var offset = 12;
    var questions = [];
    for (var i = 0; i < packet.header.qdcount; i++) {
      var qName = decodeName(view, offset);
      offset = qName.end;
      if (offset + 4 > view.byteLength) throw new Error('DNS question out of bounds');
      questions.push({ name: qName.name, type: view.getUint16(offset) });
      offset += 4;
    }
    var answers = [];
    for (var j = 0; j < packet.answers.length; j++) {
      var rec = packet.answers[j];
      var rrName = decodeName(view, rec.offset);
      answers.push({
        name: rrName.name,
        type: rec.type,
        TTL: rec.ttl,
        data: rdataToJsonData(view, rec),
      });
    }
    var json = {
      Status: flags & 0x000F,
      TC: !!(flags & 0x0200),
      RD: !!(flags & 0x0100),
      RA: !!(flags & 0x0080),
      AD: !!(flags & 0x0020),
      CD: !!(flags & 0x0010),
      Question: questions,
    };
    if (answers.length) json.Answer = answers;
    var out = new Response(JSON.stringify(json), { status: response.status, headers: JSON_HEADERS });
    var upstreamTime = response.headers.get('X-Upstream-Time');
    if (upstreamTime) out.headers.set('X-Upstream-Time', upstreamTime);
    return out;
  } catch (err) {
    return jsonError('invalid_dns_response', 502);
  }
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
  const ips = await resolvePreferred(prefDomain, queryMeta.type, expectedOwner, ctx, ctx.clientIP);
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

  // Prepare query with EDNS/ECS (same semantics as main flow)
  var preparedBody = prepareQuery(body, clientIP);

  // Fire all upstreams — each tagged with its index
  var controllers = [];
  var tagged = [];
  var done = [];
  var upstreamKeys = Object.keys(UPSTREAMS);
  if (AUTO_CONCURRENCY > 0 && AUTO_CONCURRENCY < upstreamKeys.length) {
    upstreamKeys = upstreamKeys.slice(0, AUTO_CONCURRENCY);
  }
  for (var i = 0; i < upstreamKeys.length; i++) {
    var ctrl = new AbortController();
    controllers.push(ctrl);
    done.push(false);
    (function (idx) {
      tagged.push(
        queryUpstream(UPSTREAMS[upstreamKeys[idx]].url, preparedBody, startedAt, controllers[idx].signal, upstreamKeys[idx])
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
        if (rawIps.length > 0) {
          firstValid = winner.result;
          for (var j = 0; j < rawIps.length; j++) candidates.push(rawIps[j]);
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
      filtered.push(candidates[i]);
      if (filtered.length >= META_MAX_IPS) break;
    }
  }

  if (filtered.length === 0) {
    return respond(servfail(body, 22, 'No reachable Meta IP'), ctx);
  }

// Meta type 65 ECH: handled by postProcessBody() in auto.js (autoFlow
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

  logEvent('info', 'meta_collect', { requestId: ctx.requestId, firstValidMs: firstValid ? firstValid.time : META_HARD_TIMEOUT_MS, candidateCount: candidates.length, reachableCount: filtered.length, staticCandidateCount: allRouteIPs ? allRouteIPs.length : 0 });

  return respond(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, filtered, 300), ctx);
}

// ── autoFlow ─────────────────────────────────────────────────────

async function autoFlow(ctx, body, clientIP, queryMeta, regionActive, echActive, preferredCf, preferredCft, preferredVrc, remapList, googleConf) {
  // Non-A/AAAA → concurrentAll with post-processing (ECH)
  if (!queryMeta || (queryMeta.type !== 1 && queryMeta.type !== 28)) {
    return await concurrentAll(body, clientIP, queryMeta, echActive, preferredCf, preferredCft, preferredVrc, {}, ctx);
  }

  // AUTO 1: classify — only used for owner detection
  var startedAt = Date.now();
  const firstResult = await concurrentAll(body, clientIP, queryMeta, false, '', '', '', { skipPostProcess: true }, ctx);
  var auto1Buf = await firstResult.clone().arrayBuffer();
  var auto1AnswerCount = auto1Buf && auto1Buf.byteLength >= 12 ? new DataView(auto1Buf).getUint16(6) : 0;
  var auto1Rcode = auto1Buf && auto1Buf.byteLength >= 3 ? (new DataView(auto1Buf).getUint8(3) & 0x0F) : -1;
  logEvent('info', 'auto1_result', { requestId: ctx.requestId, elapsedMs: Date.now() - startedAt, rcode: auto1Rcode, answerCount: auto1AnswerCount });

  if (!regionActive) {
    // Add header to non-region response
    firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
    return firstResult;
  }

  const firstBuf = await firstResult.clone().arrayBuffer();

  // Domain rules take priority over IP classification
  var owner;
  var classifySource = '';
    if (isCFDomain(queryMeta.name, remapList)) {
    owner = 'CF';
    classifySource = 'domain_rule';
  } else if (isMetaDomain(queryMeta.name)) {
    owner = 'META';
    classifySource = 'domain_rule';
  }
  if (!owner && googleConf && queryMeta.type === 1) {
    var googleMatch = matchGoogleProxy(queryMeta.name, googleConf);
    if (googleMatch && googleMatch.ips && googleMatch.ips.length) {
      owner = 'GOOGLE';
      classifySource = 'domain_rule';
      ctx._googleMatch = googleMatch;
    }
  }
  if (!owner) {
    owner = classifyResponse(firstBuf, queryMeta.type, ctx);
    classifySource = 'response_ip';
  }
  logEvent('info', 'route_classified', { requestId: ctx.requestId, owner: owner, classifySource: classifySource });
  ctx.owner = owner;

  if (!owner) {
    firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
    return firstResult;
  }

  // AUTO 2: optimize based on owner
  if (owner === 'META') {
    return await metaResolve(ctx, body, clientIP, queryMeta, echActive);
  }

  logEvent('info', 'auto2_start', { requestId: ctx.requestId, owner: owner, target: owner === 'CF' ? 'cf_preferred' : owner === 'CFT' ? 'cft_preferred' : owner === 'VRC' ? 'vrc_preferred' : 'meta_original' });

  if (owner === 'CF') {
    if (!preferredCf) {
      firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
      return firstResult;
    }
    var answer = await preferredAnswer(ctx, queryMeta, preferredCf, 60, 'CF');
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

  if (owner === 'GOOGLE') {
    var googleMatch = ctx._googleMatch;
    if (googleMatch && googleMatch.ips) {
      var proxyBytes = googleMatch.ips.map(ipToBytes).filter(function(b) { return b; });
      if (proxyBytes.length > 0) {
        var existingIps = auto1Buf && auto1Buf.byteLength >= 12 ? extractIPBytes(auto1Buf, 1) : [];
        var seen = {};
        var combined = [];
        // Proxy IPs first — GFW blackholes real Google IPv4, so browser
        // Happy Eyeballs must try the tunnel proxy before timing out on
        // blocked direct IPs.
        for (var pi = 0; pi < proxyBytes.length; pi++) {
          var key = Array.prototype.join.call(proxyBytes[pi], '.');
          if (!seen[key]) { seen[key] = true; combined.push(proxyBytes[pi]); }
        }
        for (var ei = 0; ei < existingIps.length; ei++) {
          var key = Array.prototype.join.call(existingIps[ei], '.');
          if (!seen[key]) { seen[key] = true; combined.push(existingIps[ei]); }
        }
        var mergedBuf = buildDNS(queryMeta.id, queryMeta.name, 1, combined, 300);
        logEvent('info', 'google_proxy', { requestId: ctx.requestId, qname: queryMeta.name, mixed: existingIps.length, proxy: proxyBytes.length, total: combined.length });
        return respond(mergedBuf, ctx);
      }
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
      const upstreamNames = [AUTO_PROVIDER, ...Object.keys(UPSTREAMS)];
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

      const parsedRequest = await parseDohRequest(request);
      if (parsedRequest.error) {
        var requestError = jsonError(parsedRequest.error.error, parsedRequest.error.status);
        Object.keys(parsedRequest.error.headers).forEach(function(name) { requestError.headers.set(name, parsedRequest.error.headers[name]); });
        requestError.headers.set('X-DoH-Request-ID', requestId);
        return requestError;
      }
      body = parsedRequest.body;
      const qMeta = parsedRequest.queryMeta;
      const wantsJson = parsedRequest.wantsJson;

      const clientCountry = request.cf && request.cf.country || '';
      const regionCfg = REGION_CONFIG && REGION_CONFIG[clientCountry];
      const regionActive = !!(regionCfg && (regionCfg.preferredCf || regionCfg.preferredCft || regionCfg.preferredVrc || regionCfg.ech || (regionCfg.remap && regionCfg.remap.length) || (regionCfg.google && regionCfg.google.length)));
      const preferredCf = regionCfg ? (regionCfg.preferredCf || '') : '';
      const echActive = !!(regionCfg && regionCfg.ech);
      const preferredCft = regionCfg ? (regionCfg.preferredCft || '') : '';
      const preferredVrc = regionCfg ? (regionCfg.preferredVrc || '') : '';

      const clientIP = request.headers.get('CF-Connecting-IP');
      const queryMeta = qMeta;
      if (queryMeta && queryMeta.name) {
        var remapForOwner = regionCfg ? regionCfg.remap : null;
        queryMeta.forcedOwner = isCFDomain(queryMeta.name, remapForOwner) ? 'CF' : isMetaDomain(queryMeta.name) ? 'META' : null;
      }

      var ctx = { requestId: requestId, region: clientCountry, qname: queryMeta ? queryMeta.name : '', qtype: queryMeta ? queryMeta.type : 0 };
      logEvent('info', 'request_start', { requestId: requestId, qname: ctx.qname, qtype: ctx.qtype, region: clientCountry });

      // Chrome DoH canary
      if (queryMeta && queryMeta.name && queryMeta.name.toLowerCase().replace(/\.+$/, '') === 'use-application-dns.net') {
        if (queryMeta.type === 1 || queryMeta.type === 28) {
          var nx = buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, [], 60);
          new DataView(nx).setUint16(2, 0x8183);
          var r = respond(nx, ctx);
          logEvent('info', 'request_end', { requestId: requestId, result: 'canary_nxdomain', owner: null, answerCount: 0 });
          return r;
        }
      }

      // AAAA block for remap domains
      if (queryMeta && queryMeta.name && queryMeta.type === 28 && regionCfg && regionCfg.remap && isCFDomain(queryMeta.name, regionCfg.remap)) {
        var no6 = buildDNS(queryMeta.id, queryMeta.name, 28, [], 300);
        var r6 = respond(no6, ctx);
        logEvent('info', 'request_end', { requestId: requestId, result: 'remap_no_aaaa', owner: null, answerCount: 0 });
        return r6;
      }

      if (route.provider === AUTO_PROVIDER) {
        var result = await autoFlow(ctx, body, clientIP, queryMeta, regionActive, echActive, preferredCf, preferredCft, preferredVrc, regionCfg ? regionCfg.remap : null, regionCfg ? regionCfg.google : null);
        if (wantsJson) result = await dnsWireToJsonResponse(result);
        result.headers.set('X-DoH-Request-ID', requestId);
        logEvent('info', 'request_end', { requestId: requestId, result: 'completed', owner: ctx.owner || null });
        return result;
      }
      var sResult = await singleUpstream(ctx, route.provider, body, clientIP, queryMeta, echActive);
      if (wantsJson) sResult = await dnsWireToJsonResponse(sResult);
      sResult.headers.set('X-DoH-Request-ID', requestId);
      logEvent('info', 'request_end', { requestId: requestId, result: 'single_upstream', owner: null });
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

// ── Single upstream query ──────────────────────────────────────────

async function singleUpstream(ctx, provider, body, clientIP, queryMeta, echActive) {
  const upstream = UPSTREAMS[provider];
  if (!upstream) return respond(servfail(body), ctx);
  const queryId = body && body.byteLength >= 2 ? new DataView(body).getUint16(0) : 0;
  const queryBody = prepareQuery(body, clientIP);
  const started = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(function() { try { ctrl.abort(); } catch (_) {} }, HARD_TIMEOUT_MS);
  try {
    const response = await fetch(upstream.url, {
      method: 'POST',
      headers: DNS_HEADERS,
      body: queryBody,
      signal: ctrl.signal,
    });
    const responseBody = await response.arrayBuffer();
    const elapsed = Date.now() - started;
    const originalResult = answersPass(responseBody, queryId, queryMeta && queryMeta.name, queryMeta && queryMeta.type);
    if (response.status !== 200 || !originalResult.passed || originalResult.classification === 'invalid') {
      return respond(servfail(body, 17, 'Filtered'), ctx, elapsed);
    }
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
        var echResult = await injectECH(finalBody, queryMeta.name, owner, cfEch, ctx);
        if (echResult.changed) {
          var injectedBytes = echResult.body instanceof Response ? await echResult.body.arrayBuffer() : echResult.body;
          if (injectedBytes) finalBody = injectedBytes;
        } else {
          logEvent('warn', 'ech_result', { requestId: ctx.requestId, owner: owner, status: 'degraded', reason: 'ech_not_applied_' + echResult.status });
        }
      }
    }
    const fResult = answersPass(finalBody, queryId, queryMeta && queryMeta.name, queryMeta && queryMeta.type);
    if (response.status === 200 && fResult.passed && fResult.classification !== 'invalid') return respond(finalBody, ctx, elapsed);
    return respond(servfail(body, 17, 'Filtered'), ctx, elapsed);
  } catch (err) {
    logEvent('error', 'single_upstream_error', { requestId: ctx.requestId, stage: 'singleUpstream', provider: provider, errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
  } finally { clearTimeout(timer); }
  return respond(servfail(body), ctx);
}
