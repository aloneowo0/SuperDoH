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
import { probeOwner, detectOwner, extractIps, isMetaDomain, classifyResponse } from './cdn.js';
import { dnsResponse, servfail, buildDNS, parseDns, extractIPBytes, decodeName } from './dns-lib.js';
import { resolveMetaFromMap } from './meta-route.js';
import { logEvent, setLogLevel } from './logger.js';
import { parseDohRequest } from './doh-request.js';
setLogLevel(LOG_LEVEL);

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };
const JSON_HEADERS = { 'Content-Type': 'application/json;charset=utf-8' };
const TYPE_A = 1;
const TYPE_AAAA = 28;
const TYPE_HTTPS = 65;
// ── Response helper with requestId ──────────────────────────────────

function respond(body, ctx, upstreamTime) {
  const r = dnsResponse(body, upstreamTime);
  r.headers.set('X-DoH-Request-ID', ctx.requestId);
  return r;
}

/** Check if domain should be force-routed to CF via region remap. */
function isCFDomain(name, remapList) {
  if (!name || !remapList || !remapList.length) return false;
  const n = name.toLowerCase().replace(/\.+$/, '');
  for (let i = 0; i < remapList.length; i++) {
    const rd = remapList[i].toLowerCase().replace(/\.+$/, '');
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
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < parts.length; i++) {
    if (!/^\d{1,3}$/.test(parts[i])) return null;
    const octet = Number(parts[i]);
    if (octet > 255) return null;
    bytes[i] = octet;
  }
  return bytes;
}

function matchGoogleProxy(name, googleConf) {
  if (!name || !googleConf || !googleConf.length) return null;
  for (let i = 0; i < googleConf.length; i++) {
    const entry = googleConf[i];
    const patterns = entry.match || [];
    for (let j = 0; j < patterns.length; j++) {
      const p = patterns[j];
      if (p instanceof RegExp) {
        if (p.test(name)) return entry;
      } else if (typeof p === 'string') {
        const n = name.toLowerCase().replace(/\.+$/, '');
        const rd = p.toLowerCase().replace(/\.+$/, '');
        const suffix = rd.startsWith('.') ? rd : '.' + rd;
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
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function rdataToJsonData(view, record) {
  const rdata = new Uint8Array(view.buffer, view.byteOffset + record.rdataOffset, record.rdlength);
  if (record.type === TYPE_A && rdata.length === 4) {
    return rdata[0] + '.' + rdata[1] + '.' + rdata[2] + '.' + rdata[3];
  }
  if (record.type === TYPE_AAAA && rdata.length === 16) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(((rdata[i] << 8) | rdata[i + 1]).toString(16));
    return parts.join(':');
  }
  return bytesToBase64(rdata);
}

async function dnsWireToJsonResponse(response) {
  try {
    const buf = await response.arrayBuffer();
    const packet = parseDns(buf);
    const view = packet.view;
    const flags = packet.header.flags;
    let offset = 12;
    const questions = [];
    for (let i = 0; i < packet.header.qdcount; i++) {
      const qName = decodeName(view, offset);
      offset = qName.end;
      if (offset + 4 > view.byteLength) throw new Error('DNS question out of bounds');
      questions.push({ name: qName.name, type: view.getUint16(offset) });
      offset += 4;
    }
    const answers = [];
    for (let j = 0; j < packet.answers.length; j++) {
      const rec = packet.answers[j];
      const rrName = decodeName(view, rec.offset);
      answers.push({
        name: rrName.name,
        type: rec.type,
        TTL: rec.ttl,
        data: rdataToJsonData(view, rec),
      });
    }
    const json = {
      Status: flags & 0x000F,
      TC: !!(flags & 0x0200),
      RD: !!(flags & 0x0100),
      RA: !!(flags & 0x0080),
      AD: !!(flags & 0x0020),
      CD: !!(flags & 0x0010),
      Question: questions,
    };
    if (answers.length) json.Answer = answers;
    const out = new Response(JSON.stringify(json), { status: response.status, headers: JSON_HEADERS });
    const upstreamTime = response.headers.get('X-Upstream-Time');
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
  if (queryMeta.type === TYPE_AAAA) {
    return respond(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, [], 60), ctx);
  }

  const startedAt = Date.now();
  const hardDeadline = startedAt + META_HARD_TIMEOUT_MS;
  const candidates = [];

  // Static route / cache hit — only use IPs matching query type
  const allRouteIPs = resolveMetaFromMap(queryMeta.name);
  if (allRouteIPs && allRouteIPs.length > 0) {
    const expectedLen = queryMeta.type === TYPE_A ? 4 : queryMeta.type === TYPE_AAAA ? 16 : -1;
    for (let ri = 0; ri < allRouteIPs.length; ri++) {
      if (allRouteIPs[ri].length === expectedLen) candidates.push(allRouteIPs[ri]);
    }
  }

  // Prepare query with EDNS/ECS (same semantics as main flow)
  const preparedBody = prepareQuery(body, clientIP);

  // Fire all upstreams — each tagged with its index
  const controllers = [];
  const tagged = [];
  const done = [];
  let upstreamKeys = Object.keys(UPSTREAMS);
  if (AUTO_CONCURRENCY > 0 && AUTO_CONCURRENCY < upstreamKeys.length) {
    upstreamKeys = upstreamKeys.slice(0, AUTO_CONCURRENCY);
  }
  for (let i = 0; i < upstreamKeys.length; i++) {
    const ctrl = new AbortController();
    controllers.push(ctrl);
    done.push(false);
    const idx = i;
    tagged.push(
      queryUpstream(UPSTREAMS[upstreamKeys[idx]].url, preparedBody, startedAt, controllers[idx].signal, upstreamKeys[idx])
        .then((r) => ({ idx, result: r }))
    );
  }

  function abortAll() {
    for (let i = 0; i < controllers.length; i++) {
      try { controllers[i].abort(); } catch (_) { /* ignore — abort may throw if already aborted */ }
    }
  }

  // Build a race list from unresolved tagged promises + timeout promise
  function raceList(deadline) {
    const list = [];
    for (let i = 0; i < tagged.length; i++) {
      if (!done[i]) list.push(tagged[i]);
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) return [];
    list.push(new Promise(function (resolve) { setTimeout(function () { resolve(null); }, remaining); }));
    return list;
  }

  // ── Phase 1: wait for first valid response within 800ms ──────────

  let firstValid = null;
  while (Date.now() < hardDeadline) {
    const racers = raceList(hardDeadline);
    if (racers.length <= 1) break; // nothing left except the timeout (or nothing at all)

    const winner = await Promise.race(racers);
    if (!winner) break; // timeout
    done[winner.idx] = true;

    if (winner.result.valid) {
      try {
        const rawIps = extractIPBytes(winner.result.response, queryMeta.type);
        if (rawIps.length > 0) {
          firstValid = winner.result;
          for (let j = 0; j < rawIps.length; j++) candidates.push(rawIps[j]);
          break;
        }
      } catch (err) {
        logEvent('error', 'meta_error', { requestId: ctx.requestId, stage: 'metaResolve_phase1_extract', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
      }
    }
  }

  // ── Phase 2: 50ms collect window after first valid ───────────────

  if (firstValid) {
    const collectDeadline = Math.min(Date.now() + META_COLLECT_WINDOW_MS, hardDeadline);
    while (Date.now() < collectDeadline) {
      const racers = raceList(collectDeadline);
      if (racers.length <= 1) break;

      const winner = await Promise.race(racers);
      if (!winner) break;
      done[winner.idx] = true;

      if (winner.result.valid) {
        try {
          const ips = extractIPBytes(winner.result.response, queryMeta.type);
          for (let j = 0; j < ips.length; j++) candidates.push(ips[j]);
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

  const seen = new Set();
  let filtered = [];
  for (let i = 0; i < candidates.length; i++) {
    const key = Array.from(candidates[i]).join(',');
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
  const rdataLen = queryMeta.type === TYPE_A ? 4 : queryMeta.type === TYPE_AAAA ? 16 : null;
  if (rdataLen) {
    const validFiltered = [];
    for (let fi = 0; fi < filtered.length; fi++) {
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
  if (!queryMeta || (queryMeta.type !== TYPE_A && queryMeta.type !== TYPE_AAAA)) {
    return await concurrentAll(body, clientIP, queryMeta, echActive, preferredCf, preferredCft, preferredVrc, {}, ctx);
  }

  // AUTO 1: classify — only used for owner detection
  const startedAt = Date.now();
  const firstResult = await concurrentAll(body, clientIP, queryMeta, false, '', '', '', { skipPostProcess: true }, ctx);
  const auto1Buf = await firstResult.clone().arrayBuffer();
  const auto1AnswerCount = auto1Buf && auto1Buf.byteLength >= 12 ? new DataView(auto1Buf).getUint16(6) : 0;
  const auto1Rcode = auto1Buf && auto1Buf.byteLength >= 3 ? (new DataView(auto1Buf).getUint8(3) & 0x0F) : -1;
  logEvent('info', 'auto1_result', { requestId: ctx.requestId, elapsedMs: Date.now() - startedAt, rcode: auto1Rcode, answerCount: auto1AnswerCount });

  if (!regionActive) {
    // Add header to non-region response
    firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
    return firstResult;
  }

  const firstBuf = await firstResult.clone().arrayBuffer();

  // Domain rules take priority over IP classification
  let owner;
  let classifySource = '';
    if (isCFDomain(queryMeta.name, remapList)) {
    owner = 'CF';
    classifySource = 'domain_rule';
  } else if (isMetaDomain(queryMeta.name)) {
    owner = 'META';
    classifySource = 'domain_rule';
  }
  if (!owner && googleConf && queryMeta.type === TYPE_A) {
    const googleMatch = matchGoogleProxy(queryMeta.name, googleConf);
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
    const answer = await preferredAnswer(ctx, queryMeta, preferredCf, 60, 'CF');
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
    const answer = await preferredAnswer(ctx, queryMeta, preferredCft, 60, 'CFT');
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
    const answer = await preferredAnswer(ctx, queryMeta, preferredVrc, 60, 'VRC');
    if (answer) {
      logEvent('info', 'request_end', { requestId: ctx.requestId, result: 'optimized', owner: owner, answerCount: 1 });
      return answer;
    }
    firstResult.headers.set('X-DoH-Request-ID', ctx.requestId);
    return firstResult;
  }

  if (owner === 'GOOGLE') {
    const googleMatch = ctx._googleMatch;
    if (googleMatch && googleMatch.ips) {
      const proxyBytes = googleMatch.ips.map(ipToBytes).filter(function(b) { return b; });
      if (proxyBytes.length > 0) {
        const existingIps = auto1Buf && auto1Buf.byteLength >= 12 ? extractIPBytes(auto1Buf, TYPE_A) : [];
        const seen = {};
        const combined = [];
        // Proxy IPs first — GFW blackholes real Google IPv4, so browser
        // Happy Eyeballs must try the tunnel proxy before timing out on
        // blocked direct IPs.
        for (let pi = 0; pi < proxyBytes.length; pi++) {
          const key = [...proxyBytes[pi]].join('.');
          if (!seen[key]) { seen[key] = true; combined.push(proxyBytes[pi]); }
        }
        for (let ei = 0; ei < existingIps.length; ei++) {
          const key = [...existingIps[ei]].join('.');
          if (!seen[key]) { seen[key] = true; combined.push(existingIps[ei]); }
        }
        const mergedBuf = buildDNS(queryMeta.id, queryMeta.name, TYPE_A, combined, 300);
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
    const requestId = crypto.randomUUID().slice(0, 8);
    const startedAt = Date.now();
    let body = null;
    try {
      const route = resolveRoute(request);
      const upstreamNames = [AUTO_PROVIDER, ...Object.keys(UPSTREAMS)];
      if (route.home) {
        const homeResp = new URL(request.url).pathname === '/en'
          ? serveHomepageEn(request, UPSTREAMS, upstreamNames)
          : serveHomepage(request, UPSTREAMS, upstreamNames);
        homeResp.headers.set('X-DoH-Request-ID', requestId);
        return homeResp;
      }
      if (route.health) {
        const hResp = healthResponse(upstreamNames);
        hResp.headers.set('X-DoH-Request-ID', requestId);
        return hResp;
      }
      if (route.error) {
        const errResp = jsonError(route.error);
        errResp.headers.set('X-DoH-Request-ID', requestId);
        return errResp;
      }

      const parsedRequest = await parseDohRequest(request);
      if (parsedRequest.error) {
        const requestError = jsonError(parsedRequest.error.error, parsedRequest.error.status);
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
        const remapForOwner = regionCfg ? regionCfg.remap : null;
        queryMeta.forcedOwner = isCFDomain(queryMeta.name, remapForOwner) ? 'CF' : isMetaDomain(queryMeta.name) ? 'META' : null;
      }

      const ctx = { requestId: requestId, region: clientCountry, qname: queryMeta ? queryMeta.name : '', qtype: queryMeta ? queryMeta.type : 0 };
      logEvent('info', 'request_start', { requestId: requestId, qname: ctx.qname, qtype: ctx.qtype, region: clientCountry });

      // Chrome DoH canary
      if (queryMeta && queryMeta.name && queryMeta.name.toLowerCase().replace(/\.+$/, '') === 'use-application-dns.net') {
        if (queryMeta.type === TYPE_A || queryMeta.type === TYPE_AAAA) {
          const nx = buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, [], 60);
          new DataView(nx).setUint16(2, 0x8183);
          const r = respond(nx, ctx);
          logEvent('info', 'request_end', { requestId: requestId, result: 'canary_nxdomain', owner: null, answerCount: 0 });
          return r;
        }
      }

      // AAAA block for remap domains
      if (queryMeta && queryMeta.name && queryMeta.type === TYPE_AAAA && regionCfg && regionCfg.remap && isCFDomain(queryMeta.name, regionCfg.remap)) {
        const no6 = buildDNS(queryMeta.id, queryMeta.name, TYPE_AAAA, [], 300);
        const r6 = respond(no6, ctx);
        logEvent('info', 'request_end', { requestId: requestId, result: 'remap_no_aaaa', owner: null, answerCount: 0 });
        return r6;
      }

      if (route.provider === AUTO_PROVIDER) {
        let result = await autoFlow(ctx, body, clientIP, queryMeta, regionActive, echActive, preferredCf, preferredCft, preferredVrc, regionCfg ? regionCfg.remap : null, regionCfg ? regionCfg.google : null);
        if (wantsJson) result = await dnsWireToJsonResponse(result);
        result.headers.set('X-DoH-Request-ID', requestId);
        logEvent('info', 'request_end', { requestId: requestId, result: 'completed', owner: ctx.owner || null });
        return result;
      }
      let sResult = await singleUpstream(ctx, route.provider, body, clientIP, queryMeta, echActive);
      if (wantsJson) sResult = await dnsWireToJsonResponse(sResult);
      sResult.headers.set('X-DoH-Request-ID', requestId);
      logEvent('info', 'request_end', { requestId: requestId, result: 'single_upstream', owner: null });
      return sResult;
    } catch (err) {
      logEvent('error', 'request_error', { requestId: requestId, errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err), elapsedMs: Date.now() - startedAt });
      if (body) {
        const sfResp = dnsResponse(servfail(body));
        sfResp.headers.set('X-DoH-Request-ID', requestId);
        return sfResp;
      }
      const errResp = jsonError('internal_error', 500);
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
  const timer = setTimeout(function() { try { ctrl.abort(); } catch (_) { /* ignore — abort may throw if already aborted */ } }, HARD_TIMEOUT_MS);
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
    if (echActive && queryMeta && queryMeta.type === TYPE_HTTPS) {
      let owner = null;
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
        const echResult = await injectECH(finalBody, queryMeta.name, owner, cfEch, ctx);
        if (echResult.changed) {
          const injectedBytes = echResult.body instanceof Response ? await echResult.body.arrayBuffer() : echResult.body;
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
