/** Multi-upstream racing module — ECS protect window + post-processing */
import { ECS_PROTECT_MS, FOREIGN_UPSTREAMS, HARD_TIMEOUT_MS, AUTO_CONCURRENCY, PREFERRED_TIMEOUT_MS, UPSTREAMS } from './config.js';
import { prepareQuery, filterAnswers, validateResponse } from './edns.js';
import { fetchCFEch, injectECH } from './ech.js';
import { probeOwner, isMetaDomain, detectOwner } from './cdn.js';
import { buildWireQuery, dnsResponse, extractIPBytes, parseQueryMeta, servfail } from './dns-lib.js';
import { cancelDnsResponseBody, readDnsResponseBody } from './dns-response.js';
import { logEvent, recordFallback } from './logger.js';

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };

export async function concurrentAll(body, clientIP, queryMeta, echActive, activePref, preferredCft, preferredVrc, options, ctx) {
  const opts = options || {};
  const upstreams = opts.upstreams || UPSTREAMS;
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;
  const protectEnd = started + ECS_PROTECT_MS;

  const effectiveBody = opts.overrideBody || body;
  const queryId = effectiveBody && effectiveBody.byteLength >= 2 ? new DataView(effectiveBody).getUint16(0) : 0;
  const preparedBody = prepareQuery(effectiveBody, clientIP);

  let entries = Object.entries(upstreams);
  if (AUTO_CONCURRENCY > 0 && AUTO_CONCURRENCY < entries.length) {
    entries = entries.slice(0, AUTO_CONCURRENCY);
  }
  const pending = entries.map(([name, cfg]) => {
    const ctrl = new AbortController();
    return {
      ecs: cfg.ecs,
      ctrl,
      promise: queryUpstream(cfg.url, preparedBody, started, ctrl.signal, name, queryId, ctx)
        .then((r) => ({ ecs: cfg.ecs, result: r })),
    };
  });

  const held = [];

  function abortPending() {
    for (const p of pending) {
      try { p.ctrl.abort(); } catch (_) { /* ignore — abort may throw if already aborted */ }
    }
  }

  function sortHeld() {
    held.sort((a, b) => {
      const ap = a.result.classification === 'positive' ? 0 : 1;
      const bp = b.result.classification === 'positive' ? 0 : 1;
      if (ap !== bp) return ap - bp;
      return a.result.time - b.result.time;
    });
  }

  async function finishResult(result) {
    let processed;
    if (opts.skipPostProcess) {
      abortPending();
      processed = result.response;
    } else {
      abortPending();
      processed = await postProcessBody(result.response, queryMeta, echActive, ctx);
    }
    return dnsResponse(processed, result.time);
  }

  while (pending.length && Date.now() < deadline) {
    const inProtect = Date.now() < protectEnd;

    // 保护窗到期先检查暂存：释放最快的那条
    if (!inProtect && held.some((item) => item.result.classification === 'positive')) {
      sortHeld();
      const bestHeld = held[0];
      if (opts.acceptFilter && !opts.acceptFilter(bestHeld.result.response)) {
        held.shift();
        continue;
      }
      return await finishResult(bestHeld.result);
    }

    const remaining = (inProtect ? protectEnd : deadline) - Date.now();
    if (remaining <= 0) {
      // 剩余时间为0但可能有暂存 → 回到循环顶部释放暂存
      // 如果保护窗已过且暂存也空了 → 跳出
      if (!inProtect && held.length === 0) break;
      continue;
    }

    const settled = await Promise.race([
      ...pending.map((p) => p.promise.then((r) => ({ pending: p, value: r }))),
      sleep(remaining).then(() => null),
    ]);
    if (!settled) {
      // sleep 赢了 → 检查暂存（回到循环顶部）
      continue;
    }
    pending.splice(pending.indexOf(settled.pending), 1);

    if (inProtect) {
      // 保护窗内：ECS+有效 → 立即返回；非ECS+有效 → 暂存
      if (settled.value.ecs && settled.value.result.classification === 'positive') {
        if (opts.acceptFilter && !opts.acceptFilter(settled.value.result.response)) {
          continue;
        }
        return await finishResult(settled.value.result);
      }
      if (settled.value.result.valid) {
        held.push(settled.value);
      }
      continue;
    }

    // 保护窗后：positive 直接返回；negative 暂存，只有没有 positive 时才兜底返回
    if (settled.value.result.classification === 'positive') {
      if (opts.acceptFilter && !opts.acceptFilter(settled.value.result.response)) {
        continue;
      }
      return await finishResult(settled.value.result);
    }
    if (settled.value.result.classification === 'negative') {
      held.push(settled.value);
    }
  }

  // 硬超时：最后检查一次暂存
  if (held.length > 0) {
    sortHeld();
    while (held.length > 0) {
      const bestHeld = held[0];
      if (opts.acceptFilter && !opts.acceptFilter(bestHeld.result.response)) {
        held.shift();
        continue;
      }
      return await finishResult(bestHeld.result);
    }
  }

  abortPending();
  return dnsResponse(servfail(body, 22, 'No reachable upstream'), Date.now() - started);
}

export async function queryUpstream(url, body, started, signal, upstreamName, queryId, ctx = null) {
  try {
    if (queryId === undefined || queryId === null) queryId = body && body.byteLength >= 2 ? new DataView(body).getUint16(0) : 0;
    const queryMeta = parseQueryMeta(body, ctx);
    const response = await fetch(url, { method: 'POST', headers: DNS_HEADERS, body, signal });
    if (response.status !== 200) {
      cancelDnsResponseBody(response);
      return { response: null, time: Date.now() - started, valid: false, classification: 'invalid', rcode: -1, answerCount: 0 };
    }
    const responseBody = await readDnsResponseBody(response);
    const pass = answersPass(responseBody, queryId, queryMeta && queryMeta.name, queryMeta && queryMeta.type, ctx);
    return {
      response: responseBody,
      time: Date.now() - started,
      valid: pass.passed === true && pass.classification !== 'invalid',
      classification: pass.classification || 'invalid',
      rcode: pass.rcode,
      answerCount: pass.answerCount,
    };
  } catch (err) {
    if (err && err.name === 'AbortError') return { response: null, time: Date.now() - started, valid: false, classification: 'invalid' };
    logEvent('error', 'auto_error', ctx, { stage: 'queryUpstream', domain: ctx && ctx.qname || '', upstream: upstreamName || 'unknown', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    return { response: null, time: Date.now() - started, valid: false, classification: 'invalid' };
  }
}

export function answersPass(responseBody, queryId, qname, qtype, ctx = null) {
  const validation = validateResponse(responseBody, queryId, qname, qtype, ctx);
  if (validation.classification === 'invalid') return { passed: false, reason: 'invalid_response', ...validation };
  const result = filterAnswers(responseBody, queryId);
  return { passed: result !== false && result?.passed !== false, reason: result?.reason || null, ...validation };
}

export async function resolvePreferred(domain, type, expectedOwner, ctx, clientIP, upstreams, foreignUpstreams) {
  const ups = upstreams || UPSTREAMS;
  const foreign = foreignUpstreams || FOREIGN_UPSTREAMS;
  const wireQuery = buildWireQuery(domain, type);
  const query = prepareQuery(wireQuery, clientIP);
  const started = Date.now();
  const deadline = started + PREFERRED_TIMEOUT_MS;
  let foreignUrls = foreign.map(function(n) { return ups[n].url; });
  if (AUTO_CONCURRENCY > 0 && AUTO_CONCURRENCY < foreignUrls.length) {
    foreignUrls = foreignUrls.slice(0, AUTO_CONCURRENCY);
  }
  if (foreignUrls.length === 0) return [];

  const controllers = [];
  const collected = [];

  function abortAll() {
    for (let i = 0; i < controllers.length; i++) {
      try { controllers[i].abort(); } catch (_) { /* ignore — abort may throw if already aborted */ }
    }
  }

  const promises = foreignUrls.map(function (url) {
    const ctrl = new AbortController();
    controllers.push(ctrl);
    return fetch(url, {
      method: 'POST',
      headers: DNS_HEADERS,
      body: query,
      signal: ctrl.signal,
    }).then(async function (res) {
      if (res.status !== 200) { cancelDnsResponseBody(res); return null; }
      const buf = await readDnsResponseBody(res);
      const validation = validateResponse(buf, new DataView(wireQuery).getUint16(0), domain, type, ctx);
      if (validation.classification !== 'positive') return null;
      return buf;
    }).then(function (buf) {
      if (!buf) return null;
      try {
        const ips = extractIPBytes(buf, type, ctx);
        for (let i = 0; i < ips.length; i++) {
          collected.push(ips[i]);
        }
      } catch (err) {
        logEvent('error', 'dns_error', ctx, { stage: 'resolvePreferredIPs_extract', domain, errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
      }
      return null;
    }).catch(function (err) {
      if (err && err.name === 'AbortError') return null;
      logEvent('error', 'dns_error', ctx, { stage: 'resolvePreferredIPs_fetch', domain, errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
      return null;
    });
  });

  const timeout = new Promise(function (resolve) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) { resolve(); return; }
    setTimeout(function () { abortAll(); resolve(); }, remaining);
  });

  await Promise.race([Promise.all(promises), timeout]);
  abortAll();

  const ipSet = new Set();
  const allIps = [];
  for (let i = 0; i < collected.length; i++) {
    const key = Array.from(collected[i]).join(',');
    if (!ipSet.has(key)) {
      ipSet.add(key);
      allIps.push(collected[i]);
    }
  }

  if (expectedOwner) {
    try {
      const ownerFiltered = [];
      for (let oi = 0; oi < allIps.length; oi++) {
        const ipBytes = allIps[oi];
        let ipStr;
        if (ipBytes.length === 4) {
          ipStr = ipBytes[0] + '.' + ipBytes[1] + '.' + ipBytes[2] + '.' + ipBytes[3];
        } else if (ipBytes.length === 16) {
          const parts = [];
          for (let pi = 0; pi < 16; pi += 2) {
            parts.push(((ipBytes[pi] << 8) | ipBytes[pi + 1]).toString(16));
          }
          ipStr = parts.join(':');
        }
        if (ipStr && detectOwner(ipStr) === expectedOwner) ownerFiltered.push(ipBytes);
      }
      return ownerFiltered;
    } catch (err) {
      logEvent('error', 'dns_error', ctx, { stage: 'resolvePreferredIPs_owner_filter', domain, errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
      return [];
    }
  }
  return allIps;
}

export async function postProcessBody(responseBody, queryMeta, echActive, ctx) {
  if (!queryMeta) return responseBody;

  if (echActive && queryMeta.type === 65) {
    try {
      let owner = null;
      if (queryMeta.forcedOwner) {
        owner = queryMeta.forcedOwner;
      } else if (isMetaDomain(queryMeta.name, ctx)) {
        owner = 'META';
      } else {
        const ownerResult = await probeOwner(queryMeta.name, ctx);
        if (ownerResult && ownerResult.owner) owner = ownerResult.owner;
      }
      if (owner) {
        if (ctx) ctx.owner = owner;
        let cfEch = null;
        let echStale = false;
        if (owner === 'CF') {
          cfEch = await fetchCFEch(null, ctx);
          if (!cfEch) {
            if (ctx) {
              ctx.echInjected = false;
              ctx.echStatus = 'degraded';
            }
            recordFallback(ctx, { stage: 'cf_ech', owner: 'CF', reason: 'fresh_and_stale_unavailable', from: 'ech_optimized', to: 'original_https_response' });
            return responseBody;
          }
          echStale = !!cfEch.stale;
        }
        if (owner === 'META' && !cfEch) {
          // META uses static ECH (META_ECH_B64) inside injectECH, so cfEch
          // is expected to be null here — this is the normal Meta ECH path.
        }
        const echResult = await injectECH(responseBody, queryMeta.name, owner, cfEch, ctx);
        if (echResult.changed) {
          const bytes = echResult.body instanceof Response ? await echResult.body.arrayBuffer() : echResult.body;
          if (bytes) {
            const echStatus = echStale ? 'stale' : (cfEch ? 'fresh' : 'built');
            if (ctx) {
              ctx.echInjected = true;
              ctx.echStatus = echStatus;
            }
            return bytes;
          }
        } else {
          if (ctx) {
            ctx.echInjected = false;
            ctx.echStatus = 'degraded';
          }
          recordFallback(ctx, { stage: 'ech_injection', owner: owner, reason: 'ech_not_applied_' + echResult.status, from: 'ech_optimized', to: 'original_https_response' });
        }
      }
    } catch (err) {
      if (ctx) {
        ctx.echInjected = false;
        ctx.echStatus = 'failed';
      }
      logEvent('error', 'auto_error', ctx, { stage: 'postProcessBody', domain: queryMeta.name, errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err), fallbackAction: 'return_original_response' });
    }
  }

  return responseBody;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
