/** Multi-upstream racing module — ECS protect window + post-processing */
import { ECS_PROTECT_MS, HARD_TIMEOUT_MS, UPSTREAMS } from './config.js';
import { prepareQuery, filterAnswers, validateResponse } from './edns.js';
import { fetchCFEch, injectECH } from './ech.js';
import { probeOwner, isMetaDomain } from './cdn.js';
import { dnsResponse, parseQueryMeta, servfail } from './dns-lib.js';
import { logEvent } from './logger.js';

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };

export async function concurrentAll(body, clientIP, queryMeta, echActive, activePref, preferredCft, preferredVrc, options, ctx) {
  var opts = options || {};
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;
  const protectEnd = started + ECS_PROTECT_MS;

  const effectiveBody = opts.overrideBody || body;
  const queryId = effectiveBody && effectiveBody.byteLength >= 2 ? new DataView(effectiveBody).getUint16(0) : 0;
  const preparedBody = prepareQuery(effectiveBody, clientIP);

  const pending = Object.entries(UPSTREAMS).map(([name, cfg]) => {
    const ctrl = new AbortController();
    return {
      ecs: cfg.ecs,
      ctrl,
      promise: queryUpstream(cfg.url, preparedBody, started, ctrl.signal, name, queryId)
        .then((r) => ({ ecs: cfg.ecs, result: r })),
    };
  });

  const held = [];

  function abortPending() {
    for (const p of pending) {
      try { p.ctrl.abort(); } catch (_) {}
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
    var processed;
    if (opts.skipPostProcess) {
      abortPending();
      processed = result.response;
    } else {
      abortPending();
      processed = await postProcessBody(result.response, queryMeta, echActive, activePref, preferredCft, preferredVrc, ctx);
    }
    return dnsResponse(processed, result.time);
  }

  while (pending.length && Date.now() < deadline) {
    const inProtect = Date.now() < protectEnd;

    // 保护窗到期先检查暂存：释放最快的那条
    if (!inProtect && held.some((item) => item.result.classification === 'positive')) {
      sortHeld();
      var bestHeld = held[0];
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
      var bestHeld = held[0];
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

export async function queryUpstream(url, body, started, signal, upstreamName, queryId) {
  try {
    if (queryId === undefined || queryId === null) queryId = body && body.byteLength >= 2 ? new DataView(body).getUint16(0) : 0;
    const queryMeta = parseQueryMeta(body);
    const response = await fetch(url, { method: 'POST', headers: DNS_HEADERS, body, signal });
    const responseBody = await response.arrayBuffer();
    const pass = response.status === 200 ? answersPass(responseBody, queryId, queryMeta && queryMeta.name, queryMeta && queryMeta.type) : { passed: false, classification: 'invalid', rcode: -1, answerCount: 0 };
    return {
      response: responseBody,
      time: Date.now() - started,
      valid: response.status === 200 && pass.passed === true && pass.classification !== 'invalid',
      classification: pass.classification || 'invalid',
      rcode: pass.rcode,
      answerCount: pass.answerCount,
    };
  } catch (err) {
    if (err && err.name === 'AbortError') return { response: null, time: Date.now() - started, valid: false, classification: 'invalid' };
    logEvent('error', 'mix_error', { stage: 'queryUpstream', upstream: upstreamName || 'unknown', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    return { response: null, time: Date.now() - started, valid: false, classification: 'invalid' };
  }
}

export function answersPass(responseBody, queryId, qname, qtype) {
  const validation = validateResponse(responseBody, queryId, qname, qtype);
  if (validation.classification === 'invalid') return { passed: false, reason: 'invalid_response', ...validation };
  const result = filterAnswers(responseBody, queryId);
  return { passed: result !== false && result?.passed !== false, reason: result?.reason || null, ...validation };
}

export async function postProcessBody(responseBody, queryMeta, echActive, activePref, preferredCft, preferredVrc, ctx) {
  if (!queryMeta) return responseBody;
  void activePref;
  void preferredCft;
  void preferredVrc;

  if (echActive && queryMeta.type === 65) {
    try {
      var owner = null;
      if (queryMeta._knownCF) {
        owner = 'CF';
      } else if (queryMeta.forcedOwner) {
        owner = queryMeta.forcedOwner;
      } else if (isMetaDomain(queryMeta.name)) {
        owner = 'META';
      } else {
        const ownerResult = await probeOwner(queryMeta.name);
        if (ownerResult && ownerResult.owner) owner = ownerResult.owner;
      }
      if (owner) {
        var cfEch = null;
        var echStale = false;
        if (owner === 'CF') {
          cfEch = await fetchCFEch(null, null);
          if (!cfEch) {
            logEvent('warn', 'fallback', { requestId: ctx && ctx.requestId, stage: 'cf_ech', owner: 'CF', reason: 'fresh_and_stale_unavailable', from: 'ech_optimized', to: 'original_https_response' });
            logEvent('warn', 'ech_result', { requestId: ctx && ctx.requestId, owner: 'CF', status: 'degraded', reason: 'ech_fetch_failed' });
            return responseBody;
          }
          echStale = !!cfEch.stale;
        }
        if (owner === 'META' && !cfEch) {
          // META uses static ECH (META_ECH_B64) inside injectECH, so cfEch
          // is expected to be null here — this is the normal Meta ECH path.
        }
        var echResult = await injectECH(responseBody, queryMeta.name, owner, cfEch, ctx);
        if (echResult.changed) {
          var bytes = echResult.body instanceof Response ? await echResult.body.arrayBuffer() : echResult.body;
          if (bytes) {
            var echStatus = echStale ? 'stale' : (cfEch ? 'fresh' : 'built');
            logEvent(echStatus === 'degraded' ? 'warn' : 'info', 'ech_result', { requestId: ctx && ctx.requestId, owner: owner, status: echStatus, reason: echStatus === 'degraded' ? 'ech_fetch_failed' : '' });
            return bytes;
          }
        } else {
          logEvent('warn', 'fallback', { requestId: ctx && ctx.requestId, stage: 'ech_injection', owner: owner, reason: 'ech_not_applied_' + echResult.status, from: 'ech_optimized', to: 'original_https_response' });
          logEvent('warn', 'ech_result', { requestId: ctx && ctx.requestId, owner: owner, status: 'degraded', reason: 'ech_not_applied_' + echResult.status });
        }
      }
    } catch (err) {
      logEvent('error', 'mix_error', { requestId: ctx && ctx.requestId, stage: 'postProcessBody', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err), fallbackAction: 'return_original_response' });
    }
  }

  return responseBody;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
