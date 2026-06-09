/** Multi-upstream racing module — ECS protect window + post-processing */
import { ECS_PROTECT_MS, HARD_TIMEOUT_MS, UPSTREAMS } from './config.js';
import { prepareQuery, filterAnswers } from './edns.js';
import { fetchCFEch, injectECH } from './ech.js';
import { probeOwner, isMetaDomain } from './cdn.js';
import { dnsResponse, servfail } from './dns-lib.js';
import { logEvent } from './logger.js';

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };
var _lastKnownCfEch = null;

export async function concurrentAll(body, clientIP, queryMeta, echActive, activePref, preferredCft, preferredVrc, options, ctx) {
  var opts = options || {};
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;
  const protectEnd = started + ECS_PROTECT_MS;

  const effectiveBody = opts.overrideBody || body;
  const preparedBody = prepareQuery(effectiveBody, clientIP);

  const pending = Object.entries(UPSTREAMS).map(([name, cfg]) => {
    const ctrl = new AbortController();
    return {
      ecs: cfg.ecs,
      ctrl,
      promise: queryUpstream(cfg.url, preparedBody, started, ctrl.signal, name)
        .then((r) => ({ ecs: cfg.ecs, result: r })),
    };
  });

  const held = [];

  function abortPending() {
    for (const p of pending) {
      try { p.ctrl.abort(); } catch (_) {}
    }
  }

  while (pending.length && Date.now() < deadline) {
    const inProtect = Date.now() < protectEnd;

    // 保护窗到期先检查暂存：释放最快的那条
    if (!inProtect && held.length > 0) {
      held.sort((a, b) => a.result.time - b.result.time);
      var bestHeld = held[0];
      if (opts.acceptFilter && !opts.acceptFilter(bestHeld.result.response)) {
        held.shift();
        continue;
      }
      var processed;
      if (opts.skipPostProcess) {
        abortPending();
        processed = bestHeld.result.response;
      } else {
        abortPending();
        processed = await postProcessBody(bestHeld.result.response, queryMeta, echActive, activePref, preferredCft, preferredVrc, ctx);
      }
      return dnsResponse(processed, bestHeld.result.time);
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
      if (settled.value.ecs && settled.value.result.valid) {
        if (opts.acceptFilter && !opts.acceptFilter(settled.value.result.response)) {
          continue;
        }
        var processed;
        if (opts.skipPostProcess) {
          abortPending();
          processed = settled.value.result.response;
        } else {
          abortPending();
          processed = await postProcessBody(settled.value.result.response, queryMeta, echActive, activePref, preferredCft, preferredVrc, ctx);
        }
        return dnsResponse(processed, settled.value.result.time);
      }
      if (settled.value.result.valid) {
        held.push(settled.value);
      }
      continue;
    }

    // 保护窗后：任意有效响应直接返回
    if (settled.value.result.valid) {
      if (opts.acceptFilter && !opts.acceptFilter(settled.value.result.response)) {
        continue;
      }
      var processed;
      if (opts.skipPostProcess) {
        abortPending();
        processed = settled.value.result.response;
      } else {
        abortPending();
        processed = await postProcessBody(settled.value.result.response, queryMeta, echActive, activePref, preferredCft, preferredVrc, ctx);
      }
      return dnsResponse(processed, settled.value.result.time);
    }
  }

  // 硬超时：最后检查一次暂存
  if (held.length > 0) {
    held.sort((a, b) => a.result.time - b.result.time);
    while (held.length > 0) {
      var bestHeld = held[0];
      if (opts.acceptFilter && !opts.acceptFilter(bestHeld.result.response)) {
        held.shift();
        continue;
      }
      var processed;
      if (opts.skipPostProcess) {
        abortPending();
        processed = bestHeld.result.response;
      } else {
        abortPending();
        processed = await postProcessBody(bestHeld.result.response, queryMeta, echActive, activePref, preferredCft, preferredVrc, ctx);
      }
      return dnsResponse(processed, bestHeld.result.time);
    }
  }

  return dnsResponse(servfail(body, 22, 'No reachable upstream'), Date.now() - started);
}

export async function queryUpstream(url, body, started, signal, upstreamName) {
  try {
    const response = await fetch(url, { method: 'POST', headers: DNS_HEADERS, body, signal });
    const responseBody = await response.arrayBuffer();
    return {
      response: responseBody,
      time: Date.now() - started,
      valid: response.status === 200 && answersPass(responseBody),
    };
  } catch (err) {
    if (err && err.name === 'AbortError') return { response: null, time: Date.now() - started, valid: false };
    logEvent('error', 'mix_error', { stage: 'queryUpstream', upstream: upstreamName || 'unknown', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    return { response: null, time: Date.now() - started, valid: false };
  }
}

export function answersPass(responseBody) {
  const result = filterAnswers(responseBody);
  return result !== false && result?.passed !== false;
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
          if (!cfEch && _lastKnownCfEch && _lastKnownCfEch.expires > Date.now()) {
            cfEch = _lastKnownCfEch.data;
            echStale = true;
            logEvent('warn', 'ech_result', { requestId: ctx && ctx.requestId, owner: 'CF', status: 'stale', reason: 'using_last_known_good' });
          }
          if (!cfEch) {
            logEvent('warn', 'fallback', { requestId: ctx && ctx.requestId, stage: 'cf_ech', owner: 'CF', reason: 'fresh_and_stale_unavailable', from: 'ech_optimized', to: 'original_https_response' });
            logEvent('warn', 'ech_result', { requestId: ctx && ctx.requestId, owner: 'CF', status: 'degraded', reason: 'ech_fetch_failed' });
            return responseBody;
          }
          if (!echStale) {
            _lastKnownCfEch = { data: cfEch, expires: Date.now() + 3600000 };
          }
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
