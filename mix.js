/** Multi-upstream racing module — ECS protect window + post-processing */
import { ECS_PROTECT_MS, HARD_TIMEOUT_MS, UPSTREAMS } from './config.js';
import { prepareQuery, filterAnswers } from './edns.js';
import { fetchCFEch, injectECH } from './ech.js';
import { probeOwner, detectOwner, extractIps, resolvePreferredIPs } from './special-domain.js';
import { dnsResponse, buildDNS, servfail } from './dns-lib.js';

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };

export async function concurrentAll(body, clientIP, queryMeta, regionActive, activePref) {
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;
  const protectEnd = started + ECS_PROTECT_MS;

  const preparedBody = prepareQuery(body, clientIP);

  const pending = Object.entries(UPSTREAMS).map(([, cfg]) => {
    const ctrl = new AbortController();
    return {
      ecs: cfg.ecs,
      ctrl,
      promise: queryUpstream(cfg.url, preparedBody, started, ctrl.signal)
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
      const best = held[0];
      const processed = await postProcessBody(best.result.response, queryMeta, regionActive, activePref);
      abortPending();
      return dnsResponse(processed, best.result.time);
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
        const processed = await postProcessBody(settled.value.result.response, queryMeta, regionActive, activePref);
        abortPending();
        return dnsResponse(processed, settled.value.result.time);
      }
      if (settled.value.result.valid) {
        held.push(settled.value);
      }
      continue;
    }

    // 保护窗后：任意有效响应直接返回
    if (settled.value.result.valid) {
      const processed = await postProcessBody(settled.value.result.response, queryMeta, regionActive, activePref);
      abortPending();
      return dnsResponse(processed, settled.value.result.time);
    }
  }

  // 硬超时：最后检查一次暂存
  if (held.length > 0) {
    held.sort((a, b) => a.result.time - b.result.time);
    const processed = await postProcessBody(held[0].result.response, queryMeta, regionActive, activePref);
    abortPending();
    return dnsResponse(processed, held[0].result.time);
  }

  return dnsResponse(servfail(body, 22, 'No reachable upstream'), Date.now() - started);
}

export async function queryUpstream(url, body, started, signal) {
  try {
    const response = await fetch(url, { method: 'POST', headers: DNS_HEADERS, body, signal });
    const responseBody = await response.arrayBuffer();
    return {
      response: responseBody,
      time: Date.now() - started,
      valid: response.status === 200 && answersPass(responseBody),
    };
  } catch (_) {
    return { response: null, time: Date.now() - started, valid: false };
  }
}

export function answersPass(responseBody) {
  const result = filterAnswers(responseBody);
  return result !== false && result?.passed !== false;
}

export async function postProcessBody(responseBody, queryMeta, regionActive, activePref) {
  if (!queryMeta) return responseBody;

  if (regionActive && queryMeta.type === 65) {
    try {
      const cfEch = await fetchCFEch(null, null);
      const ownerResult = await probeOwner(queryMeta.name);
      if (ownerResult && ownerResult.owner) {
        const injected = await injectECH(responseBody, queryMeta.name, ownerResult.owner, cfEch);
        if (injected) {
          const bytes = injected instanceof Response ? await injected.arrayBuffer() : injected;
          if (bytes) return bytes;
        }
      }
    } catch (_) {}
  }

  if (activePref && (queryMeta.type === 1 || queryMeta.type === 28)) {
    try {
      const ips = extractIps(responseBody);
      if (ips.some(function (ip) { return detectOwner(ip) === 'CF'; })) {
        const preferred = await resolvePreferredIPs(activePref, queryMeta.type);
        if (preferred && preferred.length > 0) {
          return buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, preferred, 60);
        }
      }
    } catch (_) {}
  }

  return responseBody;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}


