import { ECS_PROTECT_MS, HARD_TIMEOUT_MS, MIX_PROVIDER, UPSTREAMS, REGION, REGION_CONFIG } from './config.js';
import { prepareQuery, filterAnswers } from './edns.js';
import { serveHomepage, serveHomepageEn } from './homepage.js';
import { resolveRoute } from './router.js';
import { fetchCFEch, injectECH } from './ech-inject.js';
import { shouldRemap, remapResponse, resolvePreferredIPs } from './domain-map.js';
import { probeOwner } from './cdn-detect.js';

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };
const JSON_HEADERS = { 'Content-Type': 'application/json;charset=utf-8' };

let _regionActive = false;

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

      const acceptHeader = request.headers.get('Accept') || '';
      if (acceptHeader.includes('application/dns-json')) {
        return await rfc8484Passthrough(route, request);
      }

      // Global auto: build body, inject EDNS, forward
      if (request.method === 'GET') {
        body = buildQueryFromURL(new URL(request.url));
        if (!body) return jsonError('missing_name_or_type');
      } else {
        body = await request.clone().arrayBuffer();
      }
      const clientIP = request.headers.get('CF-Connecting-IP');
      const queryMeta = parseQueryMeta(body);
      const clientCountry = request.cf && request.cf.country || '';
      const regionCfg = REGION_CONFIG && REGION_CONFIG[clientCountry];
      const regionActive = !!(regionCfg && regionCfg.preferred);
      _regionActive = !!(regionCfg && regionCfg.ech);
      const activePref = regionCfg ? regionCfg.preferred : '';

      const remapDomains = regionCfg ? regionCfg.remap.map(d => d.toLowerCase()) : [];
      if (queryMeta && regionActive && remapDomains.some(d => queryMeta.name === d || queryMeta.name.endsWith('.' + d))) {
        let echRdata = null;
        if (queryMeta.type === 65) {
          const cfEch = await fetchCFEch(null, null);
          if (cfEch && cfEch.rdata) echRdata = cfEch.rdata;
        }
        const remapped = await remapResponse(body, queryMeta.name, queryMeta.type, activePref, echRdata);
        if (remapped !== null) return dnsResponse(remapped);
      }
      if (regionActive && queryMeta && queryMeta.type === 65 && isMetaDomain(queryMeta.name)) {
        const injected = await injectECH(body, queryMeta.name, 'META', null);
        if (injected) {
          const bytes = injected instanceof Response ? await injected.arrayBuffer() : injected;
          if (bytes) return dnsResponse(bytes);
        }
      }
      if (queryMeta && isMetaDomain(queryMeta.name) && (queryMeta.type === 1 || queryMeta.type === 28)) {
        const ips = await resolvePreferredIPs(queryMeta.name, queryMeta.type);
        if (ips && ips.length > 0) return dnsResponse(buildDNS(queryMeta.id, queryMeta.name, queryMeta.type, ips, 300));
      }
      if (route.provider === MIX_PROVIDER) {
        return await concurrentAll(body, clientIP, queryMeta);
      }
      return await singleUpstream(route.provider, body, clientIP, queryMeta);
    } catch (_) {
      return body ? dnsResponse(servfail(body)) : jsonError('internal_error', 500);
    }
  },
};

function buildQueryFromURL(url) {
  const dnsParam = url.searchParams.get('dns');
  if (dnsParam) {
    try {
      const b64 = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
      const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      return bin.buffer;
    } catch (_) {}
  }

  const name = url.searchParams.get('name');
  if (!name) return null;
  const typeStr = (url.searchParams.get('type') || 'A').toUpperCase();
  const typeMap = { A: 1, AAAA: 28, TXT: 16, MX: 15, CNAME: 5, NS: 2, SOA: 6, PTR: 12, HTTPS: 65, SVCB: 64 };
  const qtype = typeMap[typeStr] || 1;

  const buf = new ArrayBuffer(12);
  const view = new DataView(buf);
  view.setUint16(0, Math.floor(Math.random() * 65536));
  view.setUint16(2, 0x0100);
  view.setUint16(4, 1);
  view.setUint16(6, 0);
  view.setUint16(8, 0);
  view.setUint16(10, 0);

  const labels = name.replace(/\.+$/, '').split('.');
  const nameBytes = [];
  for (const label of labels) {
    if (label.length > 63) return null;
    nameBytes.push(label.length);
    for (let i = 0; i < label.length; i++) nameBytes.push(label.charCodeAt(i));
  }
  nameBytes.push(0);

  const question = new ArrayBuffer(4);
  const qv = new DataView(question);
  qv.setUint16(0, qtype);
  qv.setUint16(2, 1);

  const total = 12 + nameBytes.length + 4;
  const out = new Uint8Array(total);
  out.set(new Uint8Array(buf), 0);
  out.set(nameBytes, 12);
  out.set(new Uint8Array(question), 12 + nameBytes.length);
  return out.buffer;
}

function parseQueryMeta(body) {
  try {
    const bytes = body instanceof ArrayBuffer ? new Uint8Array(body) : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    if (bytes.length < 12) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const id = view.getUint16(0);
    let offset = 12;
    const labels = [];
    for (let jumps = 0; jumps < 128; jumps++) {
      if (offset >= bytes.length) return null;
      const len = bytes[offset];
      if ((len & 0xC0) === 0xC0) { offset += 2; break; }
      if (len === 0) { offset++; break; }
      offset++;
      labels.push(new TextDecoder().decode(bytes.subarray(offset, offset + len)));
      offset += len;
    }
    const qType = view.getUint16(offset);
    return { id, name: labels.join('.').toLowerCase(), type: qType };
  } catch (_) {
    return null;
  }
}

async function rfc8484Passthrough(route, request) {
  let target = route.provider === MIX_PROVIDER
    ? (UPSTREAMS['google'] || Object.values(UPSTREAMS)[0])
    : UPSTREAMS[route.provider];
  if (!target) return jsonError('unknown_provider');

  const jsonUrl = target.url.includes('dns.google/dns-query')
    ? 'https://dns.google/resolve'
    : target.url;

  const query = route.queryString;
  const upstreamReq = new Request(jsonUrl + query, {
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

async function singleUpstream(provider, body, clientIP, queryMeta) {
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
    if (_regionActive && queryMeta && queryMeta.type === 65) {
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
    if (response.status === 200 && answersPass(finalBody)) return dnsResponse(finalBody, elapsed);
    return dnsResponse(servfail(body, 17, 'Filtered'), elapsed);
  } catch (_) {}
  return dnsResponse(servfail(body));
}

async function concurrentAll(body, clientIP, queryMeta) {
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;
  const protectEnd = started + ECS_PROTECT_MS;

  // Fire all upstreams concurrently, each wrapped to capture result
  const pending = Object.entries(UPSTREAMS).map(([name, cfg]) => ({
    ecs: cfg.ecs,
    promise: queryUpstream(cfg.url, prepareQuery(body, clientIP), started)
      .then((r) => ({ ecs: cfg.ecs, result: r })),
  }));

  const held = [];  // 暂存区：保护窗内到达的非ECS有效响应

  while (pending.length && Date.now() < deadline) {
    const inProtect = Date.now() < protectEnd;

    // 保护窗到期先检查暂存：释放最快的那条
    if (!inProtect && held.length > 0) {
      held.sort((a, b) => a.result.time - b.result.time);
      const best = held[0];
      const processed = await postProcessBody(best.result.response, queryMeta);
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
        const processed = await postProcessBody(settled.value.result.response, queryMeta);
        return dnsResponse(processed, settled.value.result.time);
      }
      if (settled.value.result.valid) {
        held.push(settled.value);
      }
      continue;
    }

    // 保护窗后：任意有效响应直接返回
    if (settled.value.result.valid) {
      const processed = await postProcessBody(settled.value.result.response, queryMeta);
      return dnsResponse(processed, settled.value.result.time);
    }
  }

  // 硬超时：最后检查一次暂存
  if (held.length > 0) {
    held.sort((a, b) => a.result.time - b.result.time);
    const processed = await postProcessBody(held[0].result.response, queryMeta);
    return dnsResponse(processed, held[0].result.time);
  }

  return dnsResponse(servfail(body, 22, 'No reachable upstream'), Date.now() - started);
}

async function queryUpstream(url, body, started) {
  try {
    const response = await fetch(url, { method: 'POST', headers: DNS_HEADERS, body });
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

function answersPass(responseBody) {
  const result = filterAnswers(responseBody);
  return result !== false && result?.passed !== false;
}

async function postProcessBody(responseBody, queryMeta) {
  if (!_regionActive || !queryMeta || queryMeta.type !== 65) return responseBody;
  try {
    const ownerResult = await probeOwner(queryMeta.name);
    if (!ownerResult || !ownerResult.owner) return responseBody;
    const cfEch = await fetchCFEch(null, null);
    const injected = await injectECH(responseBody, queryMeta.name, ownerResult.owner, cfEch);
    if (injected) {
      const bytes = injected instanceof Response ? await injected.arrayBuffer() : injected;
      if (bytes) return bytes;
    }
  } catch (_) {}
  return responseBody;
}

function isMetaDomain(name) {
  const domains = ['facebook.com','fbcdn.net','instagram.com','cdninstagram.com','messenger.com','whatsapp.com','whatsapp.net','threads.net','meta.com','oculus.com','fbsbx.com','thefacebook.com','connect.facebook.net'];
  try {
    return domains.some(function (d) { return name === d || name.endsWith('.' + d); });
  } catch (_) { return false; }
}

function dnsResponse(body, upstreamTime) {
  const headers = upstreamTime != null
    ? { ...DNS_HEADERS, 'X-Upstream-Time': String(upstreamTime) }
    : DNS_HEADERS;
  return new Response(body, { status: 200, headers });
}

function buildDNS(id, qName, qType, rdataList, ttl) {
  const labels = qName.replace(/\.+$/, '').split('.');
  const nameBytes = [];
  for (const label of labels) {
    if (label.length > 63) break;
    nameBytes.push(label.length);
    for (let i = 0; i < label.length; i++) nameBytes.push(label.charCodeAt(i));
  }
  nameBytes.push(0);

  let totalLen = 12 + nameBytes.length + 4;
  for (const rd of rdataList) totalLen += 12 + rd.length;

  const buf = new ArrayBuffer(totalLen);
  const bytes = new Uint8Array(buf);
  const view = new DataView(buf);
  view.setUint16(0, id);
  view.setUint16(2, 0x8180);
  view.setUint16(4, 1);
  view.setUint16(6, rdataList.length);
  view.setUint16(8, 0);
  view.setUint16(10, 0);

  let offset = 12;
  bytes.set(nameBytes, offset); offset += nameBytes.length;
  view.setUint16(offset, qType); offset += 2;
  view.setUint16(offset, 1); offset += 2;

  for (const rd of rdataList) {
    view.setUint16(offset, 0xC00C); offset += 2;
    view.setUint16(offset, qType); offset += 2;
    view.setUint16(offset, 1); offset += 2;
    view.setUint32(offset, ttl); offset += 4;
    view.setUint16(offset, rd.length); offset += 2;
    bytes.set(rd, offset); offset += rd.length;
  }
  return buf;
}

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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function servfail(originalBody, edeCode = 0, edeText = '') {
  const id = originalBody && originalBody.byteLength >= 2 ? new DataView(originalBody).getUint16(0) : 0;
  const textBytes = new TextEncoder().encode(edeText);
  const edeOptionLen = edeCode ? (6 + textBytes.length) : 0;

  const headerLen = 12;
  const qdEnd = skipQuestion(originalBody);
  const qdBytes = qdEnd > headerLen ? new Uint8Array(originalBody.slice(headerLen, qdEnd)) : new Uint8Array(0);

  const arcount = edeCode ? 1 : 0;
  const optLen = edeCode ? (11 + edeOptionLen) : 0;
  const total = headerLen + qdBytes.length + optLen;
  const buf = new ArrayBuffer(total);
  const out = new DataView(buf);
  const bytes = new Uint8Array(buf);

  const qdcount = qdBytes.length > 0 ? 1 : 0;
  out.setUint16(0, id);
  out.setUint16(2, 0x8182);
  out.setUint16(4, qdcount);
  out.setUint16(6, 0);
  out.setUint16(8, 0);
  out.setUint16(10, arcount);
  bytes.set(qdBytes, headerLen);

  if (edeCode) {
    const off = headerLen + qdBytes.length;
    bytes[off] = 0;
    out.setUint16(off + 1, 41);
    out.setUint16(off + 3, 4096);
    out.setUint32(off + 5, 0);
    out.setUint16(off + 9, edeOptionLen);
    out.setUint16(off + 11, 15);
    out.setUint16(off + 13, 2 + textBytes.length);
    out.setUint16(off + 15, edeCode);
    if (textBytes.length) bytes.set(textBytes, off + 17);
  }

  return buf;
}

function skipQuestion(body) {
  if (!body || body.byteLength < 12) return 12;
  let off = 12;
  const bytes = new Uint8Array(body);
  while (off < bytes.length) {
    const len = bytes[off];
    if (len === 0) return off + 1 + 4;
    if (len & 0xC0) return off + 2 + 4;
    off += 1 + len;
  }
  return 12;
}
