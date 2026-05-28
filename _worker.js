import { ECS_PROTECT_MS, HARD_TIMEOUT_MS, MIX_PROVIDER, UPSTREAMS } from './config.js';
import { prepareQuery, filterAnswers } from './edns.js';
import { serveHomepage, serveHomepageEn } from './homepage.js';
import { resolveRoute } from './router.js';

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };
const JSON_HEADERS = { 'Content-Type': 'application/json;charset=utf-8' };

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
      if (route.provider === MIX_PROVIDER) {
        return await concurrentAll(body, clientIP);
      }
      return await singleUpstream(route.provider, body, clientIP);
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

async function singleUpstream(provider, body, clientIP) {
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
    if (response.status === 200 && answersPass(responseBody)) return dnsResponse(responseBody, elapsed);
    return dnsResponse(servfail(body, 17, 'Filtered'), elapsed);
  } catch (_) {}
  return dnsResponse(servfail(body));
}

async function concurrentAll(body, clientIP) {
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;
  const protectEnd = started + ECS_PROTECT_MS;

  // Fire all upstreams concurrently, each wrapped to capture result
  const pending = Object.entries(UPSTREAMS).map(([name, cfg]) => ({
    name,
    ecs: cfg.ecs,
    promise: queryUpstream(name, cfg.url, prepareQuery(body, clientIP), started)
      .then((r) => ({ ecs: cfg.ecs, result: r })),
  }));

  while (pending.length && Date.now() < deadline) {
    const remaining = Math.min(protectEnd > Date.now() ? protectEnd : deadline, deadline) - Date.now();
    if (remaining <= 0) break;
    const settled = await Promise.race([
      ...pending.map((p) => p.promise.then((r) => ({ pending: p, value: r }))),
      sleep(remaining).then(() => null),
    ]);
    if (!settled) break;
    pending.splice(pending.indexOf(settled.pending), 1);

    if (protectEnd && Date.now() < protectEnd) {
      // Protection window: only return valid ECS responses
      if (settled.value.ecs && settled.value.result.valid) {
        return dnsResponse(settled.value.result.response, settled.value.result.time);
      }
      continue;
    }

    // After protection: any valid response wins
    if (settled.value.result.valid) {
      return dnsResponse(settled.value.result.response, settled.value.result.time);
    }
  }

  return dnsResponse(servfail(body, 22, 'No reachable upstream'), Date.now() - started);
}

async function queryUpstream(name, url, body, started) {
  try {
    const response = await fetch(url, { method: 'POST', headers: DNS_HEADERS, body });
    const responseBody = await response.arrayBuffer();
    return {
      name,
      response: responseBody,
      time: Date.now() - started,
      valid: response.status === 200 && answersPass(responseBody),
    };
  } catch (_) {
    return { name, response: null, time: Date.now() - started, valid: false };
  }
}

function answersPass(responseBody) {
  const result = filterAnswers(responseBody);
  return result !== false && result?.passed !== false;
}

function dnsResponse(body, upstreamTime) {
  const headers = upstreamTime != null
    ? { ...DNS_HEADERS, 'X-Upstream-Time': String(upstreamTime) }
    : DNS_HEADERS;
  return new Response(body, { status: 200, headers });
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
  }), { headers: JSON_HEADERS });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function servfail(originalBody, edeCode = 0, edeText = '') {
  const id = originalBody && originalBody.byteLength >= 2 ? new DataView(originalBody).getUint16(0) : 0;
  const textBytes = new TextEncoder().encode(edeText);
  const edeOptionLen = edeCode ? (4 + textBytes.length) : 0;

  const headerLen = 12;
  const qdEnd = skipQuestion(originalBody);
  const qdBytes = qdEnd > headerLen ? new Uint8Array(originalBody.slice(headerLen, qdEnd)) : new Uint8Array(0);

  const arcount = edeCode ? 1 : 0;
  const optLen = edeCode ? (11 + edeOptionLen) : 0;
  const total = headerLen + qdBytes.length + optLen;
  const buf = new ArrayBuffer(total);
  const out = new DataView(buf);
  const bytes = new Uint8Array(buf);

  out.setUint16(0, id);
  out.setUint16(2, 0x8182);
  out.setUint16(4, 1);
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
