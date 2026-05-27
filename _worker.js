import { ECS_PROTECT_MS, HARD_TIMEOUT_MS, MIX_PROVIDER, UPSTREAMS } from './config.js';
import { autoMode, detectECS, filterAnswers, keepMode, plusMode } from './edns.js';
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
      if (route.error) return jsonError(route.error);

      const clientIP = request.headers.get('CF-Connecting-IP');
      const acceptHeader = request.headers.get('Accept') || '';
      if (acceptHeader.includes('application/dns-json')) {
        return await rfc8484Passthrough(route, request, clientIP);
      }

      if (request.method === 'GET') {
        body = buildQueryFromURL(new URL(request.url));
        if (!body) return jsonError('missing_name_or_type');
      } else {
        body = await request.clone().arrayBuffer();
      }
      if (route.provider === MIX_PROVIDER) {
        return await concurrentAll(body, clientIP, route.mode, route.queryString);
      }
      return await singleUpstream(route.provider, body, clientIP, route.mode, route.queryString);
    } catch (_) {
      return body ? dnsResponse(servfail(body)) : jsonError('internal_error', 500);
    }
  },
};

function buildQueryFromURL(url) {
  const name = url.searchParams.get('name') || url.searchParams.get('dns');
  if (!name) return null;
  const typeStr = (url.searchParams.get('type') || 'A').toUpperCase();
  const typeMap = { A: 1, AAAA: 28, TXT: 16, MX: 15, CNAME: 5, NS: 2, SOA: 6, PTR: 12 };
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

async function rfc8484Passthrough(route, request, clientIP) {
  const target = route.provider === MIX_PROVIDER
    ? Object.values(UPSTREAMS)[0]
    : UPSTREAMS[route.provider];
  if (!target) return jsonError('unknown_provider');

  const url = new URL(target.url + route.queryString);
  const upstreamReq = new Request(url, {
    method: request.method,
    headers: {
      'Accept': 'application/dns-json',
      'Content-Type': request.headers.get('Content-Type') || 'application/dns-json',
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

async function singleUpstream(provider, body, clientIP, mode, queryString) {
  const upstream = UPSTREAMS[provider];
  if (!upstream) return dnsResponse(servfail(body));
  const modeBody = applyMode(body, clientIP, mode, provider);
  const started = Date.now();
  try {
    const response = await fetch(upstream.url, {
      method: 'POST',
      headers: DNS_HEADERS,
      body: modeBody,
    });
    const responseBody = await response.arrayBuffer();
    const elapsed = Date.now() - started;
    if (response.status === 200 && answersPass(responseBody)) return dnsResponse(responseBody, elapsed);
  } catch (_) {}
  return dnsResponse(servfail(body));
}

async function concurrentAll(body, clientIP, mode, queryString) {
  const hasEcs = mode !== 'keep' || detectECS(body);
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;
  const protectEnd = hasEcs ? started + ECS_PROTECT_MS : 0;

  // Fire all upstreams concurrently, each wrapped to capture result
  const pending = Object.entries(UPSTREAMS).map(([name, cfg]) => ({
    name,
    ecs: cfg.ecs,
    promise: queryUpstream(name, cfg.url, applyMode(body, clientIP, mode, name), started)
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

  return dnsResponse(servfail(body));
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

function applyMode(body, clientIP, mode, provider) {
  const caps = UPSTREAMS[provider] || {};
  if (mode === 'plus' && caps.plus) return plusMode(body, clientIP);
  if (mode === 'auto' && caps.ecs) return autoMode(body, clientIP);
  return keepMode(body);
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function servfail(originalBody) {
  const id = originalBody && originalBody.byteLength >= 2 ? new DataView(originalBody).getUint16(0) : 0;
  const buf = new ArrayBuffer(12);
  const out = new DataView(buf);
  out.setUint16(0, id);
  out.setUint16(2, 0x8182);
  for (let offset = 4; offset < 12; offset += 2) out.setUint16(offset, 0);
  return buf;
}
