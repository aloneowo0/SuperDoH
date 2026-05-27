import { ECS_PRIORITY, HARD_TIMEOUT_MS, MIX_PROVIDER, NO_ECS_PRIORITY, UPSTREAMS } from './config.js';
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
          ? serveHomepageEn(request, UPSTREAMS)
          : serveHomepage(request, UPSTREAMS);
      }
      if (route.error) return jsonError(route.error);
      body = await request.clone().arrayBuffer();
      const clientIP = request.headers.get('CF-Connecting-IP');
      if (route.provider === MIX_PROVIDER) {
        return await concurrentAll(body, clientIP, route.mode, route.queryString);
      }
      return await singleUpstream(route.provider, body, clientIP, route.mode, route.queryString);
    } catch (_) {
      return body ? dnsResponse(servfail(body)) : jsonError('internal_error', 500);
    }
  },
};

async function singleUpstream(provider, body, clientIP, mode, queryString) {
  const upstream = UPSTREAMS[provider];
  if (!upstream) return dnsResponse(servfail(body));
  const modeBody = applyMode(body, clientIP, mode, provider);
  try {
    const response = await fetch(upstream.url, {
      method: 'POST',
      headers: DNS_HEADERS,
      body: modeBody,
    });
    const responseBody = await response.arrayBuffer();
    if (response.status === 200 && answersPass(responseBody)) return dnsResponse(responseBody);
  } catch (_) {}
  return dnsResponse(servfail(body));
}

async function concurrentAll(body, clientIP, mode, queryString) {
  const hasEcs = mode !== 'keep' || detectECS(body);
  const priority = hasEcs ? ECS_PRIORITY : NO_ECS_PRIORITY;
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;

  const pending = priority
    .filter((name) => UPSTREAMS[name])
    .map((name) => ({
      name,
      promise: queryUpstream(name, UPSTREAMS[name].url,
        applyMode(body, clientIP, mode, name), started),
    }));

  const results = [];
  while (pending.length && Date.now() < deadline) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    const settled = await Promise.race([
      ...pending.map((p) => p.promise.then((result) => ({ pending: p, result }))),
      sleep(remaining).then(() => null),
    ]);
    if (!settled) break;
    const idx = pending.indexOf(settled.pending);
    if (idx >= 0) pending.splice(idx, 1);
    results.push(settled.result);
  }

  for (const name of priority) {
    const result = results.find((r) => r.name === name && r.valid);
    if (result) return dnsResponse(result.response);
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

function dnsResponse(body) {
  return new Response(body, { status: 200, headers: DNS_HEADERS });
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
