import { GRACE_WINDOW_MS, HARD_TIMEOUT_MS, MIX_PROVIDER, UPSTREAMS } from './config.js';
import { autoMode, filterAnswers, keepMode, plusMode } from './edns.js';
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
          ? serveHomepageEn(request, upstreamNames)
          : serveHomepage(request, upstreamNames);
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
  const modeBody = applyMode(body, clientIP, mode);
  try {
    const response = await fetch(upstream + queryString, {
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
  const modeBody = applyMode(body, clientIP, mode);
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;
  const pending = Object.entries(UPSTREAMS).map(([name, url]) => {
    const item = {};
    item.promise = queryUpstream(name, url + queryString, modeBody, started).then((result) => ({ item, result }));
    return item;
  });
  const results = [];
  let graceDone = false;
  while (pending.length && Date.now() < deadline) {
    const settled = await racePending(pending, deadline - Date.now());
    if (!settled) break;
    removePending(pending, settled.item);
    results.push(settled.result);
    if (!graceDone) {
      await collectDuring(pending, results, Math.min(GRACE_WINDOW_MS, deadline - Date.now()));
      graceDone = true;
      const best = fastestValid(results);
      if (best) return dnsResponse(best.response);
    } else if (settled.result.valid) {
      return dnsResponse(settled.result.response);
    }
  }
  const best = fastestValid(results);
  return dnsResponse(best ? best.response : servfail(body));
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
async function collectDuring(pending, results, ms) {
  const end = Date.now() + Math.max(0, ms);
  while (pending.length && Date.now() < end) {
    const settled = await racePending(pending, end - Date.now());
    if (!settled) return;
    removePending(pending, settled.item);
    results.push(settled.result);
  }
}
function racePending(pending, ms) {
  return Promise.race([
    ...pending.map((item) => item.promise),
    sleep(Math.max(0, ms)).then(() => null),
  ]);
}
function removePending(pending, item) {
  const index = pending.indexOf(item);
  if (index >= 0) pending.splice(index, 1);
}
function fastestValid(results) {
  return results
    .filter((result) => result.valid)
    .sort((a, b) => a.time - b.time)[0];
}
function applyMode(body, clientIP, mode) {
  if (mode === 'plus') return plusMode(body, clientIP);
  if (mode === 'auto') return autoMode(body, clientIP);
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
