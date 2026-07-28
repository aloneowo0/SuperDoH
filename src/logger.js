const _levels = { debug: 0, info: 1, warn: 2, error: 3, none: 99 };
let _minLevel = 1;

function createRequestId() {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let requestId = '';
  for (let i = 0; i < bytes.length; i++) requestId += bytes[i].toString(16).padStart(2, '0');
  return requestId;
}

function createRequestContext(initial = {}) {
  const values = initial && typeof initial === 'object' ? initial : {};
  const ctx = {
    qname: '',
    qtype: 0,
    region: '',
    owner: null,
    optimizationApplied: false,
    echInjected: false,
    echStatus: null,
    auto1: null,
    preferred: null,
    meta: null,
    googleProxy: null,
    fallbacks: [],
    ...values,
  };
  ctx.requestId = createRequestId();
  ctx.fallbacks = Array.isArray(values.fallbacks) ? values.fallbacks : [];
  ctx.startedAt = Date.now();
  return ctx;
}

function setLogLevel(level) {
  if (Object.prototype.hasOwnProperty.call(_levels, level)) _minLevel = _levels[level];
}

function logEvent(level, event, ctx, data = {}) {
  if (!ctx || !ctx.requestId || !Object.prototype.hasOwnProperty.call(_levels, level) || _levels[level] < _minLevel) return false;
  const payload = {
    timestamp: new Date().toISOString(),
    level,
    event,
    ...(data && typeof data === 'object' ? data : {}),
    requestId: ctx.requestId,
    qname: ctx.qname,
    qtype: ctx.qtype,
  };
  const line = JSON.stringify(payload);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
  return true;
}

function recordFallback(ctx, data = {}) {
  if (!ctx) return false;
  if (!Array.isArray(ctx.fallbacks)) ctx.fallbacks = [];
  const fallback = data && typeof data === 'object' ? data : {};
  ctx.fallbacks.push(fallback);
  return logEvent('warn', 'fallback', ctx, fallback);
}

function logRequestEnd(ctx, data = {}) {
  if (!ctx) return false;
  return logEvent('info', 'request_end', ctx, {
    ...ctx,
    ...(data && typeof data === 'object' ? data : {}),
  });
}

export { createRequestContext, logEvent, logRequestEnd, recordFallback, setLogLevel };
