/** @typedef {{ group?: string, rule?: number, action?: number, source?: string }} Location */

export class RuleError extends Error {
  /** @param {string} code @param {string} message @param {Location} [location] @param {import('./types.js').FailureReason} [reason] */
  constructor(code, message, location = {}, reason) {
    super(message);
    this.name = 'RuleError';
    this.code = code;
    this.location = Object.freeze({ ...location });
    this.reason = reason && Object.freeze({ ...reason });
  }
}

const messages = Object.freeze({
  ECH_INVALID: 'Invalid ECH probe configuration or result.',
  ECH_PROBE_TIMEOUT: 'ECH probe request timed out.',
  ECH_PROBE_FAILED: 'ECH probe request failed.',
  INVALID_ECH_CONFIG: 'Invalid ECH configuration.',
  INVALID_ECH_SOURCE: 'Invalid DNS HTTPS ECH source.',
  NO_ECH_CONFIG: 'No usable ECH configuration is available.',
  AMBIGUOUS_ECH_CONFIG: 'DNS HTTPS source contains distinct ECH configurations.',
  NO_ECH_RECORD: 'No selected HTTPS ServiceMode answer record exists.',
  DOMAIN_LIST_TIMEOUT: 'Domain list source request timed out.',
  DOMAIN_LIST_UNAVAILABLE: 'The domain list is unavailable.',
  DOMAIN_LIST_FAILED: 'Domain list source request failed.',
  DOMAIN_LIST_INVALID: 'Invalid domain list source data.',
  ATTRIBUTION_TIMEOUT: 'Address attribution request timed out.',
  ATTRIBUTION_FAILED: 'Address attribution request failed.',
  ATTRIBUTION_INVALID: 'Invalid address attribution response.',
  CACHE_FAILED: 'DNS cache operation failed.',
  ACCESS_DENIED: 'The requested endpoint is not available.',
  INVALID_HTTP: 'Invalid DoH HTTP request.',
  EXECUTION_TIMEOUT: 'DNS execution deadline exceeded.',
  REQUEST_CANCELLED: 'DNS execution was cancelled.',
  UPSTREAM_TIMEOUT: 'DNS upstream request timed out.',
  UPSTREAM_FAILED: 'DNS upstream request failed.',
  UPSTREAM_INVALID: 'Invalid DNS upstream response.',
  NO_UPSTREAM: 'No DNS upstream is configured.',
  INVALID_CONTEXT: 'Invalid matching context.',
  INVALID_CONFIG: 'Invalid or unsupported rule configuration.',
  INVALID_OPTIONS: 'Invalid execution diagnostics options.',
  INVALID_QUERY: 'Invalid or unsupported DNS query.',
  NO_RESPONSE: 'This action requires an existing DNS response.',
  RESOURCE_LIMIT: 'Configured resource limit exceeded.',
  INVALID_STATE: 'Invalid DNS working state.',
});
/** @param {Location} location */
function safeLocation(location) {
  /** @type {Location} */
  const result = {};
  if (typeof location.group === 'string' && (/^[A-Za-z0-9_]{1,128}$/.test(location.group) || location.group === '<invalid>')) result.group = location.group;
  if (typeof location.source === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(location.source)) result.source = location.source;
  for (const key of /** @type {const} */ (['rule', 'action'])) {
    const value = location[key];
    if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) result[key] = value;
  }
  return result;
}
/** @param {unknown} error @param {Location} [location] */
export function normalizeFailure(error, location = {}) {
  const known = error instanceof RuleError && Object.hasOwn(messages, error.code);
  const code = known ? /** @type {keyof typeof messages} */ (error.code) : 'INVALID_STATE';
  // Values, stack and arbitrary cause chains may contain configuration or credentials.
  const kind = known && error.reason ? error.reason.kind
    : error instanceof RangeError ? 'RangeError' : error instanceof TypeError ? 'TypeError' : 'Error';
  return new RuleError(code, messages[code], safeLocation({ ...location, ...(error instanceof RuleError ? error.location : {}) }),
    known && !error.reason ? undefined : {
      kind: kind === 'TypeError' || kind === 'RangeError' ? kind : 'Error',
      message: 'The DNS operation failed; raw exception details are withheld.',
    });
}
/** @param {import('./types.js').FailureEvent} event */
function writeEvent(event) {
  const text = JSON.stringify(event);
  try { console.error(text); }
  catch {
    try { console.warn(text); }
    catch { /* Host logging failure must not change DNS execution. */ }
  }
}

/** @param {import('./types.js').ExecutionOptions} options */
export function createReporter(options) {
  let requestId = crypto.randomUUID();
  /** @type {import('./types.js').ExecutionOptions['onEvent']} */
  let observer;
  try {
    if (!options || typeof options !== 'object' || Array.isArray(options) || Object.keys(options).some(k => k !== 'requestId' && k !== 'onEvent' && k !== 'context' && k !== 'signal')) throw new Error();
    if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) throw new Error();
    if (options.requestId !== undefined && (typeof options.requestId !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(options.requestId))) throw new Error();
    if (options.onEvent !== undefined && typeof options.onEvent !== 'function') throw new Error();
    observer = options.onEvent;
    requestId = options.requestId ?? requestId;
  } catch {
    const error = new RuleError('INVALID_OPTIONS', messages.INVALID_OPTIONS);
    writeEvent(Object.freeze({ event: 'execution_failed', level: 'error', requestId, location: error.location, code: error.code, message: error.message, disposition: 'terminated', rolledBack: false }));
    throw error;
  }
  /** @param {RuleError} error @param {import('./types.js').Action['type']} [actionType] @param {boolean} [continued] */
  const report = (error, actionType, continued = false) => {
    const safe = normalizeFailure(error);
    /** @type {import('./types.js').FailureEvent} */
    const event = Object.freeze({
      event: actionType ? 'action_failed' : 'execution_failed', level: 'error', requestId,
      location: safe.location, actionType, code: safe.code, message: safe.message,
      reason: safe.reason, disposition: continued ? 'rolled_back_continue' : 'terminated', rolledBack: continued,
    });
    if (!observer) { writeEvent(event); return; }
    const fallback = () => {
      writeEvent(Object.freeze({ ...event, event: 'observer_failed', code: 'LOGGING_FAILED', message: 'Failure observer could not receive the event; the original event follows.', reason: undefined }));
      writeEvent(event);
    };
    try {
      const result = /** @type {unknown} */ (observer(event));
      if (result && (typeof result === 'object' || typeof result === 'function') && 'then' in result) {
        // Observers are synchronous; consume unexpected rejections without waiting.
        void Promise.resolve(result).catch(() => {});
        fallback();
      }
    } catch { fallback(); }
  };
  return Object.assign(report, { requestId });
}
