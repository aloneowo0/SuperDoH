import { RuleError } from '../rules/errors.js';

const SAFE_CODES = new Set(['EXECUTION_TIMEOUT', 'EXTENSION_TIMEOUT', 'UPSTREAM_TIMEOUT', 'REQUEST_CANCELLED']);

/** @param {unknown} reason @returns {RuleError} */
function cancellationError(reason) {
  if (reason instanceof RuleError && SAFE_CODES.has(reason.code)) return reason;
  return new RuleError('REQUEST_CANCELLED', 'The request was cancelled.');
}

/**
 * Creates a request budget with one absolute deadline shared by all operations.
 * @param {number} timeoutMs
 * @param {AbortSignal} [parentSignal]
 * @param {string} [timeoutCode='EXECUTION_TIMEOUT']
 */
export function createBudget(timeoutMs, parentSignal, timeoutCode = 'EXECUTION_TIMEOUT') {
  const controller = new AbortController();
  const deadline = Date.now() + timeoutMs;
  let disposed = false;
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let timer;

  /** @param {RuleError} error */
  const abort = (error) => {
    if (!controller.signal.aborted) controller.abort(error);
  };
  const onParentAbort = () => abort(cancellationError(parentSignal?.reason));
  const timeoutError = () => new RuleError(timeoutCode, 'The operation exceeded its execution deadline.');

  if (parentSignal?.aborted) onParentAbort();
  else if (Number.isFinite(timeoutMs) && timeoutMs >= 0) {
    timer = setTimeout(() => abort(timeoutError()), Math.min(timeoutMs, 2147483647));
    parentSignal?.addEventListener('abort', onParentAbort, { once: true });
  } else {
    abort(new RuleError('INVALID_CONFIG', 'Invalid execution budget.'));
    parentSignal?.addEventListener('abort', onParentAbort, { once: true });
  }

  /** @returns {void} */
  function check() {
    if (Date.now() >= deadline && !controller.signal.aborted) abort(timeoutError());
    if (controller.signal.aborted) throw cancellationError(controller.signal.reason);
  }

  /** @template T @param {() => T | Promise<T>} callback @returns {Promise<T>} */
  async function run(callback) {
    check();
    /** @type {(() => void) | undefined} */
    let onAbort;
    const cancelled = new Promise((_, reject) => {
      onAbort = () => reject(cancellationError(controller.signal.reason));
      controller.signal.addEventListener('abort', onAbort, { once: true });
      if (controller.signal.aborted) onAbort();
    });
    // Always observe the operation, including a rejection arriving after cancellation.
    const operation = Promise.resolve().then(() => {
      check();
      return callback();
    });
    operation.catch(() => {});
    try {
      return await Promise.race([operation, cancelled]);
    } finally {
      if (onAbort) controller.signal.removeEventListener('abort', onAbort);
    }
  }

  /** @returns {void} */
  function dispose() {
    if (disposed) return;
    disposed = true;
    if (timer !== undefined) clearTimeout(timer);
    parentSignal?.removeEventListener('abort', onParentAbort);
    abort(new RuleError('REQUEST_CANCELLED', 'The request was cancelled.'));
  }

  return { signal: controller.signal, check, run, dispose };
}
