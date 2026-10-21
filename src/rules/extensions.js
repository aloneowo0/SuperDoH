import { createBudget } from '../doh/budget.js';
import { RuleError } from './errors.js';
import { fields } from './values.js';

/**
 * Bind validated parameters once, but never share their mutable objects with a call.
 * @template P, C, R
 * @param {(params: unknown) => P} parseParams
 * @param {(context: C, params: P) => R | Promise<R>} run
 * @returns {import('./types.js').ExtensionDefinition<C, R>}
 */
function defineExtension(parseParams, run) {
  return Object.freeze({
    /** @param {unknown} raw */
    bind(raw) {
      const parsed = parseParams(structuredClone(raw));
      if (parsed && (typeof parsed === 'object' || typeof parsed === 'function') && 'then' in parsed && typeof parsed.then === 'function') {
        // Parameter parsers are synchronous; reject but consume accidental async failure.
        void Promise.resolve(parsed).catch(() => {});
        throw new Error();
      }
      const params = structuredClone(parsed);
      return (/** @type {C} */ context) => run(context, structuredClone(params));
    },
  });
}
/**
 * @template P
 * @param {(params: unknown) => P} parseParams
 * @param {(context: import('./types.js').ConditionContext, params: P) => boolean | Promise<boolean>} run
 */
export function defineCondition(parseParams, run) { return defineExtension(parseParams, run); }
/**
 * @template P
 * @param {(params: unknown) => P} parseParams
 * @param {(context: import('./types.js').ActionContext, params: P) => void | Promise<void>} run
 */
export function defineAction(parseParams, run) { return defineExtension(parseParams, run); }

/**
 * @template C, R
 * @param {unknown} reference
 * @param {Readonly<Record<string, import('./types.js').ExtensionDefinition<C, R>>> | undefined} registry
 * @returns {(context: C) => R | Promise<R>}
 */
export function bindExtension(reference, registry) {
  const v = fields(reference, ['name', 'params']);
  if (typeof v.name !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(v.name) || !registry || !Object.hasOwn(registry, v.name)) {
    throw new RuleError('UNKNOWN_EXTENSION', 'Unknown trusted extension.');
  }
  try { return registry[v.name].bind(v.params); }
  catch { throw new RuleError('INVALID_EXTENSION_PARAMS', 'Invalid trusted extension parameters.'); }
}

/** @param {import('./limits.js').Limits} limits @param {AbortSignal} [parentSignal] */
export function createExtensionRunner(limits, parentSignal) {
  let spent = 0, calls = 0;
  /** @template T @param {(signal: AbortSignal) => T | Promise<T>} callback @returns {Promise<T>} */
  return async callback => {
    if (++calls > limits.maxExtensionCalls) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
    const remaining = limits.maxExtensionTimeMs - spent;
    if (remaining <= 0) throw new RuleError('EXTENSION_TIMEOUT', 'Trusted extension execution deadline exceeded.');
    const started = Date.now();
    const budget = createBudget(remaining, parentSignal, 'EXTENSION_TIMEOUT');
    try { return await budget.run(() => callback(budget.signal)); }
    finally { spent += Date.now() - started; budget.dispose(); }
  };
}
