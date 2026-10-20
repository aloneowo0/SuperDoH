/** @typedef {{ group?: string, rule?: number, action?: number }} Location */

export class RuleError extends Error {
  /** @param {string} code @param {string} message @param {Location} [location] */
  constructor(code, message, location = {}) {
    super(message);
    this.name = 'RuleError';
    this.code = code;
    this.location = Object.freeze({ ...location });
  }
}
