const { parseConditionsShape } = require('./validation');

/**
 * Evaluates condition trees used in policies, derived roles and outputs.
 */
class Conditions {
  /**
   * Parses a condition shape with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parseConditionsShape(shape, options);
  }

  #strategies = {
    any: (conds, req) => {
      if (!Array.isArray(conds) || !conds.length) return false;
      for (const cond of conds) if (this.isFulfilled(req, cond)) return true;
      return false;
    },
    all: (conds, req) => {
      if (!Array.isArray(conds) || !conds.length) return false;
      for (const cond of conds) if (!this.isFulfilled(req, cond)) return false;
      return true;
    },
    none: (conds, req) => {
      if (!Array.isArray(conds) || !conds.length) return false;
      for (const cond of conds) if (this.isFulfilled(req, cond)) return false;
      return true;
    },
  };

  #shape = null;

  /**
   * @param {unknown} shape
   * @param {object} [options]
   */
  constructor(shape, options = {}) {
    this.#shape = Conditions.parseShape(shape, options);
  }

  get shape() {
    return this.#shape;
  }

  /**
   * Evaluates the current condition or a nested condition against the request.
   *
   * @param {Record<string, unknown>} req
   * @param {unknown} [condition]
   * @returns {boolean}
   */
  isFulfilled(req, condition = undefined) {
    const cond = condition === undefined ? this.#shape.match : condition;
    if (typeof cond === 'function') return cond(req);
    // Fail closed on invalid nested leaves (e.g. `{ all: [false] }` without a
    // validator). Using `||` here would treat falsy nested values as "missing"
    // and recurse back to the root match, causing stack overflow.
    if (typeof cond !== 'object' || cond === null) return false;

    const strategyKeys = Object.keys(cond);
    // Fail closed when no strategy is present (e.g. `{ match: {} }` without a
    // validation backend). An empty results set would otherwise vacuously
    // evaluate to `true` and turn a broken conditional rule into an unconditional match.
    if (!strategyKeys.length) return false;

    const results = new Set();
    for (const strategyKey of strategyKeys) {
      const strategy = this.#strategies[strategyKey];
      // Forward-compat: ignore unknown keys (schemas allow additional properties).
      if (!strategy) continue;
      const result = strategy(cond[strategyKey], req);
      results.add(result);
    }
    // Only unknown/extra keys were present (e.g. `{ description: '...' }`).
    if (!results.size) return false;
    return !results.has(false);
  }
}

module.exports = { Conditions };
