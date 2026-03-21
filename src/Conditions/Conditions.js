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
      for (const cond of conds) if (this.isFulfilled(req, cond)) return true;
      return false;
    },
    all: (conds, req) => {
      for (const cond of conds) if (!this.isFulfilled(req, cond)) return false;
      return true;
    },
    none: (conds, req) => {
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
  isFulfilled(req, condition = null) {
    const cond = condition || this.#shape.match;
    if (typeof cond === 'function') return cond(req);
    if (typeof cond !== 'object') throw new TypeError(`Invalid condition: ${cond}`);

    const strategyKeys = Object.keys(cond);
    const results = new Set();
    for (const strategyKey of strategyKeys) {
      const strategy = this.#strategies[strategyKey];
      if (!strategy) throw new Error(`Unknown strategy: ${strategyKey}`);
      const result = strategy(cond[strategyKey], req);
      results.add(result);
    }
    return !results.has(false);
  }
}

module.exports = { Conditions };
