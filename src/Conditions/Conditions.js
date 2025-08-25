const { ConditionsZodSchemas } = require('./schemas');

class Conditions {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return ConditionsZodSchemas.buildShape(z).parse(shape);
    return shape;
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

  constructor(shape, { z } = {}) {
    this.#shape = Conditions.parseShape(shape, { z });
  }

  get shape() {
    return this.#shape;
  }

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
