const { ConditionsZodSchemas } = require('./schemas');

class Conditions {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return ConditionsZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  #strategies = {
    any: (conds, req) => {
      for (const cond of conds) if (cond(req)) return true;
      return false;
    },
    all: (conds, req) => {
      for (const cond of conds) if (!cond(req)) return false;
      return true;
    },
    none: (conds, req) => {
      for (const cond of conds) if (cond(req)) return false;
      return true;
    },
  };

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = Conditions.parseShape(shape, { z });
  }

  isFulfilled(req) {
    const cond = this.#shape.match;
    if (typeof cond === 'function') return cond(req);
    if (typeof cond !== 'object') throw new TypeError(`Invalid condition: ${cond}`);

    const [strategyKey] = Object.keys(cond);
    const strategy = this.#strategies[strategyKey];
    if (!strategy) throw new Error(`Unknown strategy: ${strategyKey}`);
    return strategy(cond[strategyKey], req);
  }
}

module.exports = { Conditions };
