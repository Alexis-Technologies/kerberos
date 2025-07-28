const { ConditionsZodSchemas } = require('./schemas');

class Conditions {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return ConditionsZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  strategies = {
    any: (conds, req) => conds.some((cond) => this.evaluateCondition(cond, req)),
    all: (conds, req) => conds.every((cond) => this.evaluateCondition(cond, req)),
    none: (conds, req) => !conds.some((cond) => this.evaluateCondition(cond, req)),
  };

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = Conditions.parseShape(shape, { z });
  }

  evaluateCondition(cond, req) {
    if (typeof cond === 'function') {
      return cond(req);
    }

    if (typeof cond === 'object') {
      const [strategyKey] = Object.keys(cond);
      const strategy = this.strategies[strategyKey];
      if (!strategy) {
        throw new Error(`Unknown strategy: ${strategyKey}`);
      }
      return strategy(cond[strategyKey], req);
    }

    throw new Error(`Invalid condition: ${cond}`);
  }

  isFulfilled(req) {
    return this.evaluateCondition(this.#shape.match, req);
  }
}

module.exports = { Conditions };
