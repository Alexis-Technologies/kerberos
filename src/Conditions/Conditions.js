const { z } = require('zod');

const { ConditionSchemaSchema } = require('./schemas');

class Conditions {
  strategies = {
    any: (conds, req) => conds.some((cond) => this.evaluateCondition(cond, req)),
    all: (conds, req) => conds.every((cond) => this.evaluateCondition(cond, req)),
    none: (conds, req) => !conds.some((cond) => this.evaluateCondition(cond, req)),
  };

  constructor(schema) {
    this.schema = ConditionSchemaSchema.parse(schema);
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
    return this.evaluateCondition(this.schema.match, req);
  }
}

const ConditionsInstanceSchema = z.instanceof(Conditions);

module.exports = { Conditions, ConditionsInstanceSchema };
