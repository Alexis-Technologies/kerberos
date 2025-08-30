const { OutputsZodSchemas } = require('./schemas.js');

class Outputs {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return OutputsZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = Outputs.parseShape(shape, { z });
  }

  get shape() {
    return this.#shape;
  }

  build(req, isConditionFulfilled, src) {
    try {
      let outputFunction = null;

      if (typeof this.#shape === 'function') {
        outputFunction = this.#shape;
      } else if (isConditionFulfilled && this.#shape.when.ruleActivated) {
        outputFunction = this.#shape.when.ruleActivated;
      } else if (!isConditionFulfilled && this.#shape.when.conditionNotMet) {
        outputFunction = this.#shape.when.conditionNotMet;
      }

      return { src, val: outputFunction?.(req) ?? null };
    } catch (error) {
      // If output function fails, add error information
      return { src, val: { error: 'Output function evaluation failed', message: error.message } };
    }
  }
}

module.exports = { Outputs };
