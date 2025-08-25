const { OutputsZodSchemas } = require('./schemas.js');

class Outputs {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return OutputsZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  static buildSrc({ version, name, kind, index }) {
    return `resource.${kind}.v${version}#${name || 'UNNAMED_RULE' + (index !== undefined ? `_${index}` : '')}`;
  }

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = Outputs.parseShape(shape, { z });
  }

  get shape() {
    return this.#shape;
  }

  build(req, { version, name, kind, isConditionFulfilled, index }) {
    try {
      let outputFunction = null;

      if (isConditionFulfilled && this.#shape.when.ruleActivated) {
        outputFunction = this.#shape.when.ruleActivated;
      } else if (!isConditionFulfilled && this.#shape.when.conditionNotMet) {
        outputFunction = this.#shape.when.conditionNotMet;
      }

      return {
        src: Outputs.buildSrc({ version, name, kind, index }),
        val: outputFunction?.(req)
      };
    } catch (error) {
      // If output function fails, add error information
      return {
        src: Outputs.buildSrc({ version, name, kind, index }),
        val: {
          error: 'Output function evaluation failed',
          message: error.message,
        },
      };
    }
  }
}

module.exports = { Outputs };
