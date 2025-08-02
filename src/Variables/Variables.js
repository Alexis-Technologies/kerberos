const { VariablesZodSchemas } = require('./schemas.js');

class Variables {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return VariablesZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = Variables.parseShape(shape, { z });
  }

  get shape() {
    return this.#shape;
  }

  get(req) {
    return Object.fromEntries(Object.entries(this.#shape).map(([name, fn]) => [name, fn(req)]));
  }
}

module.exports = { Variables };
