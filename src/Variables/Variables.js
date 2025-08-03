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
    const result = {};
    for (const name in this.#shape) {
      if (!Object.prototype.hasOwnProperty.call(this.#shape, name)) continue;
      result[name] = this.#shape[name](req);
    }
    return result;
  }
}

module.exports = { Variables };
