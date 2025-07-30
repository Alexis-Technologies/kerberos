const { ConstantsZodSchemas } = require('./schemas.js');

class Constants {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return ConstantsZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = Constants.parseShape(shape, { z });
  }

  get shape() {
    return this.#shape;
  }

  get() {
    return this.shape;
  }
}

module.exports = { Constants };
