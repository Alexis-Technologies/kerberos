const { z } = require('zod');

const { ConstantsZodSchemas } = require('./schemas.js');

class Constants {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return ConstantsZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = ConstantsZodSchemas.buildShape(z).parse(shape);
  }

  get() {
    return this.#shape;
  }
}

const ConstantsInstanceSchema = z.instanceof(Constants);

module.exports = {
  Constants,
  ConstantsInstanceSchema,
};
