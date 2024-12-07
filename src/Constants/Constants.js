const { z } = require('zod');

const { ConstantsSchemaSchema } = require('./schemas.js');

class Constants {
  constructor(schema) {
    this.schema = ConstantsSchemaSchema.parse(schema);
  }

  get() {
    return this.schema;
  }
}

const ConstantsInstanceSchema = z.instanceof(Constants);

module.exports = {
  Constants,
  ConstantsInstanceSchema,
};
