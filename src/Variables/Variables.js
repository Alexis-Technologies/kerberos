const { z } = require('zod');

const { VariablesSchemaSchema } = require('./schemas.js');

class Variables {
  constructor(schema) {
    this.schema = VariablesSchemaSchema.parse(schema);
  }

  get(req) {
    return Object.fromEntries(Object.entries(this.schema).map(([name, fn]) => [name, fn(req)]));
  }
}

const VariablesInstanceSchema = z.instanceof(Variables);

module.exports = { Variables, VariablesInstanceSchema };
