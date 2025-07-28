const { VariablesSchemaSchema } = require('./schemas.js');

class Variables {
  constructor(schema) {
    this.schema = VariablesSchemaSchema.parse(schema);
  }

  get(req) {
    return Object.fromEntries(Object.entries(this.schema).map(([name, fn]) => [name, fn(req)]));
  }
}

module.exports = { Variables };
