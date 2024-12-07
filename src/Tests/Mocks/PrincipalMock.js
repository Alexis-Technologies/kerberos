const { z } = require('zod');

const RequestPrincipalSchema = require('../../schemas.js').RequestPrincipalSchema;

const PrincipalMockSchema = RequestPrincipalSchema.extend({ name: z.string() });

class PrincipalMock {
  constructor(schema) {
    this.schema = PrincipalMockSchema.parse(schema);
  }

  get id() {
    return this.schema.id;
  }

  get name() {
    return this.schema.name;
  }

  get roles() {
    return this.schema.roles;
  }

  get attr() {
    return this.schema.attr;
  }
}

module.exports = {
  PrincipalMock,
  PrincipalMockSchema,
};
