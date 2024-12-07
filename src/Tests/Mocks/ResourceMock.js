const { z } = require('zod');

const { RequestResourceSchema } = require('../../schemas.js');

const ResourceMockSchema = RequestResourceSchema.extend({ name: z.string() });

class ResourceMock {
  constructor(schema) {
    this.schema = ResourceMockSchema.parse(schema);
  }

  get id() {
    return this.schema.id;
  }

  get name() {
    return this.schema.name;
  }

  get kind() {
    return this.schema.kind;
  }

  get attr() {
    return this.schema.attr;
  }
}

module.exports = { ResourceMock, ResourceMockSchema };
