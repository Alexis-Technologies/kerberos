const { ZodSchemas } = require('../../schemas.js');

class ResourceMockZodSchemas extends ZodSchemas {
  static buildShape(z) {
    return z.object({ ...ZodSchemas.buildRequestResource(z).shape, name: z.string() });
  }
}

class ResourceMock {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return ResourceMockZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = ResourceMock.parseShape(shape, { z });
  }

  get id() {
    return this.#shape.id;
  }

  get name() {
    return this.#shape.name;
  }

  get kind() {
    return this.#shape.kind;
  }

  get attr() {
    return this.#shape.attr;
  }
}

module.exports = { ResourceMock, ResourceMockZodSchemas };
