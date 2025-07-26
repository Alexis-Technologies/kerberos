const { ZodSchemas } = require('../../schemas.js');

class PrincipalMockZodSchemas extends ZodSchemas {
  static buildShape(z) {
    return z.object({ ...ZodSchemas.buildRequestPrincipal(z).shape, name: z.string() });
  }
}

class PrincipalMock {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return PrincipalMockZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = PrincipalMock.parseShape(shape, { z });
  }

  get id() {
    return this.#shape.id;
  }

  get name() {
    return this.#shape.name;
  }

  get roles() {
    return this.#shape.roles;
  }

  get attr() {
    return this.#shape.attr;
  }
}

module.exports = {
  PrincipalMock,
  PrincipalMockZodSchemas,
};
