const { PrincipalMock, PrincipalMockZodSchemas } = require('./PrincipalMock.js');

class PrincipalsMockZodSchemas extends PrincipalMockZodSchemas {
  static buildShape(z) {
    const PrincipalMockShapeZodSchema = PrincipalMockZodSchemas.buildShape(z);
    return z.union([
      z.array(z.instanceof(PrincipalMock)).nonempty(),
      z.record(PrincipalMockShapeZodSchema.shape.name, PrincipalMockShapeZodSchema.omit({ name: true }))
    ]);
  }
}

class PrincipalsMock {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return PrincipalsMockZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  #principals = new Map();

  constructor(principals, { z } = {}) {
    const parsedPrincipals = PrincipalsMock.parseShape(principals, { z });
    if (Array.isArray(parsedPrincipals)) {
      parsedPrincipals.forEach((principal) => this.#principals.set(principal.name, principal));
    } else {
      Object.entries(parsedPrincipals).forEach(([name, principal]) => {
        const mock = new PrincipalMock({ ...principal, name });
        this.#principals.set(mock.name, mock);
      });
    }
  }

  get mocks() {
    return [...this.#principals.values()];
  }

  get(name) {
    return this.#principals.get(name);
  }
}

module.exports = { PrincipalsMockZodSchemas, PrincipalsMock };
