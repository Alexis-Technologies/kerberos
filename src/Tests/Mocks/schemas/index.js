const { JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../../schemas');

/**
 * Zod schema builders for principal mocks.
 */
class PrincipalMockZodSchemas extends ZodSchemas {
  static buildShape(z) {
    return z.object({ ...ZodSchemas.buildRequestPrincipal(z).shape, name: z.string() });
  }
}

/**
 * Plain JSON Schema builders for principal mocks.
 */
class PrincipalMockJsonSchemas extends JsonSchemas {
  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        ...JsonSchemas.buildRequestPrincipal().properties,
        name: { type: 'string' },
      },
      [...JsonSchemas.buildRequestPrincipal().required, 'name']
    );
  }
}

/**
 * TypeBox schema builders for principal mocks.
 */
class PrincipalMockTypeBoxSchemas extends TypeBoxSchemas {
  static buildShape(t) {
    return t.Object({
      ...TypeBoxSchemas.buildRequestPrincipal(t).properties,
      name: t.String(),
    });
  }
}

/**
 * Zod schema builders for principals mocks.
 */
class PrincipalsMockZodSchemas extends PrincipalMockZodSchemas {
  static buildShape(z, PrincipalMock) {
    const principalShape = PrincipalMockZodSchemas.buildShape(z);
    return z.union([
      z.array(z.instanceof(PrincipalMock)).nonempty(),
      z.record(principalShape.shape.name, principalShape.omit({ name: true })),
    ]);
  }
}

/**
 * Plain JSON Schema builders for principals mocks.
 */
class PrincipalsMockJsonSchemas extends PrincipalMockJsonSchemas {
  static buildShape(PrincipalMock) {
    return {
      anyOf: [
        JsonSchemas.buildNonEmptyArrayShape(JsonSchemas.buildInstanceOfShape(PrincipalMock)),
        JsonSchemas.buildRecordShape({
          ...PrincipalMockJsonSchemas.buildShape(),
          required: PrincipalMockJsonSchemas.buildShape().required.filter((key) => key !== 'name'),
          properties: {
            ...PrincipalMockJsonSchemas.buildShape().properties,
          },
        }),
      ],
    };
  }
}

/**
 * TypeBox schema builders for principals mocks.
 */
class PrincipalsMockTypeBoxSchemas extends PrincipalMockTypeBoxSchemas {
  static buildShape(t, PrincipalMock) {
    return t.Union([
      TypeBoxSchemas.buildNonEmptyArrayShape(t, TypeBoxSchemas.buildInstanceOfShape(t, PrincipalMock)),
      t.Record(
        t.String(),
        t.Object({
          id: t.String(),
          policyVersion: t.Optional(t.String()),
          scope: t.Optional(TypeBoxSchemas.buildScopeString(t)),
          roles: TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String()),
          attr: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
        })
      ),
    ]);
  }
}

/**
 * Zod schema builders for resource mocks.
 */
class ResourceMockZodSchemas extends ZodSchemas {
  static buildShape(z) {
    return z.object({ ...ZodSchemas.buildRequestResource(z).shape, name: z.string() });
  }
}

/**
 * Plain JSON Schema builders for resource mocks.
 */
class ResourceMockJsonSchemas extends JsonSchemas {
  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        ...JsonSchemas.buildRequestResource().properties,
        name: { type: 'string' },
      },
      [...JsonSchemas.buildRequestResource().required, 'name']
    );
  }
}

/**
 * TypeBox schema builders for resource mocks.
 */
class ResourceMockTypeBoxSchemas extends TypeBoxSchemas {
  static buildShape(t) {
    return t.Object({
      ...TypeBoxSchemas.buildRequestResource(t).properties,
      name: t.String(),
    });
  }
}

/**
 * Zod schema builders for resources mocks.
 */
class ResourcesMockZodSchemas extends ResourceMockZodSchemas {
  static buildShape(z, ResourceMock) {
    const resourceShape = ResourceMockZodSchemas.buildShape(z);
    return z.union([
      z.array(z.instanceof(ResourceMock)).nonempty(),
      z.record(resourceShape.shape.name, resourceShape.omit({ name: true })),
    ]);
  }
}

/**
 * Plain JSON Schema builders for resources mocks.
 */
class ResourcesMockJsonSchemas extends ResourceMockJsonSchemas {
  static buildShape(ResourceMock) {
    return {
      anyOf: [
        JsonSchemas.buildNonEmptyArrayShape(JsonSchemas.buildInstanceOfShape(ResourceMock)),
        JsonSchemas.buildRecordShape({
          ...ResourceMockJsonSchemas.buildShape(),
          required: ResourceMockJsonSchemas.buildShape().required.filter((key) => key !== 'name'),
          properties: {
            ...ResourceMockJsonSchemas.buildShape().properties,
          },
        }),
      ],
    };
  }
}

/**
 * TypeBox schema builders for resources mocks.
 */
class ResourcesMockTypeBoxSchemas extends ResourceMockTypeBoxSchemas {
  static buildShape(t, ResourceMock) {
    return t.Union([
      TypeBoxSchemas.buildNonEmptyArrayShape(t, TypeBoxSchemas.buildInstanceOfShape(t, ResourceMock)),
      t.Record(
        t.String(),
        t.Object({
          id: t.String(),
          kind: t.String(),
          policyVersion: t.Optional(t.String()),
          scope: t.Optional(TypeBoxSchemas.buildScopeString(t)),
          attr: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
        })
      ),
    ]);
  }
}

module.exports = {
  PrincipalMockJsonSchemas,
  PrincipalMockTypeBoxSchemas,
  PrincipalMockZodSchemas,
  PrincipalsMockJsonSchemas,
  PrincipalsMockTypeBoxSchemas,
  PrincipalsMockZodSchemas,
  ResourceMockJsonSchemas,
  ResourceMockTypeBoxSchemas,
  ResourceMockZodSchemas,
  ResourcesMockJsonSchemas,
  ResourcesMockTypeBoxSchemas,
  ResourcesMockZodSchemas,
};
