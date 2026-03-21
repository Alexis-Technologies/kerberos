const { JsonSchemas, TypeBoxSchemas, ZodSchemas, Effect } = require('../../schemas');
const {
  PrincipalMock,
  PrincipalsMock,
  PrincipalsMockJsonSchemas,
  PrincipalsMockTypeBoxSchemas,
  PrincipalsMockZodSchemas,
  ResourceMock,
  ResourcesMock,
  ResourcesMockJsonSchemas,
  ResourcesMockTypeBoxSchemas,
  ResourcesMockZodSchemas,
} = require('../Mocks');

/**
 * Zod schema builders for KerberosTest.
 */
class KerberosTestZodSchemas extends ZodSchemas {
  static buildInputShape(z) {
    return z
      .object({
        principals: z.union([z.array(z.string()).nonempty(), z.instanceof(PrincipalsMock)]),
        resources: z.union([z.array(z.string()).nonempty(), z.instanceof(ResourcesMock)]),
        actions: z.array(z.string()).nonempty().transform((actions) => new Set(actions)),
      });
  }

  static buildExpectedItemShape(z) {
    return z
      .object({
        principal: z.union([z.string(), z.instanceof(PrincipalMock)]),
        resource: z.union([z.string(), z.instanceof(ResourceMock)]),
        actions: z.record(z.string(), z.union([z.nativeEnum(Effect), z.boolean()])),
      });
  }

  static buildShape(z) {
    return z
      .object({
        name: z.string(),
        input: KerberosTestZodSchemas.buildInputShape(z),
        expected: z.array(KerberosTestZodSchemas.buildExpectedItemShape(z)).nonempty(),
      })
      .check((ctx) => {
        const inputActions = ctx.value.input.actions;
        for (const item of ctx.value.expected) {
          const expectedActions = new Set(Object.keys(item.actions));
          for (const action of expectedActions) {
            if (!inputActions.has(action)) {
              ctx.issues.push({
                code: 'custom',
                path: ['expected', 'actions'],
                message: `Action "${action}" in expected is not present in input actions`,
              });
            }
          }
        }
      });
  }
}

class KerberosTestJsonSchemas extends JsonSchemas {
  static buildInputShape() {
    return JsonSchemas.buildObjectShape(
      {
        principals: {
          anyOf: [
            JsonSchemas.buildNonEmptyArrayShape({ type: 'string' }),
            JsonSchemas.buildInstanceOfShape(PrincipalsMock),
          ],
        },
        resources: {
          anyOf: [
            JsonSchemas.buildNonEmptyArrayShape({ type: 'string' }),
            JsonSchemas.buildInstanceOfShape(ResourcesMock),
          ],
        },
        actions: JsonSchemas.buildNonEmptyArrayShape({ type: 'string' }),
      },
      ['principals', 'resources', 'actions']
    );
  }

  static buildExpectedItemShape() {
    return JsonSchemas.buildObjectShape(
      {
        principal: {
          anyOf: [{ type: 'string' }, JsonSchemas.buildInstanceOfShape(PrincipalMock)],
        },
        resource: {
          anyOf: [{ type: 'string' }, JsonSchemas.buildInstanceOfShape(ResourceMock)],
        },
        actions: JsonSchemas.buildRecordShape({
          anyOf: [{ enum: Object.values(Effect) }, { type: 'boolean' }],
        }),
      },
      ['principal', 'resource', 'actions']
    );
  }

  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        name: { type: 'string' },
        input: KerberosTestJsonSchemas.buildInputShape(),
        expected: JsonSchemas.buildNonEmptyArrayShape(KerberosTestJsonSchemas.buildExpectedItemShape()),
      },
      ['name', 'input', 'expected']
    );
  }
}

class KerberosTestTypeBoxSchemas extends TypeBoxSchemas {
  static buildInputShape(t) {
    return t.Object({
      principals: t.Union([
        TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String()),
        TypeBoxSchemas.buildInstanceOfShape(t, PrincipalsMock),
      ]),
      resources: t.Union([
        TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String()),
        TypeBoxSchemas.buildInstanceOfShape(t, ResourcesMock),
      ]),
      actions: TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String()),
    });
  }

  static buildExpectedItemShape(t) {
    return t.Object({
      principal: t.Union([t.String(), TypeBoxSchemas.buildInstanceOfShape(t, PrincipalMock)]),
      resource: t.Union([t.String(), TypeBoxSchemas.buildInstanceOfShape(t, ResourceMock)]),
      actions: t.Record(
        t.String(),
        t.Union([
          t.Literal(Effect.Allow),
          t.Literal(Effect.Deny),
          t.Boolean(),
        ])
      ),
    });
  }

  static buildShape(t) {
    return t.Object({
      name: t.String(),
      input: KerberosTestTypeBoxSchemas.buildInputShape(t),
      expected: TypeBoxSchemas.buildNonEmptyArrayShape(t, KerberosTestTypeBoxSchemas.buildExpectedItemShape(t)),
    });
  }
}

/**
 * Zod schema builders for KerberosTests.
 */
class KerberosTestsZodSchemas extends ZodSchemas {
  static buildTestsPolicyShape(z, KerberosTest) {
    return z.object({
      name: z.string(),
      principals: z.union([z.instanceof(PrincipalsMock), PrincipalsMockZodSchemas.buildShape(z, PrincipalMock)]),
      resources: z.union([z.instanceof(ResourcesMock), ResourcesMockZodSchemas.buildShape(z, ResourceMock)]),
      tests: z.array(z.union([z.instanceof(KerberosTest), KerberosTestZodSchemas.buildShape(z)])).nonempty(),
    });
  }

  static buildShape(z, KerberosTest) {
    return z.array(KerberosTestsZodSchemas.buildTestsPolicyShape(z, KerberosTest)).nonempty();
  }
}

class KerberosTestsJsonSchemas extends JsonSchemas {
  static buildTestsPolicyShape(KerberosTest) {
    return JsonSchemas.buildObjectShape(
      {
        name: { type: 'string' },
        principals: {
          anyOf: [
            JsonSchemas.buildInstanceOfShape(PrincipalsMock),
            PrincipalsMockJsonSchemas.buildShape(PrincipalMock),
          ],
        },
        resources: {
          anyOf: [
            JsonSchemas.buildInstanceOfShape(ResourcesMock),
            ResourcesMockJsonSchemas.buildShape(ResourceMock),
          ],
        },
        tests: JsonSchemas.buildNonEmptyArrayShape({
          anyOf: [
            JsonSchemas.buildInstanceOfShape(KerberosTest),
            KerberosTestJsonSchemas.buildShape(),
          ],
        }),
      },
      ['name', 'principals', 'resources', 'tests']
    );
  }

  static buildShape(KerberosTest) {
    return JsonSchemas.buildNonEmptyArrayShape(KerberosTestsJsonSchemas.buildTestsPolicyShape(KerberosTest));
  }
}

class KerberosTestsTypeBoxSchemas extends TypeBoxSchemas {
  static buildTestsPolicyShape(t, KerberosTest) {
    return t.Object({
      name: t.String(),
      principals: t.Union([
        TypeBoxSchemas.buildInstanceOfShape(t, PrincipalsMock),
        PrincipalsMockTypeBoxSchemas.buildShape(t, PrincipalMock),
      ]),
      resources: t.Union([
        TypeBoxSchemas.buildInstanceOfShape(t, ResourcesMock),
        ResourcesMockTypeBoxSchemas.buildShape(t, ResourceMock),
      ]),
      tests: TypeBoxSchemas.buildNonEmptyArrayShape(
        t,
        t.Union([
          TypeBoxSchemas.buildInstanceOfShape(t, KerberosTest),
          KerberosTestTypeBoxSchemas.buildShape(t),
        ])
      ),
    });
  }

  static buildShape(t, KerberosTest) {
    return TypeBoxSchemas.buildNonEmptyArrayShape(t, KerberosTestsTypeBoxSchemas.buildTestsPolicyShape(t, KerberosTest));
  }
}

module.exports = {
  KerberosTestJsonSchemas,
  KerberosTestTypeBoxSchemas,
  KerberosTestZodSchemas,
  KerberosTestsJsonSchemas,
  KerberosTestsTypeBoxSchemas,
  KerberosTestsZodSchemas,
};
