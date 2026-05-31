const { Conditions, ConditionsJsonSchemas, ConditionsTypeBoxSchemas, ConditionsZodSchemas } = require('../../Conditions');
const { Constants, ConstantsJsonSchemas, ConstantsTypeBoxSchemas, ConstantsZodSchemas } = require('../../Constants');
const { Outputs, OutputsJsonSchemas, OutputsTypeBoxSchemas, OutputsZodSchemas } = require('../../Outputs');
const { ALL_ACTIONS, Effect, JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');
const { Variables, VariablesJsonSchemas, VariablesTypeBoxSchemas, VariablesZodSchemas } = require('../../Variables');

/**
 * Zod schema builders for resource policies.
 */
class ResourcePolicyZodSchemas extends ZodSchemas {
  static buildRuleShape(z) {
    return z
      .object({
        name: z.string().optional(),
        actions: z.array(z.string()).nonempty(),
        effect: z.nativeEnum(Effect),
        roles: z
          .array(z.union([z.string(), z.literal(ALL_ACTIONS)]))
          .nonempty()
          .optional(),
        derivedRoles: z.array(z.string()).nonempty().optional(),
        condition: z.union([ConditionsZodSchemas.buildShape(z), z.instanceof(Conditions)]).optional(),
        output: z.union([OutputsZodSchemas.buildShape(z), z.instanceof(Outputs)]).optional(),
      })
      .check((ctx) => {
        if (ctx.value.roles && ctx.value.derivedRoles) {
          ctx.issues.push({
            code: 'custom',
            path: ['roles', 'derivedRoles'],
            message: 'roles and derivedRoles cannot be specified together!',
          });
        }
        if (!ctx.value.roles && !ctx.value.derivedRoles) {
          ctx.issues.push({
            code: 'custom',
            path: ['roles', 'derivedRoles'],
            message: 'roles or derivedRoles must be specified!',
          });
        }
        return true;
      });
  }

  static buildResourcePolicyShape(z) {
    return z
      .object({
        version: z.string(),
        resource: z.string(),
        scope: ZodSchemas.buildScopeString(z).optional(),
        rules: z.array(ResourcePolicyZodSchemas.buildRuleShape(z)).nonempty(),
        variables: z.union([VariablesZodSchemas.buildShape(z), z.instanceof(Variables)]).optional(),
        constants: z.union([ConstantsZodSchemas.buildShape(z), z.instanceof(Constants)]).optional(),
        importDerivedRoles: z.array(z.string()).optional(),
      });
  }

  static buildShape(z) {
    return z.object({
      resourcePolicy: ResourcePolicyZodSchemas.buildResourcePolicyShape(z),
    });
  }
}

/**
 * Plain JSON Schema builders for resource policies.
 */
class ResourcePolicyJsonSchemas extends JsonSchemas {
  static buildRuleShape() {
    return {
      allOf: [
        JsonSchemas.buildObjectShape(
          {
            name: { type: 'string' },
            actions: JsonSchemas.buildNonEmptyArrayShape({ type: 'string' }),
            effect: { enum: Object.values(Effect) },
            roles: JsonSchemas.buildNonEmptyArrayShape({
              anyOf: [{ type: 'string' }, { const: ALL_ACTIONS }],
            }),
            derivedRoles: JsonSchemas.buildNonEmptyArrayShape({ type: 'string' }),
            condition: {
              anyOf: [
                ConditionsJsonSchemas.buildShape(),
                JsonSchemas.buildInstanceOfShape(Conditions),
              ],
            },
            output: {
              anyOf: [
                OutputsJsonSchemas.buildShape(),
                JsonSchemas.buildInstanceOfShape(Outputs),
              ],
            },
          },
          ['actions', 'effect']
        ),
        {
          oneOf: [
            { required: ['roles'], not: { required: ['derivedRoles'] } },
            { required: ['derivedRoles'], not: { required: ['roles'] } },
          ],
        },
      ],
    };
  }

  static buildResourcePolicyShape() {
    return JsonSchemas.buildObjectShape(
      {
        version: { type: 'string' },
        resource: { type: 'string' },
        scope: JsonSchemas.buildScopeString(),
        rules: JsonSchemas.buildNonEmptyArrayShape(ResourcePolicyJsonSchemas.buildRuleShape()),
        variables: {
          anyOf: [
            VariablesJsonSchemas.buildShape(),
            JsonSchemas.buildInstanceOfShape(Variables),
          ],
        },
        constants: {
          anyOf: [
            ConstantsJsonSchemas.buildShape(),
            JsonSchemas.buildInstanceOfShape(Constants),
          ],
        },
        importDerivedRoles: {
          type: 'array',
          items: { type: 'string' },
        },
      },
      ['version', 'resource', 'rules']
    );
  }

  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        resourcePolicy: ResourcePolicyJsonSchemas.buildResourcePolicyShape(),
      },
      ['resourcePolicy']
    );
  }
}

/**
 * TypeBox schema builders for resource policies.
 */
class ResourcePolicyTypeBoxSchemas extends TypeBoxSchemas {
  static buildRuleShape(t) {
    return t.Intersect([
      t.Object({
        name: t.Optional(t.String()),
        actions: TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String()),
        effect: t.Union([t.Literal(Effect.Allow), t.Literal(Effect.Deny)]),
        roles: t.Optional(
          TypeBoxSchemas.buildNonEmptyArrayShape(
            t,
            t.Union([t.String(), t.Literal(ALL_ACTIONS)])
          )
        ),
        derivedRoles: t.Optional(TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String())),
        condition: t.Optional(
          t.Union([
            ConditionsTypeBoxSchemas.buildShape(t),
            TypeBoxSchemas.buildInstanceOfShape(t, Conditions),
          ])
        ),
        output: t.Optional(
          t.Union([
            OutputsTypeBoxSchemas.buildShape(t),
            TypeBoxSchemas.buildInstanceOfShape(t, Outputs),
          ])
        ),
      }),
      // `roles` and `derivedRoles` are mutually exclusive: each branch requires
      // one and forbids the other (`Never` rejects the property if present), so
      // this matches the Zod/JSON Schema invariant instead of a loose `anyOf`.
      t.Union([
        t.Object({
          roles: TypeBoxSchemas.buildNonEmptyArrayShape(t, t.Union([t.String(), t.Literal(ALL_ACTIONS)])),
          derivedRoles: t.Optional(t.Never()),
        }),
        t.Object({
          derivedRoles: TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String()),
          roles: t.Optional(t.Never()),
        }),
      ]),
    ]);
  }

  static buildResourcePolicyShape(t) {
    return t.Object({
      version: t.String(),
      resource: t.String(),
      scope: t.Optional(TypeBoxSchemas.buildScopeString(t)),
      rules: TypeBoxSchemas.buildNonEmptyArrayShape(t, ResourcePolicyTypeBoxSchemas.buildRuleShape(t)),
      variables: t.Optional(
        t.Union([
          VariablesTypeBoxSchemas.buildShape(t),
          TypeBoxSchemas.buildInstanceOfShape(t, Variables),
        ])
      ),
      constants: t.Optional(
        t.Union([
          ConstantsTypeBoxSchemas.buildShape(t),
          TypeBoxSchemas.buildInstanceOfShape(t, Constants),
        ])
      ),
      importDerivedRoles: t.Optional(t.Array(t.String())),
    });
  }

  static buildShape(t) {
    return t.Object({
      resourcePolicy: ResourcePolicyTypeBoxSchemas.buildResourcePolicyShape(t),
    });
  }
}

module.exports = {
  ResourcePolicyJsonSchemas,
  ResourcePolicyTypeBoxSchemas,
  ResourcePolicyZodSchemas,
};
