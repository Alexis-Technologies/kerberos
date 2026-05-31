const { Conditions, ConditionsJsonSchemas, ConditionsTypeBoxSchemas, ConditionsZodSchemas } = require('../../Conditions');
const { Constants, ConstantsJsonSchemas, ConstantsTypeBoxSchemas, ConstantsZodSchemas } = require('../../Constants');
const { Outputs, OutputsJsonSchemas, OutputsTypeBoxSchemas, OutputsZodSchemas } = require('../../Outputs');
const { ALL_ACTIONS, JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');
const { Variables, VariablesJsonSchemas, VariablesTypeBoxSchemas, VariablesZodSchemas } = require('../../Variables');

class RolePolicyZodSchemas extends ZodSchemas {
  static buildRuleShape(z) {
    return z
      .object({
        name: z.string().optional(),
        resource: z.union([z.string(), z.literal(ALL_ACTIONS)]),
        allowActions: z.array(z.string()).nonempty(),
        condition: z.union([ConditionsZodSchemas.buildShape(z), z.instanceof(Conditions)]).optional(),
        output: z.union([OutputsZodSchemas.buildShape(z), z.instanceof(Outputs)]).optional(),
      });
  }

  static buildRolePolicyShape(z) {
    return z.object({
      role: z.string(),
      version: z.string(),
      scope: ZodSchemas.buildScopeString(z).optional(),
      parentRoles: z.array(z.string()).optional(),
      rules: z.array(RolePolicyZodSchemas.buildRuleShape(z)).nonempty(),
      variables: z.union([VariablesZodSchemas.buildShape(z), z.instanceof(Variables)]).optional(),
      constants: z.union([ConstantsZodSchemas.buildShape(z), z.instanceof(Constants)]).optional(),
    });
  }

  static buildShape(z) {
    return z.object({
      rolePolicy: RolePolicyZodSchemas.buildRolePolicyShape(z),
    });
  }
}

class RolePolicyJsonSchemas extends JsonSchemas {
  static buildRuleShape() {
    return JsonSchemas.buildObjectShape(
      {
        name: { type: 'string' },
        resource: {
          anyOf: [{ type: 'string' }, { const: ALL_ACTIONS }],
        },
        allowActions: JsonSchemas.buildNonEmptyArrayShape({ type: 'string' }),
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
      ['resource', 'allowActions']
    );
  }

  static buildRolePolicyShape() {
    return JsonSchemas.buildObjectShape(
      {
        role: { type: 'string' },
        version: { type: 'string' },
        scope: JsonSchemas.buildScopeString(),
        parentRoles: {
          type: 'array',
          items: { type: 'string' },
        },
        rules: JsonSchemas.buildNonEmptyArrayShape(RolePolicyJsonSchemas.buildRuleShape()),
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
      },
      ['role', 'version', 'rules']
    );
  }

  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        rolePolicy: RolePolicyJsonSchemas.buildRolePolicyShape(),
      },
      ['rolePolicy']
    );
  }
}

class RolePolicyTypeBoxSchemas extends TypeBoxSchemas {
  static buildRuleShape(t) {
    return t.Object({
      name: t.Optional(t.String()),
      resource: t.Union([t.String(), t.Literal(ALL_ACTIONS)]),
      allowActions: TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String()),
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
    });
  }

  static buildRolePolicyShape(t) {
    return t.Object({
      role: t.String(),
      version: t.String(),
      scope: t.Optional(TypeBoxSchemas.buildScopeString(t)),
      parentRoles: t.Optional(t.Array(t.String())),
      rules: TypeBoxSchemas.buildNonEmptyArrayShape(t, RolePolicyTypeBoxSchemas.buildRuleShape(t)),
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
    });
  }

  static buildShape(t) {
    return t.Object({
      rolePolicy: RolePolicyTypeBoxSchemas.buildRolePolicyShape(t),
    });
  }
}

module.exports = {
  RolePolicyJsonSchemas,
  RolePolicyTypeBoxSchemas,
  RolePolicyZodSchemas,
};
