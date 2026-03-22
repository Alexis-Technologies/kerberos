const { Conditions, ConditionsJsonSchemas, ConditionsTypeBoxSchemas, ConditionsZodSchemas } = require('../../Conditions');
const { Constants, ConstantsJsonSchemas, ConstantsTypeBoxSchemas, ConstantsZodSchemas } = require('../../Constants');
const { Outputs, OutputsJsonSchemas, OutputsTypeBoxSchemas, OutputsZodSchemas } = require('../../Outputs');
const { ALL_ACTIONS, Effect, JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');
const { Variables, VariablesJsonSchemas, VariablesTypeBoxSchemas, VariablesZodSchemas } = require('../../Variables');

class PrincipalPolicyZodSchemas extends ZodSchemas {
  static buildActionRuleShape(z) {
    return z.object({
      name: z.string().optional(),
      action: z.union([z.string(), z.literal(ALL_ACTIONS)]),
      effect: z.nativeEnum(Effect),
      condition: z.union([ConditionsZodSchemas.buildShape(z), z.instanceof(Conditions)]).optional(),
      output: z.union([OutputsZodSchemas.buildShape(z), z.instanceof(Outputs)]).optional(),
    });
  }

  static buildRuleShape(z) {
    return z.object({
      resource: z.union([z.string(), z.literal(ALL_ACTIONS)]),
      actions: z.array(PrincipalPolicyZodSchemas.buildActionRuleShape(z)).nonempty(),
    });
  }

  static buildPrincipalPolicyShape(z) {
    return z.object({
      principal: z.string(),
      version: z.string(),
      scope: ZodSchemas.buildScopeString(z).optional(),
      rules: z.array(PrincipalPolicyZodSchemas.buildRuleShape(z)).nonempty(),
      variables: z.union([VariablesZodSchemas.buildShape(z), z.instanceof(Variables)]).optional(),
      constants: z.union([ConstantsZodSchemas.buildShape(z), z.instanceof(Constants)]).optional(),
    });
  }

  static buildShape(z) {
    return z.object({
      principalPolicy: PrincipalPolicyZodSchemas.buildPrincipalPolicyShape(z),
    });
  }
}

class PrincipalPolicyJsonSchemas extends JsonSchemas {
  static buildActionRuleShape() {
    return JsonSchemas.buildObjectShape(
      {
        name: { type: 'string' },
        action: {
          anyOf: [{ type: 'string' }, { const: ALL_ACTIONS }],
        },
        effect: { enum: Object.values(Effect) },
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
      ['action', 'effect']
    );
  }

  static buildRuleShape() {
    return JsonSchemas.buildObjectShape(
      {
        resource: {
          anyOf: [{ type: 'string' }, { const: ALL_ACTIONS }],
        },
        actions: JsonSchemas.buildNonEmptyArrayShape(PrincipalPolicyJsonSchemas.buildActionRuleShape()),
      },
      ['resource', 'actions']
    );
  }

  static buildPrincipalPolicyShape() {
    return JsonSchemas.buildObjectShape(
      {
        principal: { type: 'string' },
        version: { type: 'string' },
        scope: JsonSchemas.buildScopeString(),
        rules: JsonSchemas.buildNonEmptyArrayShape(PrincipalPolicyJsonSchemas.buildRuleShape()),
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
      ['principal', 'version', 'rules']
    );
  }

  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        principalPolicy: PrincipalPolicyJsonSchemas.buildPrincipalPolicyShape(),
      },
      ['principalPolicy']
    );
  }
}

class PrincipalPolicyTypeBoxSchemas extends TypeBoxSchemas {
  static buildActionRuleShape(t) {
    return t.Object({
      name: t.Optional(t.String()),
      action: t.Union([t.String(), t.Literal(ALL_ACTIONS)]),
      effect: t.Union([t.Literal(Effect.Allow), t.Literal(Effect.Deny)]),
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

  static buildRuleShape(t) {
    return t.Object({
      resource: t.Union([t.String(), t.Literal(ALL_ACTIONS)]),
      actions: TypeBoxSchemas.buildNonEmptyArrayShape(t, PrincipalPolicyTypeBoxSchemas.buildActionRuleShape(t)),
    });
  }

  static buildPrincipalPolicyShape(t) {
    return t.Object({
      principal: t.String(),
      version: t.String(),
      scope: t.Optional(TypeBoxSchemas.buildScopeString(t)),
      rules: TypeBoxSchemas.buildNonEmptyArrayShape(t, PrincipalPolicyTypeBoxSchemas.buildRuleShape(t)),
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
      principalPolicy: PrincipalPolicyTypeBoxSchemas.buildPrincipalPolicyShape(t),
    });
  }
}

module.exports = {
  PrincipalPolicyJsonSchemas,
  PrincipalPolicyTypeBoxSchemas,
  PrincipalPolicyZodSchemas,
};
