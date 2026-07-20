const {
  Conditions,
  ConditionsJsonSchemas,
  ConditionsTypeBoxSchemas,
  ConditionsZodSchemas,
} = require('../../Conditions');
const { Constants, ConstantsJsonSchemas, ConstantsTypeBoxSchemas, ConstantsZodSchemas } = require('../../Constants');
const { JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');
const { Variables, VariablesJsonSchemas, VariablesTypeBoxSchemas, VariablesZodSchemas } = require('../../Variables');

/**
 * Zod schema builders for derived roles.
 */
class DerivedRolesZodSchemas extends ZodSchemas {
  static buildDerivedRolesDefinitionShape(z) {
    // Two definition kinds: condition-backed (classic — parentRoles and
    // condition required) and relation-backed (`relation` present — both
    // become optional gates resolved through the `relations` option).
    return z
      .object({
        name: z.string(),
        parentRoles: z.array(z.string()).nonempty().optional(),
        condition: z.union([ConditionsZodSchemas.buildShape(z), z.instanceof(Conditions)]).optional(),
        relation: z.string().optional(),
      })
      .refine(
        (value) => value.relation !== undefined || (value.parentRoles !== undefined && value.condition !== undefined),
        { message: 'A derived role definition requires either "relation" or both "parentRoles" and "condition".' },
      );
  }

  static buildShape(z) {
    return z.object({
      name: z.string(),
      description: z.string().optional(),
      variables: z.union([VariablesZodSchemas.buildShape(z), z.instanceof(Variables)]).optional(),
      constants: z.union([ConstantsZodSchemas.buildShape(z), z.instanceof(Constants)]).optional(),
      definitions: z.array(DerivedRolesZodSchemas.buildDerivedRolesDefinitionShape(z)).nonempty(),
    });
  }
}

/**
 * Plain JSON Schema builders for derived roles.
 */
class DerivedRolesJsonSchemas extends JsonSchemas {
  static buildDerivedRolesDefinitionShape() {
    // Mirrors the Zod backend: either `relation` is present, or both
    // `parentRoles` and `condition` are.
    return JsonSchemas.buildObjectShape(
      {
        name: { type: 'string' },
        parentRoles: JsonSchemas.buildNonEmptyArrayShape({ type: 'string' }),
        condition: {
          anyOf: [ConditionsJsonSchemas.buildShape(), JsonSchemas.buildInstanceOfShape(Conditions)],
        },
        relation: { type: 'string' },
      },
      ['name'],
      { anyOf: [{ required: ['relation'] }, { required: ['parentRoles', 'condition'] }] },
    );
  }

  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        name: { type: 'string' },
        description: { type: 'string' },
        variables: {
          anyOf: [VariablesJsonSchemas.buildShape(), JsonSchemas.buildInstanceOfShape(Variables)],
        },
        constants: {
          anyOf: [ConstantsJsonSchemas.buildShape(), JsonSchemas.buildInstanceOfShape(Constants)],
        },
        definitions: JsonSchemas.buildNonEmptyArrayShape(DerivedRolesJsonSchemas.buildDerivedRolesDefinitionShape()),
      },
      ['name', 'definitions'],
    );
  }
}

/**
 * TypeBox schema builders for derived roles.
 */
class DerivedRolesTypeBoxSchemas extends TypeBoxSchemas {
  static buildDerivedRolesDefinitionShape(t) {
    // Mirrors the Zod/JSON Schema backends: either `relation` is present, or
    // both `parentRoles` and `condition` are (same Composite + at-least-one
    // union encoding as the Conditions match shape).
    return t.Composite([
      t.Object({
        name: t.String(),
        parentRoles: t.Optional(TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String())),
        condition: t.Optional(
          t.Union([ConditionsTypeBoxSchemas.buildShape(t), TypeBoxSchemas.buildInstanceOfShape(t, Conditions)]),
        ),
        relation: t.Optional(t.String()),
      }),
      t.Union([t.Object({ relation: t.String() }), t.Object({ parentRoles: t.Unknown(), condition: t.Unknown() })]),
    ]);
  }

  static buildShape(t) {
    return t.Object({
      name: t.String(),
      description: t.Optional(t.String()),
      variables: t.Optional(
        t.Union([VariablesTypeBoxSchemas.buildShape(t), TypeBoxSchemas.buildInstanceOfShape(t, Variables)]),
      ),
      constants: t.Optional(
        t.Union([ConstantsTypeBoxSchemas.buildShape(t), TypeBoxSchemas.buildInstanceOfShape(t, Constants)]),
      ),
      definitions: TypeBoxSchemas.buildNonEmptyArrayShape(
        t,
        DerivedRolesTypeBoxSchemas.buildDerivedRolesDefinitionShape(t),
      ),
    });
  }
}

module.exports = {
  DerivedRolesJsonSchemas,
  DerivedRolesTypeBoxSchemas,
  DerivedRolesZodSchemas,
};
