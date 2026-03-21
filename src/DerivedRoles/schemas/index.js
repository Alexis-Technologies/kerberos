const { Conditions, ConditionsJsonSchemas, ConditionsTypeBoxSchemas, ConditionsZodSchemas } = require('../../Conditions');
const { Constants, ConstantsJsonSchemas, ConstantsTypeBoxSchemas, ConstantsZodSchemas } = require('../../Constants');
const { JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');
const { Variables, VariablesJsonSchemas, VariablesTypeBoxSchemas, VariablesZodSchemas } = require('../../Variables');

/**
 * Zod schema builders for derived roles.
 */
class DerivedRolesZodSchemas extends ZodSchemas {
  static buildDerivedRolesDefinitionShape(z) {
    return z.object({
      name: z.string(),
      parentRoles: z.array(z.string()).nonempty(),
      condition: z.union([ConditionsZodSchemas.buildShape(z), z.instanceof(Conditions)]),
    });
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
    return JsonSchemas.buildObjectShape(
      {
        name: { type: 'string' },
        parentRoles: JsonSchemas.buildNonEmptyArrayShape({ type: 'string' }),
        condition: {
          anyOf: [
            ConditionsJsonSchemas.buildShape(),
            JsonSchemas.buildInstanceOfShape(Conditions),
          ],
        },
      },
      ['name', 'parentRoles', 'condition']
    );
  }

  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        name: { type: 'string' },
        description: { type: 'string' },
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
        definitions: JsonSchemas.buildNonEmptyArrayShape(DerivedRolesJsonSchemas.buildDerivedRolesDefinitionShape()),
      },
      ['name', 'definitions']
    );
  }
}

/**
 * TypeBox schema builders for derived roles.
 */
class DerivedRolesTypeBoxSchemas extends TypeBoxSchemas {
  static buildDerivedRolesDefinitionShape(t) {
    return t.Object({
      name: t.String(),
      parentRoles: TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String()),
      condition: t.Union([
        ConditionsTypeBoxSchemas.buildShape(t),
        TypeBoxSchemas.buildInstanceOfShape(t, Conditions),
      ]),
    });
  }

  static buildShape(t) {
    return t.Object({
      name: t.String(),
      description: t.Optional(t.String()),
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
      definitions: TypeBoxSchemas.buildNonEmptyArrayShape(t, DerivedRolesTypeBoxSchemas.buildDerivedRolesDefinitionShape(t)),
    });
  }
}

module.exports = {
  DerivedRolesJsonSchemas,
  DerivedRolesTypeBoxSchemas,
  DerivedRolesZodSchemas,
};
