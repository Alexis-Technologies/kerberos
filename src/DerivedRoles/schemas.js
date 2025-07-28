const { ZodSchemas } = require('../schemas.js');
const { ConditionsZodSchemas, Conditions } = require('../Conditions');
const { VariablesZodSchemas, Variables } = require('../Variables');
const { ConstantsZodSchemas, Constants } = require('../Constants');

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

module.exports = { DerivedRolesZodSchemas };
