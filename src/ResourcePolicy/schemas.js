const { VariablesZodSchemas, Variables } = require('../Variables');
const { ConditionsZodSchemas, Conditions } = require('../Conditions');
const { ConstantsZodSchemas, Constants } = require('../Constants');
const { ALL_ACTIONS, Effect, ZodSchemas } = require('../schemas.js');

class ResourcePolicyZodSchemas extends ZodSchemas {
  static buildRuleShape(z) {
    return z
      .object({
        actions: z.array(z.string()).nonempty(),
        effect: z.nativeEnum(Effect),
        roles: z
          .array(z.union([z.string(), z.literal(ALL_ACTIONS)]))
          .nonempty()
          .optional(),
        derivedRoles: z.array(z.string()).nonempty().optional(),
        condition: z.union([ConditionsZodSchemas.buildShape(z), z.instanceof(Conditions)]).optional(),
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
    return z.object({
      version: z.string(),
      resource: z.string(),
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

module.exports = { ResourcePolicyZodSchemas };
