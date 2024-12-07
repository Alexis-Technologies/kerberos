const { z } = require('zod');

const { VariablesSchemaSchema, VariablesInstanceSchema } = require('../Variables');
const { ConditionSchemaSchema, ConditionsInstanceSchema } = require('../Conditions');
const { ConstantsSchemaSchema, ConstantsInstanceSchema } = require('../Constants');
const { ALL_ACTIONS, Effect } = require('../schemas.js');

const RuleSchema = z
  .object({
    actions: z.array(z.string()).nonempty(),
    effect: z.nativeEnum(Effect),
    roles: z
      .array(z.union([z.string(), z.literal(ALL_ACTIONS)]))
      .nonempty()
      .optional(),
    derivedRoles: z.array(z.string()).nonempty().optional(),
    condition: z.union([ConditionSchemaSchema, ConditionsInstanceSchema]).optional(),
  })
  .strict()
  .refine((data) => {
    if (data.roles && data.derivedRoles) {
      throw new Error('roles and derivedRoles cannot be specified together!');
    }
    if (!data.roles && !data.derivedRoles) {
      throw new Error('roles or derivedRoles must be specified!');
    }
    return true;
  });

const ResourcePolicySchemaSchema = z
  .object({
    version: z.string(),
    resource: z.string(),
    rules: z.array(RuleSchema).nonempty(),
    variables: z.union([VariablesSchemaSchema, VariablesInstanceSchema]).optional(),
    constants: z.union([ConstantsSchemaSchema, ConstantsInstanceSchema]).optional(),
    importDerivedRoles: z.array(z.string()).optional(),
  })
  .strict();

const ResourcePolicyRootSchemaSchema = z
  .object({
    resourcePolicy: ResourcePolicySchemaSchema,
  })
  .strict();

module.exports = {
  RuleSchema,
  ResourcePolicySchemaSchema,
  ResourcePolicyRootSchemaSchema,
};
