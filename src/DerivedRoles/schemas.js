const { z } = require('zod');

const { ConditionSchemaSchema, ConditionsInstanceSchema } = require('../Conditions');
const { VariablesSchemaSchema, VariablesInstanceSchema } = require('../Variables');
const { ConstantsInstanceSchema, ConstantsSchemaSchema } = require('../Constants');

const DerivedRolesDefinitionSchemaSchema = z
  .object({
    name: z.string(),
    parentRoles: z.array(z.string()).nonempty(),
    condition: z.union([ConditionSchemaSchema, ConditionsInstanceSchema]),
  })
  .strict();

const DerivedRolesSchemaSchema = z
  .object({
    name: z.string(),
    description: z.string().optional(),
    variables: z.union([VariablesSchemaSchema, VariablesInstanceSchema]).optional(),
    constants: z.union([ConstantsSchemaSchema, ConstantsInstanceSchema]).optional(),
    definitions: z.array(DerivedRolesDefinitionSchemaSchema).nonempty(),
  })
  .strict();

module.exports = {
  DerivedRolesDefinitionSchemaSchema,
  DerivedRolesSchemaSchema,
};
