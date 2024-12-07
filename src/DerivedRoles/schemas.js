import { z } from 'zod';

import { ConditionSchemaSchema, ConditionsInstanceSchema } from '../Conditions/index.js';
import { VariablesSchemaSchema, VariablesInstanceSchema } from '../Variables/index.js';
import { ConstantsInstanceSchema, ConstantsSchemaSchema } from '../Constants/index.js';

export const DerivedRolesDefinitionSchemaSchema = z
  .object({
    name: z.string(),
    parentRoles: z.array(z.string()).nonempty(),
    condition: z.union([ConditionSchemaSchema, ConditionsInstanceSchema]),
  })
  .strict();

export const DerivedRolesSchemaSchema = z
  .object({
    name: z.string(),
    description: z.string().optional(),
    variables: z.union([VariablesSchemaSchema, VariablesInstanceSchema]).optional(),
    constants: z.union([ConstantsSchemaSchema, ConstantsInstanceSchema]).optional(),
    definitions: z.array(DerivedRolesDefinitionSchemaSchema).nonempty(),
  })
  .strict();
