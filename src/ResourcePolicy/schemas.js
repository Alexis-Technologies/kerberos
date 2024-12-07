import { z } from 'zod';

import { VariablesSchemaSchema, VariablesInstanceSchema } from '../Variables/index.js';
import { ConditionSchemaSchema, ConditionsInstanceSchema } from '../Conditions/index.js';
import { ConstantsSchemaSchema, ConstantsInstanceSchema } from '../Constants/index.js';
import { ALL_ACTIONS, Effect } from '../schemas.js';

export const RuleSchema = z
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

export const ResourcePolicySchemaSchema = z
  .object({
    version: z.string(),
    resource: z.string(),
    rules: z.array(RuleSchema).nonempty(),
    variables: z.union([VariablesSchemaSchema, VariablesInstanceSchema]).optional(),
    constants: z.union([ConstantsSchemaSchema, ConstantsInstanceSchema]).optional(),
    importDerivedRoles: z.array(z.string()).optional(),
  })
  .strict();

export const ResourcePolicyRootSchemaSchema = z
  .object({
    resourcePolicy: ResourcePolicySchemaSchema,
  })
  .strict();
