import { z } from 'zod';

import { RequestSchema } from '../schemas.js';
import { RequestWithConstantsSchema } from '../Constants/index.js';

export const VariablesReturnTypeSchema = z.unknown();

export const VariablesSchemaSchema = z.record(z.string(), z.function().args(RequestWithConstantsSchema).returns(VariablesReturnTypeSchema));

export const RequestWithVariablesSchema = RequestSchema.extend({
  variables: z.record(z.string(), VariablesReturnTypeSchema).optional(),
  V: z.record(z.string(), VariablesReturnTypeSchema).optional(),
});
