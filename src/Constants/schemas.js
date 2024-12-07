import { z } from 'zod';
import { RequestSchema } from '../schemas.js';

export const ConstantsSchemaSchema = z.record(z.string(), z.unknown());

export const RequestWithConstantsSchema = RequestSchema.extend({
  constants: ConstantsSchemaSchema.optional(),
  C: ConstantsSchemaSchema.optional(),
});
