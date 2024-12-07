import { z } from 'zod';

import { RequestWithVariablesSchema } from '../Variables/index.js';
import { RequestWithConstantsSchema } from '../Constants/index.js';

const RequestSchema = RequestWithConstantsSchema.merge(RequestWithVariablesSchema);

export const ConditionSingleMatchExprSchema = z.function().args(RequestSchema).returns(z.boolean());

export const ConditionMatchSchema = z.lazy(() =>
  z.union([
    ConditionSingleMatchExprSchema,
    z.object({
      any: z.array(ConditionMatchSchema).nonempty(),
    }),
    z.object({
      all: z.array(ConditionMatchSchema).nonempty(),
    }),
    z.object({
      none: z.array(ConditionMatchSchema).nonempty(),
    }),
  ])
);

export const ConditionSchemaSchema = z.object({ match: ConditionMatchSchema }).strict();
