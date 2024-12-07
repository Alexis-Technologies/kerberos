const { z } = require('zod');

const { RequestWithVariablesSchema } = require('../Variables');
const { RequestWithConstantsSchema } = require('../Constants');

const RequestSchema = RequestWithConstantsSchema.merge(RequestWithVariablesSchema);

const ConditionSingleMatchExprSchema = z.function().args(RequestSchema).returns(z.boolean());

const ConditionMatchSchema = z.lazy(() =>
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

const ConditionSchemaSchema = z.object({ match: ConditionMatchSchema }).strict();

module.exports = {
  ConditionSingleMatchExprSchema,
  ConditionMatchSchema,
  ConditionSchemaSchema,
};
