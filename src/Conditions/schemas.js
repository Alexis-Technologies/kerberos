const { z } = require('zod');

const { ZodSchemas } = require('../schemas.js');
const { VariablesZodSchemas, RequestWithVariablesSchema } = require('../Variables');
const { ConstantsZodSchemas, RequestWithConstantsSchema } = require('../Constants');

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

class ConditionsZodSchemas extends ZodSchemas {
  static buildFullRequest(z) {
    return z.object({
      ...ConstantsZodSchemas.buildRequestWithConstants(z).shape,
      ...VariablesZodSchemas.buildRequestWithVariables(z).shape,
    });
  }

  static buildConditionSingleMatchExpr(z) {
    return z.function({
      input: [ConditionsZodSchemas.buildFullRequest(z)],
      output: z.boolean(),
    });
  }

  static buildConditionMatchShape(z) {
    return z.lazy(() =>
      z.union([
        ConditionsZodSchemas.buildConditionSingleMatchExpr(z),
        z.object({
          any: z.array(ConditionsZodSchemas.buildConditionMatchShape(z)).nonempty(),
        }),
        z.object({
          all: z.array(ConditionsZodSchemas.buildConditionMatchShape(z)).nonempty(),
        }),
        z.object({
          none: z.array(ConditionsZodSchemas.buildConditionMatchShape(z)).nonempty(),
        }),
      ])
    );
  }

  static buildShape(z) {
    return z.object({ match: ConditionsZodSchemas.buildConditionMatchShape(z) });
  }
}

module.exports = {
  ConditionsZodSchemas,
  ConditionMatchSchema,
  ConditionSchemaSchema,
};
