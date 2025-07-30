const { ZodSchemas } = require('../schemas.js');
const { VariablesZodSchemas } = require('../Variables');
const { ConstantsZodSchemas } = require('../Constants');

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
        z.object({ any: z.array(ConditionsZodSchemas.buildConditionMatchShape(z)).nonempty() }),
        z.object({ all: z.array(ConditionsZodSchemas.buildConditionMatchShape(z)).nonempty() }),
        z.object({ none: z.array(ConditionsZodSchemas.buildConditionMatchShape(z)).nonempty() }),
      ])
    );
  }

  static buildShape(z) {
    return z.object({ match: ConditionsZodSchemas.buildConditionMatchShape(z) });
  }
}

module.exports = { ConditionsZodSchemas };
