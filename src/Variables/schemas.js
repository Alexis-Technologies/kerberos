const { ZodSchemas } = require('../schemas.js');
const { ConstantsZodSchemas } = require('../Constants');

class VariablesZodSchemas extends ZodSchemas {
  static buildShape(z) {
    return z.record(
      z.string(),
      z.function({
        input: [ConstantsZodSchemas.buildRequestWithConstants(z)],
        output: VariablesZodSchemas.buildVariablesReturnType(z),
      })
    );
  }

  static buildRequestWithVariables(z) {
    return z.object({
      ...ZodSchemas.buildRequest(z).shape,
      variables: z.record(z.string(), VariablesZodSchemas.buildVariablesReturnType(z)).optional(),
      V: z.record(z.string(), VariablesZodSchemas.buildVariablesReturnType(z)).optional(),
    });
  }

  static buildVariablesReturnType(z) {
    return z.unknown();
  }
}

module.exports = { VariablesZodSchemas };
