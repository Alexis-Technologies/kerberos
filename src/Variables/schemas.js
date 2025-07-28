const { z } = require('zod');

const { ZodSchemas, RequestSchema } = require('../schemas.js');
const { RequestWithConstantsSchema } = require('../Constants');

const VariablesReturnTypeSchema = z.unknown();

const VariablesSchemaSchema = z.record(z.string(), z.function().args(RequestWithConstantsSchema).returns(VariablesReturnTypeSchema));

const RequestWithVariablesSchema = RequestSchema.extend({
  variables: z.record(z.string(), VariablesReturnTypeSchema).optional(),
  V: z.record(z.string(), VariablesReturnTypeSchema).optional(),
});

class VariablesZodSchemas extends ZodSchemas {
  static buildShape(z) {
    return z.record(z.string(), z.function().args(RequestWithConstantsSchema).returns(VariablesZodSchemas.buildVariablesReturnType(z)));
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

module.exports = {
  VariablesZodSchemas,
  VariablesSchemaSchema,
  RequestWithVariablesSchema,
  VariablesReturnTypeSchema,
};
