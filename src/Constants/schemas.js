const { z } = require('zod');

const { RequestSchema, ZodSchemas } = require('../schemas.js');

class ConstantsZodSchemas extends ZodSchemas {
  static buildShape(z) {
    return z.record(z.string(), z.unknown());
  }

  static buildRequestWithConstants(z) {
    return z.object({
      ...ZodSchemas.buildRequest(z).shape,
      constants: ConstantsZodSchemas.buildShape(z).optional(),
      C: ConstantsZodSchemas.buildShape(z).optional(),
    });
  }
}

const ConstantsSchemaSchema = z.record(z.string(), z.unknown());

const RequestWithConstantsSchema = RequestSchema.extend({
  constants: ConstantsSchemaSchema.optional(),
  C: ConstantsSchemaSchema.optional(),
});

module.exports = {
  ConstantsZodSchemas,
  ConstantsSchemaSchema,
  RequestWithConstantsSchema,
};
