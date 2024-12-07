const { z } = require('zod');
const { RequestSchema } = require('../schemas.js');

const ConstantsSchemaSchema = z.record(z.string(), z.unknown());

const RequestWithConstantsSchema = RequestSchema.extend({
  constants: ConstantsSchemaSchema.optional(),
  C: ConstantsSchemaSchema.optional(),
});

module.exports = {
  ConstantsSchemaSchema,
  RequestWithConstantsSchema,
};
