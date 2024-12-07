const { z } = require('zod');

const { RequestSchema } = require('../schemas.js');
const { RequestWithConstantsSchema } = require('../Constants');

const VariablesReturnTypeSchema = z.unknown();

const VariablesSchemaSchema = z.record(z.string(), z.function().args(RequestWithConstantsSchema).returns(VariablesReturnTypeSchema));

const RequestWithVariablesSchema = RequestSchema.extend({
  variables: z.record(z.string(), VariablesReturnTypeSchema).optional(),
  V: z.record(z.string(), VariablesReturnTypeSchema).optional(),
});

module.exports = {
  VariablesSchemaSchema,
  RequestWithVariablesSchema,
  VariablesReturnTypeSchema,
};
