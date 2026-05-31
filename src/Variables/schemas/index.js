const { ConstantsZodSchemas } = require('../../Constants/schemas');
const { JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');

/**
 * Zod schema builders for variables.
 */
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

/**
 * Plain JSON Schema builders for variables.
 */
class VariablesJsonSchemas extends JsonSchemas {
  static buildShape() {
    return JsonSchemas.buildRecordShape(JsonSchemas.buildFunctionShape());
  }

  static buildRequestWithVariables() {
    return JsonSchemas.mergeObjectShapes(
      JsonSchemas.buildRequest(),
      JsonSchemas.buildObjectShape(
        {
          variables: JsonSchemas.buildUnknownRecordShape(),
          V: JsonSchemas.buildUnknownRecordShape(),
        },
        []
      )
    );
  }

  static buildVariablesReturnType() {
    return true;
  }
}

/**
 * TypeBox schema builders for variables.
 */
class VariablesTypeBoxSchemas extends TypeBoxSchemas {
  static buildShape(t) {
    return t.Record(t.String(), TypeBoxSchemas.buildFunctionShape(t));
  }

  static buildRequestWithVariables(t) {
    return t.Object({
      ...TypeBoxSchemas.buildRequest(t).properties,
      variables: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
      V: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
    });
  }

  static buildVariablesReturnType(t) {
    return t.Unknown();
  }
}

module.exports = {
  VariablesJsonSchemas,
  VariablesTypeBoxSchemas,
  VariablesZodSchemas,
};
