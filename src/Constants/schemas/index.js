const { JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');

/**
 * Zod schema builders for constants.
 */
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

/**
 * Plain JSON Schema builders for constants.
 */
class ConstantsJsonSchemas extends JsonSchemas {
  static buildShape() {
    return JsonSchemas.buildUnknownRecordShape();
  }

  static buildRequestWithConstants() {
    return JsonSchemas.mergeObjectShapes(
      JsonSchemas.buildRequest(),
      JsonSchemas.buildObjectShape(
        {
          constants: ConstantsJsonSchemas.buildShape(),
          C: ConstantsJsonSchemas.buildShape(),
        },
        []
      )
    );
  }
}

/**
 * TypeBox schema builders for constants.
 */
class ConstantsTypeBoxSchemas extends TypeBoxSchemas {
  static buildShape(t) {
    return TypeBoxSchemas.buildUnknownRecordShape(t);
  }

  static buildRequestWithConstants(t) {
    return t.Object({
      ...TypeBoxSchemas.buildRequest(t).properties,
      constants: t.Optional(ConstantsTypeBoxSchemas.buildShape(t)),
      C: t.Optional(ConstantsTypeBoxSchemas.buildShape(t)),
    });
  }
}

module.exports = {
  ConstantsJsonSchemas,
  ConstantsTypeBoxSchemas,
  ConstantsZodSchemas,
};
