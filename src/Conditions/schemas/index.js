const { ConstantsZodSchemas } = require('../../Constants/schemas');
const { JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');
const { VariablesZodSchemas } = require('../../Variables/schemas');

/**
 * Zod schema builders for conditions.
 */
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

/**
 * Plain JSON Schema builders for conditions.
 */
class ConditionsJsonSchemas extends JsonSchemas {
  static buildFullRequest() {
    return JsonSchemas.mergeObjectShapes(
      JsonSchemas.buildRequest(),
      JsonSchemas.buildObjectShape(
        {
          constants: JsonSchemas.buildUnknownRecordShape(),
          C: JsonSchemas.buildUnknownRecordShape(),
          variables: JsonSchemas.buildUnknownRecordShape(),
          V: JsonSchemas.buildUnknownRecordShape(),
        },
        []
      )
    );
  }

  static buildConditionSingleMatchExpr() {
    return JsonSchemas.buildFunctionShape();
  }

  static buildConditionMatchShape() {
    return {
      anyOf: [
        ConditionsJsonSchemas.buildConditionSingleMatchExpr(),
        {
          type: 'object',
          properties: {
            any: JsonSchemas.buildNonEmptyArrayShape(true),
            all: JsonSchemas.buildNonEmptyArrayShape(true),
            none: JsonSchemas.buildNonEmptyArrayShape(true),
          },
          additionalProperties: false,
          minProperties: 1,
        },
      ],
    };
  }

  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        match: ConditionsJsonSchemas.buildConditionMatchShape(),
      },
      ['match']
    );
  }
}

/**
 * TypeBox schema builders for conditions.
 */
class ConditionsTypeBoxSchemas extends TypeBoxSchemas {
  static buildFullRequest(t) {
    return t.Object({
      ...TypeBoxSchemas.buildRequest(t).properties,
      constants: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
      C: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
      variables: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
      V: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
    });
  }

  static buildConditionSingleMatchExpr(t) {
    return TypeBoxSchemas.buildFunctionShape(t);
  }

  static buildConditionMatchShape(t) {
    return t.Recursive((Self) =>
      t.Union([
        ConditionsTypeBoxSchemas.buildConditionSingleMatchExpr(t),
        t.Object({ any: TypeBoxSchemas.buildNonEmptyArrayShape(t, Self) }),
        t.Object({ all: TypeBoxSchemas.buildNonEmptyArrayShape(t, Self) }),
        t.Object({ none: TypeBoxSchemas.buildNonEmptyArrayShape(t, Self) }),
      ])
    );
  }

  static buildShape(t) {
    return t.Object({
      match: ConditionsTypeBoxSchemas.buildConditionMatchShape(t),
    });
  }
}

module.exports = {
  ConditionsJsonSchemas,
  ConditionsTypeBoxSchemas,
  ConditionsZodSchemas,
};
