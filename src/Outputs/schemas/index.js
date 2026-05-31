const { ConditionsZodSchemas } = require('../../Conditions/schemas');
const { JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');

/**
 * Zod schema builders for outputs.
 */
class OutputsZodSchemas extends ZodSchemas {
  static buildShape(z) {
    return z.union([
      z.object({
        when: z.object({
          ruleActivated: z
            .function({
              input: [ConditionsZodSchemas.buildFullRequest(z)],
              output: z.unknown(),
            })
            .optional(),
          conditionNotMet: z
            .function({
              input: [ConditionsZodSchemas.buildFullRequest(z)],
              output: z.unknown(),
            })
            .optional(),
        }),
      }),
      z.function({
        input: [ConditionsZodSchemas.buildFullRequest(z)],
        output: z.unknown(),
      }),
    ]);
  }
}

/**
 * Plain JSON Schema builders for outputs.
 */
class OutputsJsonSchemas extends JsonSchemas {
  static buildShape() {
    return {
      anyOf: [
        JsonSchemas.buildObjectShape(
          {
            when: JsonSchemas.buildObjectShape(
              {
                ruleActivated: JsonSchemas.buildFunctionShape(),
                conditionNotMet: JsonSchemas.buildFunctionShape(),
              },
              []
            ),
          },
          ['when']
        ),
        JsonSchemas.buildFunctionShape(),
      ],
    };
  }
}

/**
 * TypeBox schema builders for outputs.
 */
class OutputsTypeBoxSchemas extends TypeBoxSchemas {
  static buildShape(t) {
    return t.Union([
      t.Object({
        when: t.Object({
          ruleActivated: t.Optional(TypeBoxSchemas.buildFunctionShape(t)),
          conditionNotMet: t.Optional(TypeBoxSchemas.buildFunctionShape(t)),
        }),
      }),
      TypeBoxSchemas.buildFunctionShape(t),
    ]);
  }
}

module.exports = {
  OutputsJsonSchemas,
  OutputsTypeBoxSchemas,
  OutputsZodSchemas,
};
