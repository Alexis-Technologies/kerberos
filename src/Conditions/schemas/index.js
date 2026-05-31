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
    // A single object with three optional strategies (instead of a union of
    // single-key objects). Zod strips unknown keys when parsing, so a union of
    // single-key objects silently dropped the other strategies from a
    // multi-strategy match like `{ all: [...], none: [...] }`. `.refine()` keeps
    // the structural invariant (at least one strategy) while staying lenient to
    // unknown keys, matching the JSON Schema and TypeBox backends.
    const matchShape = z.lazy(() =>
      z.union([
        ConditionsZodSchemas.buildConditionSingleMatchExpr(z),
        z
          .object({
            any: z.array(matchShape).nonempty().optional(),
            all: z.array(matchShape).nonempty().optional(),
            none: z.array(matchShape).nonempty().optional(),
          })
          .refine(
            (value) => value.any !== undefined || value.all !== undefined || value.none !== undefined,
            { message: 'A condition match must define at least one of "any", "all", or "none".' }
          ),
      ])
    );
    return matchShape;
  }

  static buildShape(z) {
    return z.object({ match: ConditionsZodSchemas.buildConditionMatchShape(z) });
  }
}

/**
 * Plain JSON Schema builders for conditions.
 */
class ConditionsJsonSchemas extends JsonSchemas {
  // Monotonic counter that keeps each generated condition-match `$id` unique so
  // recursive `$ref`s never collide across embedded policy schemas.
  static #matchSchemaSeq = 0;

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
    // Recursively validate nested condition entries. The subschema gets a unique
    // `$id` so its strategy arrays can `$ref` back to it (full recursion),
    // while staying collision-free when embedded in several policy schemas on
    // the same Ajv instance. We stay lenient to unknown keys
    // (`additionalProperties: true`) but still require at least one valid
    // strategy via `anyOf`, so a malformed match with no strategy (or a
    // primitive leaf) is rejected while extra/forward-compat keys are tolerated.
    // This mirrors the TypeBox/Zod backends.
    const $id = `kerberos:condition-match-${(ConditionsJsonSchemas.#matchSchemaSeq += 1)}`;
    const self = { $ref: $id };
    return {
      $id,
      anyOf: [
        ConditionsJsonSchemas.buildConditionSingleMatchExpr(),
        {
          type: 'object',
          properties: {
            any: JsonSchemas.buildNonEmptyArrayShape(self),
            all: JsonSchemas.buildNonEmptyArrayShape(self),
            none: JsonSchemas.buildNonEmptyArrayShape(self),
          },
          additionalProperties: true,
          anyOf: [
            { required: ['any'] },
            { required: ['all'] },
            { required: ['none'] },
          ],
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
