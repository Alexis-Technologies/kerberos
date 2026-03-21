const { registerAjvKeywords } = require('./ajv.js');

/**
 * Detects whether a value looks like a plain object schema rather than a parser.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Builds a parse-like adapter from a parser, validator or compiled Ajv function.
 *
 * @param {unknown} validator
 * @returns {{ parse: (value: unknown) => unknown } | null}
 */
function toValidationAdapter(validator) {
  if (!validator) return null;

  if (typeof validator.parse === 'function') {
    return {
      parse(value) {
        return validator.parse(value);
      },
    };
  }

  if (typeof validator.validate === 'function') {
    return {
      parse(value) {
        const result = validator.validate(value);
        if (result === false) throw new Error(validator.message ?? 'Validation failed');
        return result === true || result === undefined ? value : result;
      },
    };
  }

  if (typeof validator === 'function') {
    return {
      parse(value) {
        const result = validator(value);
        if (result === false) {
          const errors = validator.errors ? ` ${JSON.stringify(validator.errors)}` : '';
          throw new Error(`Validation failed.${errors}`.trim());
        }
        return result === true || result === undefined ? value : result;
      },
    };
  }

  return null;
}

/**
 * Compiles a JSON Schema / TypeBox schema with Ajv and returns a parse-like adapter.
 *
 * @param {{ compile?: (schema: Record<string, unknown>) => Function }} ajv
 * @param {Record<string, unknown>} schema
 * @returns {{ parse: (value: unknown) => unknown }}
 */
function createAjvAdapter(ajv, schema) {
  if (!ajv || typeof ajv.compile !== 'function') throw new TypeError('Ajv instance with compile() is required');

  const validate = ajv.compile(schema);
  return {
    parse(value) {
      const isValid = validate(value);
      if (!isValid) {
        const errors = validate.errors ? ` ${JSON.stringify(validate.errors)}` : '';
        throw new Error(`Validation failed.${errors}`.trim());
      }
      return value;
    },
  };
}

/**
 * Resolves the appropriate validation adapter using the supported backends.
 *
 * Priority:
 * 1. Explicit schema / parser
 * 2. Zod builders
 * 3. TypeBox builders compiled with Ajv
 * 4. JSON Schema builders compiled with Ajv
 *
 * @param {object} options
 * @param {unknown} [options.schema]
 * @param {unknown} [options.z]
 * @param {unknown} [options.ajv]
 * @param {unknown} [options.typebox]
 * @param {(z: unknown) => unknown} [options.buildZod]
 * @param {(typebox: unknown) => Record<string, unknown>} [options.buildTypeBox]
 * @param {() => Record<string, unknown>} [options.buildJson]
 * @returns {{ parse: (value: unknown) => unknown } | null}
 */
function resolveValidationAdapter({ schema, z, ajv, typebox, buildZod, buildTypeBox, buildJson }) {
  const explicitAdapter = toValidationAdapter(schema);
  if (explicitAdapter) return explicitAdapter;

  if (schema && isPlainObject(schema) && ajv) return createAjvAdapter(ajv, schema);
  if (z && typeof buildZod === 'function') return toValidationAdapter(buildZod(z));
  if (ajv && typebox && typeof buildTypeBox === 'function') return createAjvAdapter(ajv, buildTypeBox(typebox));
  if (ajv && typeof buildJson === 'function') return createAjvAdapter(ajv, buildJson());

  return null;
}

/**
 * Parses a value with the best available validation backend, or returns it as-is.
 *
 * @param {unknown} value
 * @param {object} options
 * @returns {unknown}
 */
function parseWithValidation(value, options) {
  const adapter = resolveValidationAdapter(options);
  return adapter ? adapter.parse(value) : value;
}

module.exports = {
  createAjvAdapter,
  parseWithValidation,
  registerAjvKeywords,
  resolveValidationAdapter,
  toValidationAdapter,
};
