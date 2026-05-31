const { KERBEROS_TYPE_KEYWORD, KERBEROS_INSTANCE_OF_KEYWORD } = require('./keywords.js');

// O(1) strategy dispatch for the `typeof` check keyword. A prototype-less table
// guards against poisoned `expectedType` values (e.g. "constructor"), and the
// literal-string predicates satisfy the `valid-typeof` lint rule.
const TYPE_CHECKS = Object.assign(Object.create(null), {
  bigint: (value) => typeof value === 'bigint',
  boolean: (value) => typeof value === 'boolean',
  function: (value) => typeof value === 'function',
  number: (value) => typeof value === 'number',
  object: (value) => typeof value === 'object',
  string: (value) => typeof value === 'string',
  symbol: (value) => typeof value === 'symbol',
  undefined: (value) => typeof value === 'undefined',
});

/**
 * Registers Kerberos-specific Ajv keywords needed to validate the policy DSL.
 *
 * @param {{ addKeyword?: (config: Record<string, unknown>) => unknown }} ajv
 * @returns {unknown}
 */
function registerAjvKeywords(ajv) {
  if (!ajv || typeof ajv.addKeyword !== 'function') throw new TypeError('Ajv instance with addKeyword() is required');

  if (!ajv.getKeyword?.(KERBEROS_TYPE_KEYWORD)) {
    ajv.addKeyword({
      keyword: KERBEROS_TYPE_KEYWORD,
      schemaType: 'string',
      errors: false,
      validate(expectedType, value) {
        const check = TYPE_CHECKS[expectedType];
        return check ? check(value) : false;
      },
    });
  }

  if (!ajv.getKeyword?.(KERBEROS_INSTANCE_OF_KEYWORD)) {
    ajv.addKeyword({
      keyword: KERBEROS_INSTANCE_OF_KEYWORD,
      errors: false,
      validate(ExpectedClass, value) {
        return typeof ExpectedClass === 'function' && value instanceof ExpectedClass;
      },
    });
  }

  return ajv;
}

module.exports = {
  registerAjvKeywords,
};
