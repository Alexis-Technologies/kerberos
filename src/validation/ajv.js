const { KERBEROS_TYPE_KEYWORD, KERBEROS_INSTANCE_OF_KEYWORD } = require('./keywords.js');

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
        switch (expectedType) {
          case 'bigint':
            return typeof value === 'bigint';
          case 'boolean':
            return typeof value === 'boolean';
          case 'function':
            return typeof value === 'function';
          case 'number':
            return typeof value === 'number';
          case 'object':
            return typeof value === 'object';
          case 'string':
            return typeof value === 'string';
          case 'symbol':
            return typeof value === 'symbol';
          case 'undefined':
            return typeof value === 'undefined';
          default:
            return false;
        }
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
