const { parseWithValidation } = require('../../validation');
const { ConditionsJsonSchemas, ConditionsTypeBoxSchemas, ConditionsZodSchemas } = require('../schemas');

/**
 * Parses condition input with the configured validation backend.
 *
 * @param {unknown} shape
 * @param {object} [options]
 * @returns {unknown}
 */
function parseConditionsShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => ConditionsJsonSchemas.buildShape(),
    buildTypeBox: (t) => ConditionsTypeBoxSchemas.buildShape(t),
    buildZod: (z) => ConditionsZodSchemas.buildShape(z),
  });
}

module.exports = {
  parseConditionsShape,
};
