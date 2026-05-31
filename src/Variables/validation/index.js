const { parseWithValidation } = require('../../validation');
const { VariablesJsonSchemas, VariablesTypeBoxSchemas, VariablesZodSchemas } = require('../schemas');

/**
 * Parses variables input with the configured validation backend.
 *
 * @param {unknown} shape
 * @param {object} [options]
 * @returns {unknown}
 */
function parseVariablesShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => VariablesJsonSchemas.buildShape(),
    buildTypeBox: (t) => VariablesTypeBoxSchemas.buildShape(t),
    buildZod: (z) => VariablesZodSchemas.buildShape(z),
  });
}

module.exports = {
  parseVariablesShape,
};
