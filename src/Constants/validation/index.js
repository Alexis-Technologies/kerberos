const { parseWithValidation } = require('../../validation');
const { ConstantsJsonSchemas, ConstantsTypeBoxSchemas, ConstantsZodSchemas } = require('../schemas');

/**
 * Parses constants input with the configured validation backend.
 *
 * @param {unknown} shape
 * @param {object} [options]
 * @returns {unknown}
 */
function parseConstantsShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => ConstantsJsonSchemas.buildShape(),
    buildTypeBox: (t) => ConstantsTypeBoxSchemas.buildShape(t),
    buildZod: (z) => ConstantsZodSchemas.buildShape(z),
  });
}

module.exports = {
  parseConstantsShape,
};
