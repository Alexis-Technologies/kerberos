const { parseWithValidation } = require('../../validation');
const { OutputsJsonSchemas, OutputsTypeBoxSchemas, OutputsZodSchemas } = require('../schemas');

/**
 * Parses outputs input with the configured validation backend.
 *
 * @param {unknown} shape
 * @param {object} [options]
 * @returns {unknown}
 */
function parseOutputsShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => OutputsJsonSchemas.buildShape(),
    buildTypeBox: (t) => OutputsTypeBoxSchemas.buildShape(t),
    buildZod: (z) => OutputsZodSchemas.buildShape(z),
  });
}

module.exports = {
  parseOutputsShape,
};
