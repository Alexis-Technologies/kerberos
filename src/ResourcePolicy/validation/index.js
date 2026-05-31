const { parseWithValidation } = require('../../validation');
const { ResourcePolicyJsonSchemas, ResourcePolicyTypeBoxSchemas, ResourcePolicyZodSchemas } = require('../schemas');

/**
 * Parses resource policy input with the configured validation backend.
 *
 * @param {unknown} shape
 * @param {object} [options]
 * @returns {unknown}
 */
function parseResourcePolicyShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => ResourcePolicyJsonSchemas.buildShape(),
    buildTypeBox: (t) => ResourcePolicyTypeBoxSchemas.buildShape(t),
    buildZod: (z) => ResourcePolicyZodSchemas.buildShape(z),
  });
}

module.exports = {
  parseResourcePolicyShape,
};
