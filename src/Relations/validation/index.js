const { parseWithValidation } = require('../../validation');
const { RelationsJsonSchemas, RelationsTypeBoxSchemas, RelationsZodSchemas } = require('../schemas');

/**
 * Parses a relation schema input with the configured validation backend.
 *
 * @param {unknown} shape
 * @param {object} [options]
 * @returns {unknown}
 */
function parseRelationSchemaShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => RelationsJsonSchemas.buildShape(),
    buildTypeBox: (t) => RelationsTypeBoxSchemas.buildShape(t),
    buildZod: (z) => RelationsZodSchemas.buildShape(z),
  });
}

module.exports = {
  parseRelationSchemaShape,
};
