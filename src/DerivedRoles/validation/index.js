const { parseWithValidation } = require('../../validation');
const { DerivedRolesJsonSchemas, DerivedRolesTypeBoxSchemas, DerivedRolesZodSchemas } = require('../schemas');

/**
 * Parses derived roles input with the configured validation backend.
 *
 * @param {unknown} shape
 * @param {object} [options]
 * @returns {unknown}
 */
function parseDerivedRolesShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => DerivedRolesJsonSchemas.buildShape(),
    buildTypeBox: (t) => DerivedRolesTypeBoxSchemas.buildShape(t),
    buildZod: (z) => DerivedRolesZodSchemas.buildShape(z),
  });
}

module.exports = {
  parseDerivedRolesShape,
};
