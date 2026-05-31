const { parseWithValidation } = require('../../validation');
const { RolePolicyJsonSchemas, RolePolicyTypeBoxSchemas, RolePolicyZodSchemas } = require('../schemas');

function parseRolePolicyShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => RolePolicyJsonSchemas.buildShape(),
    buildTypeBox: (t) => RolePolicyTypeBoxSchemas.buildShape(t),
    buildZod: (z) => RolePolicyZodSchemas.buildShape(z),
  });
}

module.exports = {
  parseRolePolicyShape,
};
