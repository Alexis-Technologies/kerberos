const { parseWithValidation } = require('../../validation');
const { PrincipalPolicyJsonSchemas, PrincipalPolicyTypeBoxSchemas, PrincipalPolicyZodSchemas } = require('../schemas');

function parsePrincipalPolicyShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => PrincipalPolicyJsonSchemas.buildShape(),
    buildTypeBox: (t) => PrincipalPolicyTypeBoxSchemas.buildShape(t),
    buildZod: (z) => PrincipalPolicyZodSchemas.buildShape(z),
  });
}

module.exports = {
  parsePrincipalPolicyShape,
};
