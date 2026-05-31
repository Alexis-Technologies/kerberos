const { parseWithValidation } = require('../../validation');
const {
  KerberosTestJsonSchemas,
  KerberosTestTypeBoxSchemas,
  KerberosTestZodSchemas,
  KerberosTestsJsonSchemas,
  KerberosTestsTypeBoxSchemas,
  KerberosTestsZodSchemas,
} = require('../schemas');

function parseKerberosTestShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => KerberosTestJsonSchemas.buildShape(),
    buildTypeBox: (t) => KerberosTestTypeBoxSchemas.buildShape(t),
    buildZod: (z) => KerberosTestZodSchemas.buildShape(z),
  });
}

function parseKerberosTestsPolicies(policies, KerberosTest, options = {}) {
  return parseWithValidation(policies, {
    ...options,
    buildJson: () => KerberosTestsJsonSchemas.buildShape(KerberosTest),
    buildTypeBox: (t) => KerberosTestsTypeBoxSchemas.buildShape(t, KerberosTest),
    buildZod: (z) => KerberosTestsZodSchemas.buildShape(z, KerberosTest),
  });
}

module.exports = {
  parseKerberosTestShape,
  parseKerberosTestsPolicies,
};
