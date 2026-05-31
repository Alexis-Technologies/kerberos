const { parseWithValidation } = require('../../../validation');
const {
  PrincipalMockJsonSchemas,
  PrincipalMockTypeBoxSchemas,
  PrincipalMockZodSchemas,
  PrincipalsMockJsonSchemas,
  PrincipalsMockTypeBoxSchemas,
  PrincipalsMockZodSchemas,
  ResourceMockJsonSchemas,
  ResourceMockTypeBoxSchemas,
  ResourceMockZodSchemas,
  ResourcesMockJsonSchemas,
  ResourcesMockTypeBoxSchemas,
  ResourcesMockZodSchemas,
} = require('../schemas');

function parsePrincipalMockShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => PrincipalMockJsonSchemas.buildShape(),
    buildTypeBox: (t) => PrincipalMockTypeBoxSchemas.buildShape(t),
    buildZod: (z) => PrincipalMockZodSchemas.buildShape(z),
  });
}

function parsePrincipalsMockShape(shape, PrincipalMock, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => PrincipalsMockJsonSchemas.buildShape(PrincipalMock),
    buildTypeBox: (t) => PrincipalsMockTypeBoxSchemas.buildShape(t, PrincipalMock),
    buildZod: (z) => PrincipalsMockZodSchemas.buildShape(z, PrincipalMock),
  });
}

function parseResourceMockShape(shape, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => ResourceMockJsonSchemas.buildShape(),
    buildTypeBox: (t) => ResourceMockTypeBoxSchemas.buildShape(t),
    buildZod: (z) => ResourceMockZodSchemas.buildShape(z),
  });
}

function parseResourcesMockShape(shape, ResourceMock, options = {}) {
  return parseWithValidation(shape, {
    ...options,
    buildJson: () => ResourcesMockJsonSchemas.buildShape(ResourceMock),
    buildTypeBox: (t) => ResourcesMockTypeBoxSchemas.buildShape(t, ResourceMock),
    buildZod: (z) => ResourcesMockZodSchemas.buildShape(z, ResourceMock),
  });
}

module.exports = {
  parsePrincipalMockShape,
  parsePrincipalsMockShape,
  parseResourceMockShape,
  parseResourcesMockShape,
};
