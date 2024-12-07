const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { principalsPolicy } = require('./mocks/index.js');
const { PrincipalMock } = require('../src/Tests/index.js');

describe('PrincipalMock', () => {
  it('should parse schema correctly', () => {
    const principal = new PrincipalMock({ ...principalsPolicy.sally, name: 'sally' });

    assert.strictEqual(principal.id, principalsPolicy.sally.id);
    assert.strictEqual(principal.name, 'sally');
    assert.deepEqual(principal.roles, principalsPolicy.sally.roles);
    assert.deepEqual(principal.attr, principalsPolicy.sally.attr);
  });
});
