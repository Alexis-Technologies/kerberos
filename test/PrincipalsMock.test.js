const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { principalsPolicy } = require('./mocks/index.js');

const { PrincipalsMock } = require('../src/Tests/index.js');

describe('PrincipalsMock', () => {
  it('should parse schema correctly', () => {
    const principal = new PrincipalsMock(principalsPolicy);

    assert.strictEqual(principal.mocks.length, 7);
    assert.strictEqual(principal.get('sally').name, 'sally');
    assert.strictEqual(principal.get('sally').id, principalsPolicy.sally.id);
    assert.deepEqual(principal.get('sally').roles, principalsPolicy.sally.roles);
    assert.deepEqual(principal.get('sally').attr, principalsPolicy.sally.attr);
  });
});
