const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { resourcesPolicy } = require('./mocks/index.js');

const { ResourceMock } = require('@alexify/kerberos/tests');

describe('ResourceMock', () => {
  it('should parse schema correctly', () => {
    const resource = new ResourceMock({ ...resourcesPolicy.expense1, name: 'expense1' });

    assert.equal(resource.id, resourcesPolicy.expense1.id);
    assert.equal(resource.name, 'expense1');
    assert.equal(resource.kind, resourcesPolicy.expense1.kind);
    assert.deepEqual(resource.attr, resourcesPolicy.expense1.attr);
  });

  it('should expose policyVersion and scope when provided', () => {
    const resource = new ResourceMock({
      ...resourcesPolicy.expense1,
      name: 'expense1',
      policyVersion: '20210210',
      scope: 'acme.corp',
    });

    assert.strictEqual(resource.policyVersion, '20210210');
    assert.strictEqual(resource.scope, 'acme.corp');
  });
});
