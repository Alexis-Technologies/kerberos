const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { resourcesPolicy } = require('./mocks/index.js');

const { ResourceMock } = require('../src/Tests/index.js');

describe('ResourceMock', () => {
  it('should parse schema correctly', () => {
    const resource = new ResourceMock({ ...resourcesPolicy.expense1, name: 'expense1' });

    assert.equal(resource.id, resourcesPolicy.expense1.id);
    assert.equal(resource.name, 'expense1');
    assert.equal(resource.kind, resourcesPolicy.expense1.kind);
    assert.deepEqual(resource.attr, resourcesPolicy.expense1.attr);
  });
});
