const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { resourcesPolicy } = require('./mocks/index.js');

const { ResourcesMock } = require('../src/Tests/index.js');

describe('ResourcesMock', () => {
  it('should parse schema correctly', () => {
    const resource = new ResourcesMock(resourcesPolicy);

    assert.strictEqual(resource.mocks.length, 5);
    assert.strictEqual(resource.get('expense1').name, 'expense1');
    assert.strictEqual(resource.get('expense1').id, resourcesPolicy.expense1.id);
    assert.strictEqual(resource.get('expense1').kind, resourcesPolicy.expense1.kind);
    assert.deepEqual(resource.get('expense1').attr, resourcesPolicy.expense1.attr);
    assert.deepEqual(resource.getById(resourcesPolicy.expense1.id).attr, resourcesPolicy.expense1.attr);
  });
});
