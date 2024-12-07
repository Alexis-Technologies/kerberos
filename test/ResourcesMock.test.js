import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import { resourcesPolicy } from './mocks/index.js';

import { ResourcesMock } from '../src/Tests/index.js';

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
