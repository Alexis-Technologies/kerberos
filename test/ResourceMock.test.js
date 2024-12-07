import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import { resourcesPolicy } from './mocks/index.js';

import { ResourceMock } from '../src/Tests/index.js';

describe('ResourceMock', () => {
  it('should parse schema correctly', () => {
    const resource = new ResourceMock({ ...resourcesPolicy.expense1, name: 'expense1' });

    assert.equal(resource.id, resourcesPolicy.expense1.id);
    assert.equal(resource.name, 'expense1');
    assert.equal(resource.kind, resourcesPolicy.expense1.kind);
    assert.deepEqual(resource.attr, resourcesPolicy.expense1.attr);
  });
});
