import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import { principalsPolicy } from './mocks/index.js';

import { PrincipalMock } from '../src/Tests/index.js';

describe('PrincipalMock', () => {
  it('should parse schema correctly', () => {
    const principal = new PrincipalMock({ ...principalsPolicy.sally, name: 'sally' });

    assert.strictEqual(principal.id, principalsPolicy.sally.id);
    assert.strictEqual(principal.name, 'sally');
    assert.deepEqual(principal.roles, principalsPolicy.sally.roles);
    assert.deepEqual(principal.attr, principalsPolicy.sally.attr);
  });
});
