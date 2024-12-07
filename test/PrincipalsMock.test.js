import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import { principalsPolicy } from './mocks/index.js';

import { PrincipalsMock } from '../src/Tests/index.js';

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
