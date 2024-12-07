const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { commonRolesPolicy, principalsPolicy, resourcesPolicy } = require('./mocks/index.js');

const { DerivedRoles } = require('../src/index.js');

describe('DerivedRoles', () => {
  it('should parse schema', () => {
    const derivedRoles = new DerivedRoles(commonRolesPolicy);

    assert.strictEqual(derivedRoles.name, 'common_roles');
    assert.strictEqual(derivedRoles.roles.size, 4);
    assert.strictEqual(derivedRoles.schema.variables, undefined);
    assert.strictEqual(derivedRoles.schema.constants, undefined);
  });

  it('should get roles', () => {
    const R = resourcesPolicy.expense1;

    const derivedRoles = new DerivedRoles(commonRolesPolicy);

    assert.deepEqual([...derivedRoles.get({ P: principalsPolicy.sally, principal: principalsPolicy.sally, R, resource: R })], ['OWNER']);
    assert.deepEqual([...derivedRoles.get({ P: principalsPolicy.ian, principal: principalsPolicy.ian, R, resource: R })], []);
    assert.deepEqual([...derivedRoles.get({ P: principalsPolicy.frank, principal: principalsPolicy.frank, R, resource: R })], ['FINANCE']);
    assert.deepEqual([...derivedRoles.get({ P: principalsPolicy.derek, principal: principalsPolicy.derek, R, resource: R })], ['FINANCE', 'FINANCE_MANAGER', 'REGION_MANAGER']);
    assert.deepEqual([...derivedRoles.get({ P: principalsPolicy.simon, principal: principalsPolicy.simon, R, resource: R })], []);
    assert.deepEqual([...derivedRoles.get({ P: principalsPolicy.mark, principal: principalsPolicy.mark, R, resource: R })], ['REGION_MANAGER']);
    assert.deepEqual([...derivedRoles.get({ P: principalsPolicy.sydney, principal: principalsPolicy.sydney, R, resource: R })], []);
  });
});
