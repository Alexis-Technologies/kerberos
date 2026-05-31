const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { principalsPolicy, resourcesPolicy, userRolePolicy } = require('./mocks/index.js');
const { Effect, RolePolicy } = require('../src/index.js');

describe('RolePolicy', () => {
  const rolePolicy = new RolePolicy(userRolePolicy);

  it('should expose role target and rules', () => {
    assert.strictEqual(rolePolicy.role, 'USER');
    assert.strictEqual(rolePolicy.version, 'default');
    assert.deepStrictEqual(rolePolicy.parentRoles, []);
    assert.strictEqual(rolePolicy.rules.length, 2);
  });

  it('should allow listed actions and deny missing actions for matching resources', () => {
    const principal = principalsPolicy.sally;
    const resource = resourcesPolicy.expense2;
    const req = { P: principal, principal, R: resource, resource, actions: ['create', 'delete'] };

    const { effects } = rolePolicy.check(req);

    assert.deepStrictEqual(Object.fromEntries(effects), {
      create: Effect.Allow,
      delete: Effect.Deny,
    });
  });

  it('should deny when a rule condition is not fulfilled and emit conditionNotMet output', () => {
    const principal = principalsPolicy.sally;
    const resource = resourcesPolicy.expense1;
    const req = { P: principal, principal, R: resource, resource, actions: ['view'] };

    const { effects, outputs, meta } = rolePolicy.check(req);

    assert.deepStrictEqual(Object.fromEntries(effects), {
      view: Effect.Deny,
    });
    assert.strictEqual(outputs.size, 1);
    assert.strictEqual(outputs.values().next().value.val.message, 'Role policy blocked restricted vendor view');
    assert.strictEqual(meta.actions.view.matchedPolicy, 'role.USER.vdefault');
  });

  it('should support wildcard resource matching', () => {
    const wildcardPolicy = new RolePolicy({
      rolePolicy: {
        role: 'AUDITOR',
        version: 'default',
        rules: [
          {
            resource: '*',
            allowActions: ['view'],
          },
        ],
      },
    });
    const principal = { id: 'audrey', roles: ['AUDITOR'] };
    const resource = resourcesPolicy.expense2;
    const req = { P: principal, principal, R: resource, resource, actions: ['view', 'create'] };

    const { effects } = wildcardPolicy.check(req);

    assert.deepStrictEqual(Object.fromEntries(effects), {
      view: Effect.Allow,
      create: Effect.Deny,
    });
  });
});
