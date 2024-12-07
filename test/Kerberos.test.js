const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { commonRolesPolicy, principalsPolicy, resourcesPolicy, expensePolicy } = require('./mocks/index.js');

const { Effect, Kerberos } = require('../src/index.js');

describe('Kerberos', () => {
  const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy], { logger: true });

  describe('isAllowed', () => {
    it('should return true if the action is allowed', () => {
      const principal = principalsPolicy.sally;
      const resource = resourcesPolicy.expense1;
      const action = 'view';

      const isAllowed = kerberos.isAllowed({ principal, action, resource });

      assert.strictEqual(isAllowed, true);
    });

    it('should return false if the action is not allowed', () => {
      const principal = principalsPolicy.sally;
      const resource = resourcesPolicy.expense1;
      const action = 'approve';

      const isAllowed = kerberos.isAllowed({ principal, action, resource });

      assert.strictEqual(isAllowed, false);
    });
  });

  describe('checkResources', () => {
    it('should return the effect actions map for each resource (Effect mode)', () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view', 'create', 'delete'] },
        { resource: resourcesPolicy.expense4, actions: ['view', 'create'] },
      ];

      const results = kerberos.checkResources({ principal, resources });

      assert.deepStrictEqual(results, {
        results: [
          {
            resource: { id: 'expense1', kind: 'expense' },
            actions: { view: Effect.Allow, create: Effect.Allow, delete: Effect.Deny },
          },
          {
            resource: { id: 'expense4', kind: 'expense' },
            actions: { view: Effect.Deny, create: Effect.Allow },
          },
        ],
      });
    });

    it('should return the effect actions map for each resource (Boolean mode)', () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view', 'create', 'delete'] },
        { resource: resourcesPolicy.expense4, actions: ['view', 'create'] },
      ];

      const results = kerberos.checkResources({ principal, resources }, true);

      assert.deepStrictEqual(results, {
        results: [
          {
            resource: { id: 'expense1', kind: 'expense' },
            actions: { view: true, create: true, delete: false },
          },
          {
            resource: { id: 'expense4', kind: 'expense' },
            actions: { view: false, create: true },
          },
        ],
      });
    });
  });
});
