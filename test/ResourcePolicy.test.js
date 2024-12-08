const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { commonRolesPolicy, principalsPolicy, resourcesPolicy, expensePolicy } = require('./mocks/index.js');

const { DerivedRoles, Effect, ResourcePolicy } = require('../src/index.js');

describe('ResourcePolicy', () => {
  const resourcePolicy = new ResourcePolicy(expensePolicy);

  it('should get kind', () => {
    assert.strictEqual(resourcePolicy.kind, 'expense');
  });

  it('should get importDerivedRoles', () => {
    assert.deepStrictEqual(resourcePolicy.importDerivedRoles, ['common_roles']);
  });

  it('should get rules', () => {
    assert.strictEqual(resourcePolicy.rules.length, 10);
  });

  describe('isAllowed', () => {
    it('should allow ADMIN to view', () => {
      const principal = principalsPolicy.ian;
      const resource = resourcesPolicy.expense1;
      const action = 'view';
      const req = { P: principal, principal, R: resource, resource, action };

      const isAllowed = resourcePolicy.isAllowed(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.strictEqual(isAllowed, true);
    });

    it('should allow OWNER to view', () => {
      const principal = principalsPolicy.sally;
      const resource = resourcesPolicy.expense1;
      const action = 'view';
      const req = { P: principal, principal, R: resource, resource, action };

      const isAllowed = resourcePolicy.isAllowed(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.strictEqual(isAllowed, true);
    });

    it('should allowed Frank to view expenses as FINANCE role', () => {
      const principal = principalsPolicy.frank;
      const resource = resourcesPolicy.expense1;
      const action = 'view';

      const req = { P: principal, principal, R: resource, resource, action };

      const isAllowed = resourcePolicy.isAllowed(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.strictEqual(isAllowed, true);
    });

    it('should allowed Derek to delete expenses as FINANCE_MANAGER', () => {
      const principal = principalsPolicy.derek;
      const resource = resourcesPolicy.expense1;
      const action = 'delete';

      const req = { P: principal, principal, R: resource, resource, action };

      const allowed = resourcePolicy.isAllowed(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.strictEqual(allowed, true);
    });

    it('should not allow Sally to approve expenses over $10,000', () => {
      const principal = principalsPolicy.sally;
      const resource = resourcesPolicy.expense3;
      const action = 'approve';

      const req = { P: principal, principal, R: resource, resource, action };

      const allowed = resourcePolicy.isAllowed(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.strictEqual(allowed, false);
    });

    it('should allow Mark to view expenses in his region as REGION_MANAGER', () => {
      const principal = principalsPolicy.mark;
      const resource = resourcesPolicy.expense1;
      const action = 'view';

      const req = { P: principal, principal, R: resource, resource, action };

      const allowed = resourcePolicy.isAllowed(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.strictEqual(allowed, true);
    });

    it('should not allow Simon to view expenses in a different region', () => {
      const principal = principalsPolicy.simon;
      const resource = resourcesPolicy.expense1;
      const action = 'view';

      const req = { P: principal, principal, R: resource, resource, action };

      const allowed = resourcePolicy.isAllowed(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.strictEqual(allowed, false);
    });

    it('should allow Ian to perform any action', () => {
      const principal = principalsPolicy.ian;
      const resource = resourcesPolicy.expense1;
      const actions = ['view', 'create', 'update', 'delete', 'approve', 'view:approver'];

      for (const action of actions) {
        const req = { P: principal, principal, R: resource, resource, action };

        const allowed = resourcePolicy.isAllowed(req, new DerivedRoles(commonRolesPolicy).get(req));

        assert.strictEqual(allowed, true);
      }
    });

    it('should allow Sally to delete her own expense if created within the last hour', () => {
      const principal = principalsPolicy.sally;
      const resource = { ...resourcesPolicy.expense1, attr: { ...resourcesPolicy.expense1.attr, createdAt: new Date(Date.now() - 30 * 60 * 1000).toISOString() } }; // 30 minutes ago
      const action = 'delete';

      const req = { P: principal, principal, R: resource, resource, action };

      const allowed = resourcePolicy.isAllowed(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.strictEqual(allowed, true);
    });

    it('should not allow Sally to delete her own expense if created over an hour ago', () => {
      const principal = principalsPolicy.sally;
      const resource = { ...resourcesPolicy.expense1, attr: { ...resourcesPolicy.expense1.attr, createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() } }; // 2 hours ago
      const action = 'delete';

      const req = { P: principal, principal, R: resource, resource, action };

      const allowed = resourcePolicy.isAllowed(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.strictEqual(allowed, false);
    });
  });

  describe('check', () => {
    it('should return map of actions and effects (Ian)', () => {
      const principal = principalsPolicy.ian;
      const resource = resourcesPolicy.expense1;
      const actions = ['view', 'create', 'update', 'delete', 'approve', 'view:approver'];

      const req = { P: principal, principal, R: resource, resource, actions };

      const effects = resourcePolicy.check(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.deepStrictEqual(Object.fromEntries(effects), {
        view: Effect.Allow,
        create: Effect.Allow,
        update: Effect.Allow,
        delete: Effect.Allow,
        approve: Effect.Allow,
        'view:approver': Effect.Allow,
      });
    });

    it('should return map of actions and effects (Sally)', () => {
      const principal = principalsPolicy.sally;
      const resource = resourcesPolicy.expense1;
      const actions = ['view', 'create', 'update', 'delete', 'approve', 'view:approver'];

      const req = { P: principal, principal, R: resource, resource, actions };

      const effects = resourcePolicy.check(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.deepStrictEqual(Object.fromEntries(effects), {
        view: Effect.Allow,
        create: Effect.Allow,
        update: Effect.Allow,
        delete: Effect.Deny,
        approve: Effect.Deny,
        'view:approver': Effect.Deny,
      });
    });

    it('should return map of actions and effects (Frank)', () => {
      const principal = principalsPolicy.frank;
      const resource = resourcesPolicy.expense3;
      const actions = ['view', 'create', 'approve', 'view:approver', 'delete', 'update'];

      const req = { P: principal, principal, R: resource, resource, actions };

      const effects = resourcePolicy.check(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.deepStrictEqual(Object.fromEntries(effects), {
        view: Effect.Allow,
        create: Effect.Allow,
        approve: Effect.Deny,
        'view:approver': Effect.Allow,
        delete: Effect.Deny,
        update: Effect.Deny,
      });
    });

    it('should return map of actions and effects (Derek)', () => {
      const principal = principalsPolicy.derek;
      const resource = resourcesPolicy.expense1;
      const actions = ['view', 'create', 'approve', 'view:approver', 'delete', 'update'];

      const req = { P: principal, principal, R: resource, resource, actions };

      const effects = resourcePolicy.check(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.deepStrictEqual(Object.fromEntries(effects), {
        view: Effect.Allow,
        create: Effect.Allow,
        approve: Effect.Allow,
        'view:approver': Effect.Allow,
        delete: Effect.Allow,
        update: Effect.Deny,
      });
    });

    it('should return map of actions and effects (Simon)', () => {
      const principal = principalsPolicy.simon;
      const resource = resourcesPolicy.expense1;
      const actions = ['view', 'create', 'approve', 'view:approver', 'delete', 'update'];

      const req = { P: principal, principal, R: resource, resource, actions };

      const effects = resourcePolicy.check(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.deepStrictEqual(Object.fromEntries(effects), {
        view: Effect.Deny,
        create: Effect.Allow,
        approve: Effect.Deny,
        'view:approver': Effect.Deny,
        delete: Effect.Deny,
        update: Effect.Deny,
      });
    });

    it('should return map of actions and effects (Mark)', () => {
      const principal = principalsPolicy.mark;
      const resource = resourcesPolicy.expense1;
      const actions = ['view', 'create', 'approve', 'view:approver', 'delete', 'update'];

      const req = { P: principal, principal, R: resource, resource, actions };

      const effects = resourcePolicy.check(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.deepStrictEqual(Object.fromEntries(effects), {
        view: Effect.Allow,
        create: Effect.Allow,
        approve: Effect.Deny,
        'view:approver': Effect.Deny,
        delete: Effect.Deny,
        update: Effect.Deny,
      });
    });

    it('should return map of actions and effects (Sydney)', () => {
      const principal = principalsPolicy.sydney;
      const resource = resourcesPolicy.expense1;
      const actions = ['view', 'create', 'approve', 'view:approver', 'delete', 'update'];

      const req = { P: principal, principal, R: resource, resource, actions };

      const effects = resourcePolicy.check(req, new DerivedRoles(commonRolesPolicy).get(req));

      assert.deepStrictEqual(Object.fromEntries(effects), {
        view: Effect.Deny,
        create: Effect.Allow,
        approve: Effect.Deny,
        'view:approver': Effect.Deny,
        delete: Effect.Deny,
        update: Effect.Deny,
      });
    });
  });
});
