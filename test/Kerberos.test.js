const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const { z } = require('zod');

const { commonRolesPolicy, principalsPolicy, resourcesPolicy, expensePolicy } = require('./mocks/index.js');

const { Effect, Kerberos } = require('../src/index.js');

describe('Kerberos', () => {
  describe('without options', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy]);

    describe('isAllowed', () => {
      it('should return true if the action is allowed', async () => {
        const principal = principalsPolicy.sally;
        const resource = resourcesPolicy.expense1;
        const action = 'view';

        const isAllowed = await kerberos.isAllowed({ principal, action, resource });

        assert.strictEqual(isAllowed, true);
      });

      it('should return false if the action is not allowed', async () => {
        const principal = principalsPolicy.sally;
        const resource = resourcesPolicy.expense1;
        const action = 'approve';

        const isAllowed = await kerberos.isAllowed({ principal, action, resource });

        assert.strictEqual(isAllowed, false);
      });
    });

    describe('checkResources', () => {
      it('should return the effect actions map for each resource (Effect mode)', async () => {
        const principal = principalsPolicy.sally;
        const resources = [
          { resource: resourcesPolicy.expense1, actions: ['view', 'create', 'delete'] },
          { resource: resourcesPolicy.expense4, actions: ['view', 'create'] },
        ];

        const results = await kerberos.checkResources({ principal, resources });

        assert.ok(results.kerberosCallId);
        assert.strictEqual(typeof results.kerberosCallId, 'string');
        assert.deepStrictEqual(results.results, [
          {
            resource: { id: 'expense1', kind: 'expense' },
            actions: { view: Effect.Allow, create: Effect.Allow, delete: Effect.Deny },
            outputs: [],
          },
          {
            resource: { id: 'expense4', kind: 'expense' },
            actions: { view: Effect.Deny, create: Effect.Allow },
            outputs: [],
          },
        ]);
      });

      it('should return the effect actions map for each resource (Boolean mode)', async () => {
        const principal = principalsPolicy.sally;
        const resources = [
          { resource: resourcesPolicy.expense1, actions: ['view', 'create', 'delete'] },
          { resource: resourcesPolicy.expense4, actions: ['view', 'create'] },
        ];

        const results = await kerberos.checkResources({ principal, resources }, true);

        assert.ok(results.kerberosCallId);
        assert.strictEqual(typeof results.kerberosCallId, 'string');
        assert.deepStrictEqual(results.results, [
          {
            resource: { id: 'expense1', kind: 'expense' },
            actions: { view: true, create: true, delete: false },
            outputs: [],
          },
          {
            resource: { id: 'expense4', kind: 'expense' },
            actions: { view: false, create: true },
            outputs: [],
          },
        ]);
      });
    });
  });

  describe('with logger', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy], { logger: true });

    describe('isAllowed', () => {
      it('should return true if the action is allowed', async () => {
        const principal = principalsPolicy.sally;
        const resource = resourcesPolicy.expense1;
        const action = 'view';

        const isAllowed = await kerberos.isAllowed({ principal, action, resource });

        assert.strictEqual(isAllowed, true);
      });

      it('should return false if the action is not allowed', async () => {
        const principal = principalsPolicy.sally;
        const resource = resourcesPolicy.expense1;
        const action = 'approve';

        const isAllowed = await kerberos.isAllowed({ principal, action, resource });

        assert.strictEqual(isAllowed, false);
      });
    });

    describe('checkResources', () => {
      it('should return the effect actions map for each resource (Effect mode)', async () => {
        const principal = principalsPolicy.sally;
        const resources = [
          { resource: resourcesPolicy.expense1, actions: ['view', 'create', 'delete'] },
          { resource: resourcesPolicy.expense4, actions: ['view', 'create'] },
        ];

        const results = await kerberos.checkResources({ principal, resources });

        assert.ok(results.kerberosCallId);
        assert.strictEqual(typeof results.kerberosCallId, 'string');
        assert.deepStrictEqual(results.results, [
          {
            resource: { id: 'expense1', kind: 'expense' },
            actions: { view: Effect.Allow, create: Effect.Allow, delete: Effect.Deny },
            outputs: [],
          },
          {
            resource: { id: 'expense4', kind: 'expense' },
            actions: { view: Effect.Deny, create: Effect.Allow },
            outputs: [],
          },
        ]);
      });

      it('should return the effect actions map for each resource (Boolean mode)', async () => {
        const principal = principalsPolicy.sally;
        const resources = [
          { resource: resourcesPolicy.expense1, actions: ['view', 'create', 'delete'] },
          { resource: resourcesPolicy.expense4, actions: ['view', 'create'] },
        ];

        const results = await kerberos.checkResources({ principal, resources }, true);

        assert.ok(results.kerberosCallId);
        assert.strictEqual(typeof results.kerberosCallId, 'string');
        assert.deepStrictEqual(results.results, [
          {
            resource: { id: 'expense1', kind: 'expense' },
            actions: { view: true, create: true, delete: false },
            outputs: [],
          },
          {
            resource: { id: 'expense4', kind: 'expense' },
            actions: { view: false, create: true },
            outputs: [],
          },
        ]);
      });
    });
  });

  describe('with validation', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy], { z });

    describe('isAllowed', () => {
      it('should return true if the action is allowed', async () => {
        const principal = principalsPolicy.sally;
        const resource = resourcesPolicy.expense1;
        const action = 'view';

        const isAllowed = await kerberos.isAllowed({ principal, action, resource });

        assert.strictEqual(isAllowed, true);
      });

      it('should return false if the action is not allowed', async () => {
        const principal = principalsPolicy.sally;
        const resource = resourcesPolicy.expense1;
        const action = 'approve';

        const isAllowed = await kerberos.isAllowed({ principal, action, resource });

        assert.strictEqual(isAllowed, false);
      });
    });

    describe('checkResources', () => {
      it('should return the effect actions map for each resource (Effect mode)', async () => {
        const principal = principalsPolicy.sally;
        const resources = [
          { resource: resourcesPolicy.expense1, actions: ['view', 'create', 'delete'] },
          { resource: resourcesPolicy.expense4, actions: ['view', 'create'] },
        ];

        const results = await kerberos.checkResources({ principal, resources });

        assert.ok(results.kerberosCallId);
        assert.strictEqual(typeof results.kerberosCallId, 'string');
        assert.deepStrictEqual(results.results, [
          {
            resource: { id: 'expense1', kind: 'expense' },
            actions: { view: Effect.Allow, create: Effect.Allow, delete: Effect.Deny },
            outputs: [],
          },
          {
            resource: { id: 'expense4', kind: 'expense' },
            actions: { view: Effect.Deny, create: Effect.Allow },
            outputs: [],
          },
        ]);
      });

      it('should return the effect actions map for each resource (Boolean mode)', async () => {
        const principal = principalsPolicy.sally;
        const resources = [
          { resource: resourcesPolicy.expense1, actions: ['view', 'create', 'delete'] },
          { resource: resourcesPolicy.expense4, actions: ['view', 'create'] },
        ];

        const results = await kerberos.checkResources({ principal, resources }, true);

        assert.ok(results.kerberosCallId);
        assert.strictEqual(typeof results.kerberosCallId, 'string');
        assert.deepStrictEqual(results.results, [
          {
            resource: { id: 'expense1', kind: 'expense' },
            actions: { view: true, create: true, delete: false },
            outputs: [],
          },
          {
            resource: { id: 'expense4', kind: 'expense' },
            actions: { view: false, create: true },
            outputs: [],
          },
        ]);
      });
    });
  });

  describe('checkResources with reqId', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy]);

    it('should return reqId in response when provided in request', async () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view', 'create'] },
      ];
      const reqId = 'test-request-123';

      const results = await kerberos.checkResources({ reqId, principal, resources });

      assert.strictEqual(results.reqId, 'test-request-123');
      assert.ok(results.kerberosCallId);
      assert.strictEqual(typeof results.kerberosCallId, 'string');
      assert.deepStrictEqual(results.results, [
        {
          resource: { id: 'expense1', kind: 'expense' },
          actions: { view: Effect.Allow, create: Effect.Allow },
          outputs: [],
        },
      ]);
    });

    it('should not include reqId in response when not provided in request', async () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view', 'create'] },
      ];

      const results = await kerberos.checkResources({ principal, resources });

      assert.strictEqual(Object.prototype.hasOwnProperty.call(results, 'reqId'), false);
      assert.ok(results.kerberosCallId);
      assert.strictEqual(typeof results.kerberosCallId, 'string');
      assert.deepStrictEqual(results.results, [
        {
          resource: { id: 'expense1', kind: 'expense' },
          actions: { view: Effect.Allow, create: Effect.Allow },
          outputs: [],
        },
      ]);
    });
  });

  describe('checkResources with kerberosCallId', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy]);

    it('should always return kerberosCallId in response', async () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view', 'create'] },
      ];

      const results = await kerberos.checkResources({ principal, resources });

      assert.ok(results.kerberosCallId);
      assert.strictEqual(typeof results.kerberosCallId, 'string');
      assert.ok(results.kerberosCallId.length > 0);
    });

    it('should generate valid UUID format for kerberosCallId', async () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view'] },
      ];

      const results = await kerberos.checkResources({ principal, resources });
      
      // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      assert.ok(uuidRegex.test(results.kerberosCallId), `kerberosCallId should be valid UUID format, got: ${results.kerberosCallId}`);
    });

    it('should generate unique kerberosCallId for each request', async () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view'] },
      ];

      const results1 = await kerberos.checkResources({ principal, resources });
      const results2 = await kerberos.checkResources({ principal, resources });

      assert.ok(results1.kerberosCallId);
      assert.ok(results2.kerberosCallId);
      assert.notStrictEqual(results1.kerberosCallId, results2.kerberosCallId);
    });

    it('should work with Boolean mode', async () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view', 'create'] },
      ];

      const results = await kerberos.checkResources({ principal, resources }, true);

      assert.ok(results.kerberosCallId);
      assert.strictEqual(typeof results.kerberosCallId, 'string');
      assert.deepStrictEqual(results.results, [
        {
          resource: { id: 'expense1', kind: 'expense' },
          actions: { view: true, create: true },
          outputs: [],
        },
      ]);
    });
  });

  describe('Kerberos with custom getCallId', () => {
    let callCount = 0;
    const customGetCallId = () => `custom-id-${++callCount}`;
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy], { getCallId: customGetCallId });

    it('should use custom getCallId function', async () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view'] },
      ];

      const results = await kerberos.checkResources({ principal, resources });

      assert.strictEqual(results.kerberosCallId, 'custom-id-1');
    });

    it('should increment call count with custom getCallId', async () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view'] },
      ];

      const results = await kerberos.checkResources({ principal, resources });

      assert.strictEqual(results.kerberosCallId, 'custom-id-2');
    });
  });
});
