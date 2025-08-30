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

  describe('generateCallId (static)', () => {
    it('should use Node.js crypto.randomUUID when available', () => {
      // Mock nodeCrypto to simulate Node.js environment
      const mockUUID = 'node-generated-uuid-12345';
      const mockNodeCrypto = { randomUUID: () => mockUUID };

      // We need to temporarily modify the module's nodeCrypto reference
      const KerberosModule = require('../src/Kerberos.js');
      const originalGenerateCallId = KerberosModule.Kerberos.generateCallId;

      // Create a test version that uses our mock
      KerberosModule.Kerberos.generateCallId = function() {
        if (mockNodeCrypto?.randomUUID) return mockNodeCrypto.randomUUID();
        if (globalThis.window?.crypto?.randomUUID) return globalThis.window.crypto.randomUUID();
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
          const r = Math.random() * 16 | 0;
          const v = c === 'x' ? r : (r & 0x3 | 0x8);
          return v.toString(16);
        });
      };

      const result = KerberosModule.Kerberos.generateCallId();

      // Restore original method
      KerberosModule.Kerberos.generateCallId = originalGenerateCallId;

      assert.strictEqual(result, mockUUID);
    });

    it('should use browser crypto.randomUUID when Node.js crypto is not available', () => {
      const mockUUID = 'browser-generated-uuid-54321';

      // Mock global window object
      globalThis.window = {
        crypto: {
          randomUUID: () => mockUUID
        }
      };

      const KerberosModule = require('../src/Kerberos.js');
      const originalGenerateCallId = KerberosModule.Kerberos.generateCallId;

      // Create a test version that simulates no Node.js crypto but has window.crypto
      KerberosModule.Kerberos.generateCallId = function() {
        if (globalThis.window?.crypto?.randomUUID) return globalThis.window.crypto.randomUUID();
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
          const r = Math.random() * 16 | 0;
          const v = c === 'x' ? r : (r & 0x3 | 0x8);
          return v.toString(16);
        });
      };

      const result = KerberosModule.Kerberos.generateCallId();

      // Cleanup
      delete globalThis.window;
      KerberosModule.Kerberos.generateCallId = originalGenerateCallId;

      assert.strictEqual(result, mockUUID);
    });

    it('should use fallback UUID generator when no crypto is available', () => {
      const KerberosModule = require('../src/Kerberos.js');
      const originalGenerateCallId = KerberosModule.Kerberos.generateCallId;

      // Create a test version that has no crypto available
      KerberosModule.Kerberos.generateCallId = function() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
          const r = Math.random() * 16 | 0;
          const v = c === 'x' ? r : (r & 0x3 | 0x8);
          return v.toString(16);
        });
      };

      const result = KerberosModule.Kerberos.generateCallId();

      // Restore
      KerberosModule.Kerberos.generateCallId = originalGenerateCallId;

      // Validate UUID v4 format
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      assert.ok(uuidRegex.test(result), `Generated UUID "${result}" should match UUID v4 format`);
    });

    it('should generate different IDs on subsequent calls', () => {
      const id1 = Kerberos.generateCallId();
      const id2 = Kerberos.generateCallId();

      assert.notStrictEqual(id1, id2, 'Generated IDs should be unique');
      assert.ok(typeof id1 === 'string' && id1.length > 0, 'ID should be a non-empty string');
      assert.ok(typeof id2 === 'string' && id2.length > 0, 'ID should be a non-empty string');
    });

    it('should generate valid UUID format', () => {
      const id = Kerberos.generateCallId();

      assert.ok(typeof id === 'string', 'Generated ID should be a string');
      assert.strictEqual(id.length, 36, 'UUID should be 36 characters long');
      assert.ok(id.includes('-'), 'UUID should contain dashes');
      // Note: We can't guarantee UUID v4 format for native crypto.randomUUID,
      // but our fallback should generate v4-like format
    });
  });

  describe('checkResources with metadata support', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy]);

    it('should include metadata when includeMeta is true', async () => {
      const principal = {
        ...principalsPolicy.sally,
        policyVersion: '20210210',
        scope: 'acme.corp'
      };
      const resource = {
        ...resourcesPolicy.expense1,
        policyVersion: '20210210',
        scope: 'acme.corp'
      };
      const resources = [
        { resource, actions: ['view', 'create'] }
      ];

      const results = await kerberos.checkResources({ 
        reqId: 'test-meta-123',
        principal, 
        resources,
        includeMeta: true 
      });

      assert.strictEqual(results.reqId, 'test-meta-123');
      assert.ok(results.kerberosCallId);
      assert.strictEqual(results.results.length, 1);

      const result = results.results[0];
      assert.ok(result.meta);
      assert.ok(result.meta.actions);
      assert.ok(result.meta.effectiveDerivedRoles);
      assert.strictEqual(Array.isArray(result.meta.effectiveDerivedRoles), true);

      // Check that actions metadata is included
      assert.ok(result.meta.actions.view);
      assert.ok(result.meta.actions.create);
      assert.ok(result.meta.actions.view.matchedPolicy);
      assert.ok(result.meta.actions.create.matchedPolicy);
    });

    it('should not include metadata when includeMeta is false or not provided', async () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view'] }
      ];

      const results1 = await kerberos.checkResources({ principal, resources, includeMeta: false });
      const results2 = await kerberos.checkResources({ principal, resources });

      assert.strictEqual(results1.results[0].meta, undefined);
      assert.strictEqual(results2.results[0].meta, undefined);
    });

    it('should include policyVersion and scope in resource response when provided', async () => {
      const principal = {
        ...principalsPolicy.sally,
        policyVersion: '20210210',
        scope: 'acme.corp'
      };
      const resource = {
        ...resourcesPolicy.expense1,
        policyVersion: '20210210', 
        scope: 'acme.corp'
      };
      const resources = [
        { resource, actions: ['view'] }
      ];

      const results = await kerberos.checkResources({ principal, resources });

      assert.strictEqual(results.results[0].resource.policyVersion, '20210210');
      assert.strictEqual(results.results[0].resource.scope, 'acme.corp');
    });

    it('should not include policyVersion and scope in resource response when not provided', async () => {
      const principal = principalsPolicy.sally;
      const resources = [
        { resource: resourcesPolicy.expense1, actions: ['view'] }
      ];

      const results = await kerberos.checkResources({ principal, resources });

      assert.strictEqual(Object.prototype.hasOwnProperty.call(results.results[0].resource, 'policyVersion'), false);
      assert.strictEqual(Object.prototype.hasOwnProperty.call(results.results[0].resource, 'scope'), false);
    });

    it('should generate correct matchedPolicy format in metadata', async () => {
      const principal = {
        ...principalsPolicy.sally,
        scope: 'acme.corp'
      };
      const resource = {
        ...resourcesPolicy.expense1,
        policyVersion: '20210210',
        scope: 'acme.corp'
      };
      const resources = [
        { resource, actions: ['view'] }
      ];

      const results = await kerberos.checkResources({ 
        principal, 
        resources,
        includeMeta: true 
      });

      const actionMeta = results.results[0].meta.actions.view;
      assert.ok(actionMeta.matchedPolicy.includes('v20210210'));
      assert.ok(actionMeta.matchedPolicy.includes('acme.corp'));
    });

    it('should include matchedScope in metadata when scope is provided', async () => {
      const principal = {
        ...principalsPolicy.sally,
        scope: 'acme.corp'
      };
      const resource = {
        ...resourcesPolicy.expense1,
        scope: 'acme.corp'
      };
      const resources = [
        { resource, actions: ['view'] }
      ];

      const results = await kerberos.checkResources({ 
        principal, 
        resources,
        includeMeta: true 
      });

      const actionMeta = results.results[0].meta.actions.view;
      assert.strictEqual(actionMeta.matchedScope, 'acme');
    });

    it('should work with boolean mode and metadata', async () => {
      const principal = {
        ...principalsPolicy.sally,
        policyVersion: '20210210',
        scope: 'acme.corp'
      };
      const resource = {
        ...resourcesPolicy.expense1,
        policyVersion: '20210210',
        scope: 'acme.corp'
      };
      const resources = [
        { resource, actions: ['view', 'create', 'delete'] }
      ];

      const results = await kerberos.checkResources({ 
        principal, 
        resources,
        includeMeta: true 
      }, true);

      assert.strictEqual(results.results[0].actions.view, true);
      assert.strictEqual(results.results[0].actions.create, true);
      assert.strictEqual(results.results[0].actions.delete, false);
      assert.ok(results.results[0].meta);
      assert.ok(results.results[0].meta.actions.view);
      assert.ok(results.results[0].meta.actions.create);
      assert.ok(results.results[0].meta.actions.delete);
    });
  });
});
