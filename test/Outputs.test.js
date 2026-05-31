const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { Effect, Kerberos } = require('../src/index.js');

describe('Outputs functionality', () => {
  const outputsPolicy = {
    resourcePolicy: {
      version: 'default',
      resource: 'system_access',
      rules: [
        {
          name: 'working-hours-only',
          actions: ['*'],
          effect: Effect.Deny,
          roles: ['*'],
          condition: {
            match: ({ }) => {
              const now = new Date();
              return now.getHours() > 18 || now.getHours() < 8;
            }
          },
          output: {
            when: {
              ruleActivated: ({ P, R }) => ({
                principal: P.id,
                resource: R.id,
                timestamp: new Date().toISOString(),
                message: 'System can only be accessed between 0800 and 1800'
              }),
              conditionNotMet: ({ P, R }) => ({
                principal: P.id,
                resource: R.id,
                timestamp: new Date().toISOString(),
                message: 'System can be accessed at this time'
              })
            }
          }
        },
        {
          name: 'admin-access',
          actions: ['*'],
          effect: Effect.Allow,
          roles: ['admin'],
          output: {
            when: {
              ruleActivated: ({ P }) => ({
                message: 'Admin access granted',
                admin: P.id
              })
            }
          }
        }
      ]
    }
  };

  const mockPrincipal = {
    id: 'john',
    roles: ['user']
  };

  const mockResource = {
    id: 'bastion_002',
    kind: 'system_access'
  };

  const adminPrincipal = {
    id: 'alice',
    roles: ['admin']
  };

  describe('checkResources with outputs', () => {
    it('should return outputs when rules are activated', async () => {
      const kerberos = new Kerberos([outputsPolicy]);

      const resources = [
        { resource: mockResource, actions: ['login'] }
      ];

      const results = await kerberos.checkResources({
        principal: mockPrincipal,
        resources
      });

      // Check that we get outputs
      assert.ok(results.results[0].outputs);
      assert.ok(Array.isArray(results.results[0].outputs));

      // The working-hours rule applies to every principal (roles: ['*']) and
      // defines both `ruleActivated` and `conditionNotMet` branches, so it
      // always emits an output regardless of the current time. Both branches
      // share the same principal/resource/timestamp/message shape.
      const output = results.results[0].outputs.find(
        (o) => o.src === 'resource.system_access.vdefault#working-hours-only'
      );
      assert.ok(output, 'expected the working-hours output to be present');
      assert.ok(output.val);
      assert.strictEqual(output.val.principal, 'john');
      assert.strictEqual(output.val.resource, 'bastion_002');
      assert.ok(output.val.timestamp);
      assert.ok(output.val.message);
    });

    it('should return outputs for admin access', async () => {
      const kerberos = new Kerberos([outputsPolicy]);

      const resources = [
        { resource: mockResource, actions: ['login'] }
      ];

      const results = await kerberos.checkResources({
        principal: adminPrincipal,
        resources
      });

      // Check that we get outputs for admin rule
      assert.ok(results.results[0].outputs);
      const adminOutput = results.results[0].outputs.find(output =>
        output.src === 'resource.system_access.vdefault#admin-access'
      );

      // The admin-access rule matches the admin principal and has no condition,
      // so its `ruleActivated` output must always be emitted.
      assert.ok(adminOutput, 'expected the admin-access output to be present');
      assert.ok(adminOutput.val.message);
      assert.strictEqual(adminOutput.val.message, 'Admin access granted');
      assert.strictEqual(adminOutput.val.admin, 'alice');
    });

    it('should handle empty outputs when no rules have output expressions', async () => {
      const simplePolicy = {
        resourcePolicy: {
          version: 'default',
          resource: 'simple_resource',
          rules: [
            {
              name: 'allow-all',
              actions: ['*'],
              effect: Effect.Allow,
              roles: ['*']
            }
          ]
        }
      };

      const kerberos = new Kerberos([simplePolicy]);

      const resources = [
        { resource: { id: 'test', kind: 'simple_resource' }, actions: ['read'] }
      ];

      const results = await kerberos.checkResources({
        principal: mockPrincipal,
        resources
      });

      // Should have empty outputs array
      assert.ok(results.results[0].outputs);
      assert.strictEqual(results.results[0].outputs.length, 0);
    });
  });

  describe('Output Functions', () => {
    it('should execute simple output functions', () => {
      const outputFunction = ({ P }) => ({
        message: 'test',
        user: P.id
      });

      const context = {
        P: { id: 'john' },
        R: { id: 'resource1' }
      };

      const result = outputFunction(context);

      assert.strictEqual(result.message, 'test');
      assert.strictEqual(result.user, 'john');
    });

    it('should handle functions with timestamps', () => {
      const outputFunction = () => ({
        timestamp: new Date().toISOString()
      });

      const result = outputFunction({});

      assert.ok(result.timestamp);
      // Should be a valid ISO string
      assert.ok(new Date(result.timestamp).toISOString());
    });

    it('should handle property access in functions', () => {
      const outputFunction = ({ P, R }) => ({
        resourceKind: R.kind,
        principalId: P.id
      });

      const context = {
        P: { id: 'john', roles: ['user'] },
        R: { id: 'resource1', kind: 'document' }
      };

      const result = outputFunction(context);

      assert.strictEqual(result.resourceKind, 'document');
      assert.strictEqual(result.principalId, 'john');
    });
  });
});
