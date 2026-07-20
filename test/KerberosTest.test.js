const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const {
  principalsPolicy,
  expenseTestPolicy,
  resourcesPolicy,
  expensePolicy,
  commonRolesPolicy,
} = require('./mocks/index.js');

const { KerberosTest, PrincipalsMock, ResourcesMock } = require('@alexify/kerberos/tests');
const { Effect, Kerberos } = require('../src/index.js');

describe('KerberosTest', () => {
  describe('Kerberos instance injected via constructor', () => {
    const kerberosTest = new KerberosTest(
      expenseTestPolicy.tests[0],
      new Kerberos([expensePolicy], [commonRolesPolicy], { logger: true }),
    );
    kerberosTest.run(
      {
        principals: [new PrincipalsMock(principalsPolicy)],
        resources: [new ResourcesMock(resourcesPolicy)],
      },
      { describe, it, assert },
    );
  });

  describe('Kerberos instance injected via method', () => {
    const kerberosTest = new KerberosTest(expenseTestPolicy.tests[0]);
    kerberosTest.run(
      {
        principals: [new PrincipalsMock(principalsPolicy)],
        resources: [new ResourcesMock(resourcesPolicy)],
        kerberos: new Kerberos([expensePolicy], [commonRolesPolicy]),
      },
      { describe, it, assert },
    );
  });

  describe('outputs assertions in expected entries', () => {
    const outputsPolicy = {
      resourcePolicy: {
        version: 'default',
        resource: 'gadget',
        rules: [
          {
            name: 'allow-view',
            actions: ['view'],
            effect: Effect.Allow,
            roles: ['USER'],
            output: { when: { ruleActivated: ({ P }) => ({ viewer: P.id }) } },
          },
        ],
      },
    };

    const outputsTest = new KerberosTest(
      {
        name: 'outputs assertions',
        input: { principals: ['sally'], resources: ['gadget1'], actions: ['view'] },
        expected: [
          {
            principal: 'sally',
            resource: 'gadget1',
            actions: { view: Effect.Allow },
            outputs: [
              {
                src: 'resource.gadget.vdefault#allow-view',
                val: { viewer: 'sally' },
              },
            ],
          },
        ],
      },
      new Kerberos([outputsPolicy], []),
    );

    outputsTest.run(
      {
        principals: [new PrincipalsMock({ sally: { id: 'sally', roles: ['USER'] } })],
        resources: [new ResourcesMock({ gadget1: { id: 'gadget1', kind: 'gadget' } })],
      },
      { describe, it, assert },
    );
  });

  describe('outputs assertion failures', () => {
    it('should fail when expected outputs do not match', async () => {
      const noOutputsPolicy = {
        resourcePolicy: {
          version: 'default',
          resource: 'gadget',
          rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
        },
      };
      const failingTest = new KerberosTest(
        {
          name: 'outputs mismatch',
          input: { principals: ['sally'], resources: ['gadget1'], actions: ['view'] },
          expected: [
            {
              principal: 'sally',
              resource: 'gadget1',
              actions: { view: Effect.Allow },
              outputs: [{ src: 'resource.gadget.vdefault#missing', val: {} }],
            },
          ],
        },
        new Kerberos([noOutputsPolicy], []),
      );

      const assertions = [];
      failingTest.run(
        {
          principals: [new PrincipalsMock({ sally: { id: 'sally', roles: ['USER'] } })],
          resources: [new ResourcesMock({ gadget1: { id: 'gadget1', kind: 'gadget' } })],
        },
        {
          describe: (_, fn) => fn(),
          it: (_, fn) => assertions.push(fn),
          assert,
        },
      );

      await assert.rejects(async () => {
        for (const fn of assertions) await fn();
      }, /Outputs for resource "gadget1" did not match/);
    });
  });

  describe('With effectAsBoolean mode', () => {
    const testPolicy = expenseTestPolicy.tests[0];
    const testPolicyExpected = testPolicy.expected.map((item) => ({
      ...item,
      actions: Object.fromEntries(
        Object.entries(item.actions).map(([action, effect]) => [action, effect === Effect.Allow]),
      ),
    }));
    const kerberosTest = new KerberosTest(
      { ...testPolicy, expected: testPolicyExpected },
      new Kerberos([expensePolicy], [commonRolesPolicy]),
    );
    kerberosTest.run(
      {
        principals: [new PrincipalsMock(principalsPolicy)],
        resources: [new ResourcesMock(resourcesPolicy)],
        effectAsBoolean: true,
      },
      { describe, it, assert },
    );
  });

  it('should fail when checkResources returns no results for a requested resource', async () => {
    class EmptyResultKerberos extends Kerberos {
      async checkResources() {
        return { results: [] };
      }
    }

    const kerberosTest = new KerberosTest(
      expenseTestPolicy.tests[0],
      new EmptyResultKerberos([expensePolicy], [commonRolesPolicy]),
    );
    const assertions = [];

    kerberosTest.run(
      {
        principals: [new PrincipalsMock(principalsPolicy)],
        resources: [new ResourcesMock(resourcesPolicy)],
      },
      {
        describe: (_, fn) => fn(),
        it: (_, fn) => assertions.push(fn),
        assert: {
          ok(value, message) {
            if (!value) throw new Error(message);
          },
          strictEqual(actual, expected, message) {
            if (actual !== expected) throw new Error(message);
          },
        },
      },
    );

    await assert.rejects(async () => {
      for (const fn of assertions) await fn();
    }, /No result returned for resource/);
  });
});
