const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const { z } = require('zod');

const { expenseTestPolicy, expensePolicy, commonRolesPolicy } = require('./mocks/index.js');

const { KerberosTests } = require('@alexify/kerberos/tests');
const { Kerberos } = require('../src/index.js');

describe('KerberosTests', () => {
  describe('Expense Policy (raw mode)', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy], { logger: true });
    const tests = new KerberosTests(kerberos, [expenseTestPolicy]);

    tests.run({}, { describe, it, assert });
  });

  it('should construct with Zod validation enabled without re-parsing nested tests', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy]);
    const tests = new KerberosTests(kerberos, [expenseTestPolicy], { z });

    assert.ok(tests);
  });

  it('should run only each policy suite\'s own tests', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy]);
    const policyA = {
      name: 'Suite A',
      principals: expenseTestPolicy.principals,
      resources: expenseTestPolicy.resources,
      tests: [expenseTestPolicy.tests[0]],
    };
    const policyB = {
      name: 'Suite B',
      principals: expenseTestPolicy.principals,
      resources: expenseTestPolicy.resources,
      tests: [{ ...expenseTestPolicy.tests[0], name: 'Suite B Only Test' }],
    };
    const tests = new KerberosTests(kerberos, [policyA, policyB]);

    const suites = [];
    const stack = [];
    const mockDescribe = (name, fn) => {
      stack.push(name);
      if (stack.length === 1) suites.push({ policy: name, tests: [] });
      else if (stack.length === 2) suites[suites.length - 1].tests.push(name);
      fn();
      stack.pop();
    };
    const mockIt = () => {};
    const mockAssert = { ok: () => {}, strictEqual: () => {} };

    tests.run({}, { describe: mockDescribe, it: mockIt, assert: mockAssert });

    assert.strictEqual(suites.length, 2);
    assert.strictEqual(suites[0].policy, 'Suite A');
    assert.strictEqual(suites[1].policy, 'Suite B');
    assert.ok(suites[0].tests.includes('Sales Roles'));
    assert.ok(!suites[0].tests.includes('Suite B Only Test'));
    assert.ok(suites[1].tests.includes('Suite B Only Test'));
    assert.ok(!suites[1].tests.includes('Sales Roles') || suites[1].tests.length === 1);
    assert.strictEqual(suites[1].tests.length, 1);
    assert.strictEqual(suites[1].tests[0], 'Suite B Only Test');
  });

  it('should keep per-policy fixtures isolated when names overlap', async () => {
    class RecordingKerberos extends Kerberos {
      calls = [];

      async checkResources(args) {
        this.calls.push({
          suitePrincipalId: args.principal.id,
          suiteResourceId: args.resources[0].resource.id,
        });
        return {
          results: [
            {
              resource: { id: args.resources[0].resource.id, kind: args.resources[0].resource.kind },
              actions: { view: 'EFFECT_ALLOW' },
              outputs: [],
            },
          ],
        };
      }
    }

    const kerberos = new RecordingKerberos([], []);
    const sharedTest = {
      name: 'Shared fixture test',
      input: {
        principals: ['sally'],
        resources: ['doc'],
        actions: ['view'],
      },
      expected: [
        {
          principal: 'sally',
          resource: 'doc',
          actions: { view: 'EFFECT_ALLOW' },
        },
      ],
    };
    const policyA = {
      name: 'Suite A',
      principals: { sally: { id: 'suite-a-sally', roles: ['USER'] } },
      resources: { doc: { id: 'suite-a-doc', kind: 'document' } },
      tests: [sharedTest],
    };
    const policyB = {
      name: 'Suite B',
      principals: { sally: { id: 'suite-b-sally', roles: ['USER'] } },
      resources: { doc: { id: 'suite-b-doc', kind: 'document' } },
      tests: [sharedTest],
    };
    const tests = new KerberosTests(kerberos, [policyA, policyB]);
    const pending = [];

    tests.run({}, {
      describe: (_, fn) => fn(),
      it: (_, fn) => pending.push(fn),
      assert: { ok: () => {}, strictEqual: () => {} },
    });

    for (const fn of pending) await fn();

    assert.deepStrictEqual(kerberos.calls, [
      { suitePrincipalId: 'suite-a-sally', suiteResourceId: 'suite-a-doc' },
      { suitePrincipalId: 'suite-b-sally', suiteResourceId: 'suite-b-doc' },
    ]);
  });
});
