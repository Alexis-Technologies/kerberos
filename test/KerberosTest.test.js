import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import { principalsPolicy, expenseTestPolicy, resourcesPolicy, expensePolicy, commonRolesPolicy } from './mocks/index.js';

import { KerberosTest, PrincipalsMock, ResourcesMock } from '../src/Tests/index.js';
import { Effect, Kerberos } from '../src/index.js';

describe('KerberosTest', () => {
  describe('Kerberos instance injected via constructor', () => {
    const kerberosTest = new KerberosTest(expenseTestPolicy.tests[0], new Kerberos([expensePolicy], [commonRolesPolicy], { logger: true }));
    kerberosTest.run(
      {
        principals: [new PrincipalsMock(principalsPolicy)],
        resources: [new ResourcesMock(resourcesPolicy)],
      },
      { describe, it, assert }
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
      { describe, it, assert }
    );
  });

  describe('With effectAsBoolean mode', () => {
    const testPolicy = expenseTestPolicy.tests[0];
    const testPolicyExpected = testPolicy.expected.map((item) => ({ ...item, actions: Object.fromEntries(Object.entries(item.actions).map(([action, effect]) => [action, effect === Effect.Allow])) }));
    const kerberosTest = new KerberosTest({ ...testPolicy, expected: testPolicyExpected }, new Kerberos([expensePolicy], [commonRolesPolicy]));
    kerberosTest.run(
      {
        principals: [new PrincipalsMock(principalsPolicy)],
        resources: [new ResourcesMock(resourcesPolicy)],
        effectAsBoolean: true,
      },
      { describe, it, assert }
    );
  });
});
