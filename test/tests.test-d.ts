import { expectAssignable, expectType } from 'tsd';

import { Effect, Kerberos } from '../index.js';
import {
  KerberosTest,
  KerberosTests,
  PrincipalMock,
  PrincipalsMock,
  ResourceMock,
  ResourcesMock,
  type KerberosTestSchema,
  type TestsPolicySchema,
} from '../tests.js';

// Pulls the whole /tests subpath surface (tests.d.ts) into tsd compilation —
// without this file the declarations were never even syntax-checked by CI.

const kerberos = new Kerberos(
  [
    {
      resourcePolicy: {
        version: 'default',
        resource: 'expense',
        rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
      },
    },
  ],
  [],
);

const principalMock = new PrincipalMock({ name: 'sally', id: 'sally', roles: ['USER'] });
expectType<PrincipalMock>(principalMock);

const principalsMock = new PrincipalsMock({ sally: { id: 'sally', roles: ['USER'] } });
expectType<PrincipalsMock>(principalsMock);

const resourceMock = new ResourceMock({ name: 'expense1', id: 'expense1', kind: 'expense' });
expectType<ResourceMock>(resourceMock);

const resourcesMock = new ResourcesMock({ expense1: { id: 'expense1', kind: 'expense' } });
expectType<ResourcesMock>(resourcesMock);

const testSchema: KerberosTestSchema = {
  name: 'sally can view',
  input: { principals: ['sally'], resources: ['expense1'], actions: ['view'] },
  expected: [{ principal: 'sally', resource: 'expense1', actions: { view: Effect.Allow } }],
};
const kerberosTest = new KerberosTest(testSchema, kerberos);
expectType<KerberosTest>(kerberosTest);

// The static parse helpers are public surface (exercised by the repo's own
// test suite) — pin their presence so d.ts drift cannot silently remove them.
expectType<KerberosTestSchema>(KerberosTest.parseShape(testSchema));
expectAssignable<Function>(KerberosTests.parsePolicies);
expectAssignable<Function>(KerberosTests.parseTests);
expectAssignable<Function>(KerberosTests.buildPrincipalsMock);
expectAssignable<Function>(KerberosTests.buildResourcesMock);

const fixture: TestsPolicySchema = {
  name: 'expense suite',
  principals: principalsMock,
  resources: resourcesMock,
  tests: [testSchema],
};
expectAssignable<object>(fixture);
const suite = new KerberosTests(kerberos, [fixture]);
expectType<KerberosTests>(suite);
