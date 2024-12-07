const { z } = require('zod');

const { Kerberos } = require('../Kerberos.js');
const { KerberosTest, KerberosTestSchema } = require('./KerberosTest.js');
const { ResourcesMock, ResourceMockSchema, PrincipalsMock, PrincipalMockSchema } = require('./Mocks');

const TestsPolicySchema = z
  .object({
    name: z.string(),
    principals: z.union([z.instanceof(PrincipalsMock), z.array(PrincipalMockSchema).nonempty()]),
    resources: z.union([z.instanceof(ResourcesMock), z.array(ResourceMockSchema).nonempty()]),
    tests: z.array(z.union([z.instanceof(KerberosTest), KerberosTestSchema])).nonempty(),
  })
  .strict();
const TestsPoliciesSchema = z.array(TestsPolicySchema).nonempty();

class KerberosTests {
  static parseTests(tests) {
    return tests.map((test) => (test instanceof KerberosTest ? test : new KerberosTest(test)));
  }

  static parsePrincipals(principals) {
    return principals instanceof PrincipalsMock ? principals.mocks : new PrincipalsMock(principals).mocks;
  }

  static parseResources(resources) {
    return resources instanceof ResourcesMock ? resources.mocks : new ResourcesMock(resources).mocks;
  }

  constructor(kerberos, policies) {
    if (!kerberos || !(kerberos instanceof Kerberos)) throw new Error('Kerberos instance is required');
    TestsPoliciesSchema.parse(policies);
    this.kerberos = kerberos;
    this.policies = policies;
    this.tests = policies.flatMap((policy) => KerberosTests.parseTests(policy.tests));
    this.principals = new PrincipalsMock(policies.flatMap((policy) => KerberosTests.parsePrincipals(policy.principals)));
    this.resources = new ResourcesMock(policies.flatMap((policy) => KerberosTests.parseResources(policy.resources)));
  }

  run({ effectAsBoolean = false }, { describe, it, assert }) {
    for (const policy of this.policies) {
      describe(policy.name, () => {
        for (const test of this.tests) {
          test.run(
            {
              kerberos: this.kerberos,
              principals: [this.principals],
              resources: [this.resources],
              effectAsBoolean,
            },
            { describe, it, assert },
          );
        }
      });
    }
  }
}

module.exports = { KerberosTests };
