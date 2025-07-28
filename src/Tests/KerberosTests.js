const { ZodSchemas } = require('../schemas.js');
const { Kerberos } = require('../Kerberos.js');
const { KerberosTest, KerberosTestZodSchemas } = require('./KerberosTest.js');
const { ResourcesMock, PrincipalsMock, PrincipalsMockZodSchemas, ResourcesMockZodSchemas } = require('./Mocks');

class KerberosTestsZodSchemas extends ZodSchemas {
  static buildTestsPolicyShape(z) {
    return z.object({
      name: z.string(),
      principals: z.union([z.instanceof(PrincipalsMock), PrincipalsMockZodSchemas.buildShape(z)]),
      resources: z.union([z.instanceof(ResourcesMock), ResourcesMockZodSchemas.buildShape(z)]),
      tests: z.array(z.union([z.instanceof(KerberosTest), KerberosTestZodSchemas.buildShape(z)])).nonempty(),
    });
  }

  static buildShape(z) {
    return z.array(KerberosTestsZodSchemas.buildTestsPolicyShape(z)).nonempty();
  }
}

class KerberosTests {
  static parsePolicies(policies, { schema, z } = {}) {
    if (schema) return schema.parse(policies);
    if (z) return KerberosTestsZodSchemas.buildShape(z).parse(policies);
    return policies;
  }

  static parseTests(tests) {
    return tests.map((test) => (test instanceof KerberosTest ? test : new KerberosTest(test)));
  }

  static parsePrincipals(principals) {
    return principals instanceof PrincipalsMock ? principals.mocks : new PrincipalsMock(principals).mocks;
  }

  static parseResources(resources) {
    return resources instanceof ResourcesMock ? resources.mocks : new ResourcesMock(resources).mocks;
  }

  constructor(kerberos, policies, { z } = {}) {
    if (!kerberos || !(kerberos instanceof Kerberos)) throw new Error('Kerberos instance is required');
    this.kerberos = kerberos;
    this.policies = KerberosTests.parsePolicies(policies, { z });
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
            { describe, it, assert }
          );
        }
      });
    }
  }
}

module.exports = { KerberosTests };
