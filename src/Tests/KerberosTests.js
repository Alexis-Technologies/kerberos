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

  static parseTests(tests, { z } = {}) {
    const parsedTests = [];
    for (const test of tests) parsedTests.push(test instanceof KerberosTest ? test : new KerberosTest(test, { z }));
    return parsedTests;
  }

  static parsePrincipals(principals, { z } = {}) {
    return principals instanceof PrincipalsMock ? principals.mocks : new PrincipalsMock(principals, { z }).mocks;
  }

  static parseResources(resources, { z } = {}) {
    return resources instanceof ResourcesMock ? resources.mocks : new ResourcesMock(resources, { z }).mocks;
  }

  #kerberos = null;

  #policies = [];

  #tests = [];

  #principals = null;

  #resources = null;

  constructor(kerberos, policies, { z } = {}) {
    if (!kerberos || !(kerberos instanceof Kerberos)) throw new Error('Kerberos instance is required');
    this.#kerberos = kerberos;
    this.#policies = KerberosTests.parsePolicies(policies, { z });
    for (const policy of this.#policies) this.#tests.push(...KerberosTests.parseTests(policy.tests, { z }));
    const principals = [];
    for (const policy of policies) principals.push(...KerberosTests.parsePrincipals(policy.principals, { z }));
    this.#principals = new PrincipalsMock(principals, { z });
    const resources = [];
    for (const policy of policies) resources.push(...KerberosTests.parseResources(policy.resources, { z }));
    this.resources = new ResourcesMock(resources, { z });
  }

  run({ effectAsBoolean = false }, { describe, it, assert }) {
    for (const policy of this.#policies) {
      describe(policy.name, () => {
        for (const test of this.#tests) {
          test.run(
            {
              kerberos: this.#kerberos,
              principals: [this.#principals],
              resources: [this.#resources],
              effectAsBoolean,
            },
            { describe, it, assert }
          );
        }
      });
    }
  }
}

module.exports = { KerberosTests, KerberosTestsZodSchemas };
