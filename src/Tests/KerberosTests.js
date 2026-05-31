const { Kerberos } = require('../Kerberos.js');
const { KerberosTest } = require('./KerberosTest.js');
const { parseKerberosTestsPolicies } = require('./validation');
const { ResourcesMock, PrincipalsMock } = require('./Mocks');

/**
 * Runner for grouped KerberosTest policies.
 */
class KerberosTests {
  /**
   * Parses tests policy definitions with the configured validation backend.
   *
   * @param {unknown} policies
   * @param {object} [options]
   * @returns {unknown}
   */
  static parsePolicies(policies, options = {}) {
    return parseKerberosTestsPolicies(policies, KerberosTest, options);
  }

  static parseTests(tests, kerberos, options = {}) {
    const parsedTests = [];
    for (const test of tests) parsedTests.push(test instanceof KerberosTest ? test : new KerberosTest(test, kerberos, options));
    return parsedTests;
  }

  static buildPrincipalsMock(principals, options = {}) {
    return principals instanceof PrincipalsMock ? principals : new PrincipalsMock(principals, options);
  }

  static buildResourcesMock(resources, options = {}) {
    return resources instanceof ResourcesMock ? resources : new ResourcesMock(resources, options);
  }

  #kerberos = null;

  #policyGroups = [];

  /**
   * @param {Kerberos} kerberos
   * @param {unknown[]} policies
   * @param {object} [options]
   */
  constructor(kerberos, policies, options = {}) {
    if (!kerberos || !(kerberos instanceof Kerberos)) throw new Error('Kerberos instance is required');
    this.#kerberos = kerberos;
    const parsedPolicies = KerberosTests.parsePolicies(policies, options);
    for (const policy of parsedPolicies) {
      this.#policyGroups.push({
        policy,
        tests: KerberosTests.parseTests(policy.tests, kerberos, options),
        principals: KerberosTests.buildPrincipalsMock(policy.principals, options),
        resources: KerberosTests.buildResourcesMock(policy.resources, options),
      });
    }
  }

  /**
   * Registers grouped tests in the provided test runtime.
   *
   * @param {{ effectAsBoolean?: boolean }} options
   * @param {{ describe: Function, it: Function, assert: { ok: Function, strictEqual: Function } }} runtime
   * @returns {void}
   */
  run({ effectAsBoolean = false }, { describe, it, assert }) {
    for (const { policy, tests, principals, resources } of this.#policyGroups) {
      describe(policy.name, () => {
        for (const test of tests) {
          test.run(
            {
              kerberos: this.#kerberos,
              principals: [principals],
              resources: [resources],
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
