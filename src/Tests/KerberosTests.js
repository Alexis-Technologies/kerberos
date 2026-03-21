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

  static parsePrincipals(principals, options = {}) {
    return principals instanceof PrincipalsMock ? principals.mocks : new PrincipalsMock(principals, options).mocks;
  }

  static parseResources(resources, options = {}) {
    return resources instanceof ResourcesMock ? resources.mocks : new ResourcesMock(resources, options).mocks;
  }

  #kerberos = null;

  #policies = [];

  #tests = [];

  #principals = null;

  #resources = null;

  /**
   * @param {Kerberos} kerberos
   * @param {unknown[]} policies
   * @param {object} [options]
   */
  constructor(kerberos, policies, options = {}) {
    if (!kerberos || !(kerberos instanceof Kerberos)) throw new Error('Kerberos instance is required');
    this.#kerberos = kerberos;
    this.#policies = KerberosTests.parsePolicies(policies, options);
    for (const policy of this.#policies) this.#tests.push(...KerberosTests.parseTests(policy.tests, kerberos, options));
    const principals = [];
    for (const policy of policies) principals.push(...KerberosTests.parsePrincipals(policy.principals, options));
    this.#principals = new PrincipalsMock(principals, options);
    const resources = [];
    for (const policy of policies) resources.push(...KerberosTests.parseResources(policy.resources, options));
    this.#resources = new ResourcesMock(resources, options);
  }

  /**
   * Registers grouped tests in the provided test runtime.
   *
   * @param {{ effectAsBoolean?: boolean }} options
   * @param {{ describe: Function, it: Function, assert: { ok: Function, strictEqual: Function } }} runtime
   * @returns {void}
   */
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

module.exports = { KerberosTests };
