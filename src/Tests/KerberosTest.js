const { ResourceMock, ResourcesMock, PrincipalMock, PrincipalsMock } = require('./Mocks/index.js');
const { Kerberos } = require('../Kerberos.js');
const { parseKerberosTestShape } = require('./validation');

/**
 * Declarative test case for running authorization expectations against Kerberos.
 */
class KerberosTest {
  /**
   * Parses a KerberosTest shape with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parseKerberosTestShape(shape, options);
  }

  #shape = null;

  #kerberos = null;

  #principals = [];

  #resources = [];

  /**
   * @param {unknown} shape
   * @param {Kerberos} [kerberos]
   * @param {object} [options]
   */
  constructor(shape, kerberos, options = {}) {
    this.#shape = KerberosTest.parseShape(shape, options);
    if (kerberos && !(kerberos instanceof Kerberos)) throw new Error('Invalid Kerberos instance!');
    this.#kerberos = kerberos;
    if (this.#shape.input.principals instanceof PrincipalsMock) this.#principals.push(this.#shape.input.principals);
    if (this.#shape.input.resources instanceof ResourcesMock) this.#resources.push(this.#shape.input.resources);
  }

  /**
   * Registers the generated test cases in the provided test runtime.
   *
   * @param {object} options
   * @param {Kerberos} [options.kerberos]
   * @param {PrincipalsMock[]} [options.principals]
   * @param {ResourcesMock[]} [options.resources]
   * @param {boolean} [options.effectAsBoolean=false]
   * @param {{ describe: Function, it: Function, assert: { ok: Function, strictEqual: Function } }} runtime
   * @returns {void}
   */
  run({ kerberos, principals, resources, effectAsBoolean = false }, { describe, it, assert }) {
    describe(this.#shape.name, () => {
      if (kerberos && !(kerberos instanceof Kerberos)) throw new Error('Invalid Kerberos instance!');

      const kerberosInstance = this.#kerberos || kerberos;
      if (!kerberosInstance) throw new Error('Kerberos instance is required!');

      const principalMocks = [];
      const resourceMocks = [];

      if (principals) {
        for (const p of principals) {
          if (!(p instanceof PrincipalsMock)) throw new Error('Invalid PrincipalsMock instance!');
          principalMocks.push(...p.mocks);
        }
      }
      if (resources) {
        for (const r of resources) {
          if (!(r instanceof ResourcesMock)) throw new Error('Invalid ResourcesMock instance!');
          resourceMocks.push(...r.mocks);
        }
      }

      for (const p of this.#principals) principalMocks.push(...p.mocks);
      const allPrincipalsMock = new PrincipalsMock(principalMocks);

      for (const r of this.#resources) resourceMocks.push(...r.mocks);
      const allResourcesMock = new ResourcesMock(resourceMocks);

      // Group expected results by principals
      const expectedByPrincipal = new Map();
      for (const expectedItem of this.#shape.expected) {
        const principalName =
          expectedItem.principal instanceof PrincipalMock ? expectedItem.principal.name : expectedItem.principal;
        const resourceName =
          expectedItem.resource instanceof ResourceMock ? expectedItem.resource.name : expectedItem.resource;

        const principal = allPrincipalsMock.get(principalName);
        const resource = allResourcesMock.get(resourceName);

        if (!principal) throw new Error(`Principal "${principalName}" not found!`);
        if (!resource) throw new Error(`Resource "${resourceName}" not found!`);

        if (!expectedByPrincipal.has(principalName)) {
          expectedByPrincipal.set(principalName, {
            principal,
            resources: new Map(),
          });
        }

        const principalData = expectedByPrincipal.get(principalName);

        // Add resource and actions to the principal's resources map
        if (!principalData.resources.has(resourceName)) {
          principalData.resources.set(resourceName, {
            resource,
            actions: new Set(),
            expectedActions: {},
          });
        }

        const resourceData = principalData.resources.get(resourceName);
        for (const [action, effect] of Object.entries(expectedItem.actions)) {
          resourceData.actions.add(action);
          resourceData.expectedActions[action] = effect;
        }
      }

      // For each principal, call checkResources once with all resources
      for (const [principalName, principalData] of expectedByPrincipal.entries()) {
        const { principal, resources: principalResourcesMap } = principalData;

        it(`should match expected actions for principal "${principalName}"`, async () => {
          const resourcesToCheck = [];
          for (const resourceData of principalResourcesMap.values()) {
            resourcesToCheck.push({ resource: resourceData.resource, actions: Array.from(resourceData.actions) });
          }

          const { results } = await kerberosInstance.checkResources({ principal, resources: resourcesToCheck }, effectAsBoolean);

          const resultsByResourceId = new Map();
          for (const result of results) resultsByResourceId.set(result.resource.id, result);

          for (const resourceData of principalResourcesMap.values()) {
            const result = resultsByResourceId.get(resourceData.resource.id);
            assert.ok(
              result,
              `No result returned for resource "${resourceData.resource.name}" (id: "${resourceData.resource.id}")!`
            );

            const resourceName = resourceData.resource.name;

            for (const [action, expectedEffect] of Object.entries(resourceData.expectedActions)) {
              const effect = result.actions[action];
              assert.ok(
                effect !== undefined,
                `Action "${action}" not found in the checked resources response for resource "${resourceName}"!`
              );
              assert.strictEqual(
                effect,
                expectedEffect,
                `Action "${action}" effect for resource "${resourceName}" is not matched! Expected: ${expectedEffect} but got: ${effect}`
              );
            }
          }
        });
      }
    });
  }
}

module.exports = {
  KerberosTest,
};
