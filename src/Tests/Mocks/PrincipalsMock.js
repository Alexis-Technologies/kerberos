const { PrincipalMock } = require('./PrincipalMock.js');
const { PrincipalsMockZodSchemas } = require('./schemas');
const { parsePrincipalsMockShape } = require('./validation');

/**
 * Collection of named principal fixtures used in tests.
 */
class PrincipalsMock {
  /**
   * Parses principals mocks with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parsePrincipalsMockShape(shape, PrincipalMock, options);
  }

  #principals = new Map();

  /**
   * @param {unknown} principals
   * @param {object} [options]
   */
  constructor(principals, options = {}) {
    const parsedPrincipals = PrincipalsMock.parseShape(principals, options);
    if (Array.isArray(parsedPrincipals)) {
      for (const principal of parsedPrincipals) this.#principals.set(principal.name, principal);
    } else {
      for (const name in parsedPrincipals) {
        if (!Object.prototype.hasOwnProperty.call(parsedPrincipals, name)) continue;
        const principal = parsedPrincipals[name];
        const mock = new PrincipalMock({ ...principal, name }, options);
        this.#principals.set(mock.name, mock);
      }
    }
  }

  get mocks() {
    return [...this.#principals.values()];
  }

  get(name) {
    return this.#principals.get(name);
  }
}

module.exports = { PrincipalsMockZodSchemas, PrincipalsMock };
