const { PrincipalMockZodSchemas } = require('./schemas');
const { parsePrincipalMockShape } = require('./validation');

/**
 * Represents a named principal fixture used by the test helpers.
 */
class PrincipalMock {
  /**
   * Parses a principal mock shape with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parsePrincipalMockShape(shape, options);
  }

  #shape = null;

  /**
   * @param {unknown} shape
   * @param {object} [options]
   */
  constructor(shape, options = {}) {
    this.#shape = PrincipalMock.parseShape(shape, options);
  }

  get id() {
    return this.#shape.id;
  }

  get name() {
    return this.#shape.name;
  }

  get roles() {
    return this.#shape.roles;
  }

  get attr() {
    return this.#shape.attr;
  }
}

module.exports = {
  PrincipalMock,
  PrincipalMockZodSchemas,
};
