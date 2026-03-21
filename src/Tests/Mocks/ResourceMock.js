const { ResourceMockZodSchemas } = require('./schemas');
const { parseResourceMockShape } = require('./validation');

/**
 * Represents a named resource fixture used by the test helpers.
 */
class ResourceMock {
  /**
   * Parses a resource mock shape with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parseResourceMockShape(shape, options);
  }

  #shape = null;

  /**
   * @param {unknown} shape
   * @param {object} [options]
   */
  constructor(shape, options = {}) {
    this.#shape = ResourceMock.parseShape(shape, options);
  }

  get id() {
    return this.#shape.id;
  }

  get name() {
    return this.#shape.name;
  }

  get kind() {
    return this.#shape.kind;
  }

  get attr() {
    return this.#shape.attr;
  }
}

module.exports = { ResourceMock, ResourceMockZodSchemas };
