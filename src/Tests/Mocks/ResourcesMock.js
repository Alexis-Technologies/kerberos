const { ResourceMock } = require('./ResourceMock.js');
const { ResourcesMockZodSchemas } = require('./schemas');
const { parseResourcesMockShape } = require('./validation');

/**
 * Collection of named resource fixtures used in tests.
 */
class ResourcesMock {
  /**
   * Parses resources mocks with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parseResourcesMockShape(shape, ResourceMock, options);
  }

  #resources = new Map();

  /**
   * @param {unknown} resources
   * @param {object} [options]
   */
  constructor(resources, options = {}) {
    const parsedResources = ResourcesMock.parseShape(resources, options);
    if (Array.isArray(parsedResources)) {
      for (const resource of parsedResources) this.#resources.set(resource.name, resource);
    } else {
      for (const name in parsedResources) {
        if (!Object.prototype.hasOwnProperty.call(parsedResources, name)) continue;
        const resource = parsedResources[name];
        const mock = new ResourceMock({ ...resource, name }, options);
        this.#resources.set(mock.name, mock);
      }
    }
  }

  get mocks() {
    return [...this.#resources.values()];
  }

  get(name) {
    return this.#resources.get(name);
  }

  getById(id) {
    return [...this.#resources.values()].find((r) => r.id === id);
  }
}

module.exports = { ResourcesMock, ResourcesMockZodSchemas };
