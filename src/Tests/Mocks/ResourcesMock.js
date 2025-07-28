const { ResourceMock, ResourceMockZodSchemas } = require('./ResourceMock.js');

class ResourcesMockZodSchemas extends ResourceMockZodSchemas {
  static buildShape(z) {
    const ResourceMockShapeZodSchema = ResourceMockZodSchemas.buildShape(z);
    return z.union([
      z.array(z.instanceof(ResourceMock)).nonempty(),
      z.record(ResourceMockShapeZodSchema.shape.name, ResourceMockShapeZodSchema.omit({ name: true })),
    ]);
  }
}

class ResourcesMock {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return ResourcesMockZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  #resources = new Map();

  constructor(resources, { z } = {}) {
    const parsedResources = ResourcesMock.parseShape(resources, { z });
    if (Array.isArray(parsedResources)) {
      parsedResources.forEach((resource) => this.#resources.set(resource.name, resource));
    } else {
      Object.entries(parsedResources).forEach(([name, resource]) => {
        const mock = new ResourceMock({ ...resource, name });
        this.#resources.set(mock.name, mock);
      });
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
