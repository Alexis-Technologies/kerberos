import { z } from 'zod';

import { ResourceMock, ResourceMockSchema } from './ResourceMock.js';

export const ResourcesMockSchema = z.union([z.array(z.instanceof(ResourceMock)).nonempty(), z.record(ResourceMockSchema.shape.name, ResourceMockSchema.omit({ name: true }))]);

export class ResourcesMock {
  constructor(resources) {
    const parsedResources = ResourcesMockSchema.parse(resources);
    this.resources = new Map();
    if (Array.isArray(parsedResources)) {
      parsedResources.forEach((resource) => this.resources.set(resource.name, resource));
    } else {
      Object.entries(parsedResources).forEach(([name, resource]) => {
        const mock = new ResourceMock({ ...resource, name });
        this.resources.set(mock.name, mock);
      });
    }
  }

  get mocks() {
    return [...this.resources.values()];
  }

  get(name) {
    return this.resources.get(name);
  }

  getById(id) {
    return [...this.resources.values()].find((r) => r.id === id);
  }
}
