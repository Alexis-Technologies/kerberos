import { z } from 'zod';

import { RequestResourceSchema } from '../../schemas.js';

export const ResourceMockSchema = RequestResourceSchema.extend({ name: z.string() });

export class ResourceMock {
  constructor(schema) {
    this.schema = ResourceMockSchema.parse(schema);
  }

  get id() {
    return this.schema.id;
  }

  get name() {
    return this.schema.name;
  }

  get kind() {
    return this.schema.kind;
  }

  get attr() {
    return this.schema.attr;
  }
}
