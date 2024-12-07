import { z } from 'zod';

import { VariablesSchemaSchema } from './schemas.js';

export class Variables {
  constructor(schema) {
    this.schema = VariablesSchemaSchema.parse(schema);
  }

  get(req) {
    return Object.fromEntries(Object.entries(this.schema).map(([name, fn]) => [name, fn(req)]));
  }
}

export const VariablesInstanceSchema = z.instanceof(Variables);
