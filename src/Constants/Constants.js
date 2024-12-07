import { z } from 'zod';

import { ConstantsSchemaSchema } from './schemas.js';

export class Constants {
  constructor(schema) {
    this.schema = ConstantsSchemaSchema.parse(schema);
  }

  get() {
    return this.schema;
  }
}

export const ConstantsInstanceSchema = z.instanceof(Constants);
