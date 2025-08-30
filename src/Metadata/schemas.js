const { ZodSchemas } = require('../schemas.js');

class MetadataZodSchemas extends ZodSchemas {
  static buildActionMetadata(z) {
    return z.object({
      matchedPolicy: z.string(),
      matchedRule: z.string().optional(),
      matchedScope: z.string().optional(),
    });
  }

  static buildActionsMetadata(z) {
    return z.record(z.string(), MetadataZodSchemas.buildActionMetadata(z));
  }

  static buildShape(z) {
    return z.object({
      actions: MetadataZodSchemas.buildActionsMetadata(z),
      effectiveDerivedRoles: z.array(z.string()).optional(),
    });
  }
}

module.exports = { MetadataZodSchemas };
