const { JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');

/**
 * Zod schema builders for response metadata.
 */
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

/**
 * Plain JSON Schema builders for response metadata.
 */
class MetadataJsonSchemas extends JsonSchemas {
  static buildActionMetadata() {
    return JsonSchemas.buildObjectShape(
      {
        matchedPolicy: { type: 'string' },
        matchedRule: { type: 'string' },
        matchedScope: { type: 'string' },
      },
      ['matchedPolicy']
    );
  }

  static buildActionsMetadata() {
    return JsonSchemas.buildRecordShape(MetadataJsonSchemas.buildActionMetadata());
  }

  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        actions: MetadataJsonSchemas.buildActionsMetadata(),
        effectiveDerivedRoles: {
          type: 'array',
          items: { type: 'string' },
        },
      },
      ['actions']
    );
  }
}

/**
 * TypeBox schema builders for response metadata.
 */
class MetadataTypeBoxSchemas extends TypeBoxSchemas {
  static buildActionMetadata(t) {
    return t.Object({
      matchedPolicy: t.String(),
      matchedRule: t.Optional(t.String()),
      matchedScope: t.Optional(t.String()),
    });
  }

  static buildActionsMetadata(t) {
    return t.Record(t.String(), MetadataTypeBoxSchemas.buildActionMetadata(t));
  }

  static buildShape(t) {
    return t.Object({
      actions: MetadataTypeBoxSchemas.buildActionsMetadata(t),
      effectiveDerivedRoles: t.Optional(t.Array(t.String())),
    });
  }
}

module.exports = {
  MetadataJsonSchemas,
  MetadataTypeBoxSchemas,
  MetadataZodSchemas,
};
