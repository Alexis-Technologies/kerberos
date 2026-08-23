const { JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');

// Deny reasons recorded in meta.actions entries (see KerberosDecisionReason in
// index.d.ts): 'policy-miss' entries carry NO matchedPolicy at all, which is
// why every action-metadata field below is optional. 'evaluation-error' marks
// fail-closed denials from a rejected per-resource evaluation in
// checkResources (paired with an optional errorName).
const DECISION_REASONS = ['policy-miss', 'rule-miss', 'condition-not-met', 'evaluation-error'];

const POLICY_TRACE_SOURCES = ['principal', 'role', 'resource'];

/**
 * Zod schema builders for response metadata.
 */
class MetadataZodSchemas extends ZodSchemas {
  static buildActionMetadata(z) {
    return z.object({
      matchedPolicy: z.string().optional(),
      matchedRule: z.string().optional(),
      matchedScope: z.string().optional(),
      reason: z.enum(DECISION_REASONS).optional(),
      errorName: z.string().optional(),
    });
  }

  static buildActionsMetadata(z) {
    return z.record(z.string(), MetadataZodSchemas.buildActionMetadata(z));
  }

  static buildResolutionTraceEntry(z) {
    return z.union([
      z.object({
        source: z.enum(POLICY_TRACE_SOURCES),
        id: z.string(),
        version: z.string(),
        scopesSearched: z.array(z.string()),
        matchedScope: z.string().nullable(),
        origin: z.literal('cache').optional(),
      }),
      z.object({
        source: z.literal('relations'),
        name: z.string(),
        relation: z.string(),
        matched: z.boolean(),
        reason: z.literal('no-relations-resolver').optional(),
      }),
    ]);
  }

  static buildShape(z) {
    return z.object({
      actions: MetadataZodSchemas.buildActionsMetadata(z),
      effectiveDerivedRoles: z.array(z.string()).optional(),
      resolution: z.array(MetadataZodSchemas.buildResolutionTraceEntry(z)).optional(),
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
        reason: { type: 'string', enum: DECISION_REASONS },
        errorName: { type: 'string' },
      },
      [],
    );
  }

  static buildActionsMetadata() {
    return JsonSchemas.buildRecordShape(MetadataJsonSchemas.buildActionMetadata());
  }

  static buildResolutionTraceEntry() {
    return {
      // `anyOf` (not a `type` array) keeps the schema valid under Ajv strict
      // mode without the allowUnionTypes option.
      anyOf: [
        JsonSchemas.buildObjectShape(
          {
            source: { type: 'string', enum: POLICY_TRACE_SOURCES },
            id: { type: 'string' },
            version: { type: 'string' },
            scopesSearched: { type: 'array', items: { type: 'string' } },
            matchedScope: { anyOf: [{ type: 'string' }, { type: 'null' }] },
            origin: { type: 'string', enum: ['cache'] },
          },
          ['source', 'id', 'version', 'scopesSearched', 'matchedScope'],
        ),
        JsonSchemas.buildObjectShape(
          {
            source: { type: 'string', enum: ['relations'] },
            name: { type: 'string' },
            relation: { type: 'string' },
            matched: { type: 'boolean' },
            reason: { type: 'string', enum: ['no-relations-resolver'] },
          },
          ['source', 'name', 'relation', 'matched'],
        ),
      ],
    };
  }

  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        actions: MetadataJsonSchemas.buildActionsMetadata(),
        effectiveDerivedRoles: {
          type: 'array',
          items: { type: 'string' },
        },
        resolution: {
          type: 'array',
          items: MetadataJsonSchemas.buildResolutionTraceEntry(),
        },
      },
      ['actions'],
    );
  }
}

/**
 * TypeBox schema builders for response metadata.
 */
class MetadataTypeBoxSchemas extends TypeBoxSchemas {
  static buildActionMetadata(t) {
    return t.Object({
      matchedPolicy: t.Optional(t.String()),
      matchedRule: t.Optional(t.String()),
      matchedScope: t.Optional(t.String()),
      reason: t.Optional(t.Union(DECISION_REASONS.map((reason) => t.Literal(reason)))),
      errorName: t.Optional(t.String()),
    });
  }

  static buildActionsMetadata(t) {
    return t.Record(t.String(), MetadataTypeBoxSchemas.buildActionMetadata(t));
  }

  static buildResolutionTraceEntry(t) {
    return t.Union([
      t.Object({
        source: t.Union(POLICY_TRACE_SOURCES.map((source) => t.Literal(source))),
        id: t.String(),
        version: t.String(),
        scopesSearched: t.Array(t.String()),
        matchedScope: t.Union([t.String(), t.Null()]),
        origin: t.Optional(t.Literal('cache')),
      }),
      t.Object({
        source: t.Literal('relations'),
        name: t.String(),
        relation: t.String(),
        matched: t.Boolean(),
        reason: t.Optional(t.Literal('no-relations-resolver')),
      }),
    ]);
  }

  static buildShape(t) {
    return t.Object({
      actions: MetadataTypeBoxSchemas.buildActionsMetadata(t),
      effectiveDerivedRoles: t.Optional(t.Array(t.String())),
      resolution: t.Optional(t.Array(MetadataTypeBoxSchemas.buildResolutionTraceEntry(t))),
    });
  }
}

module.exports = {
  MetadataJsonSchemas,
  MetadataTypeBoxSchemas,
  MetadataZodSchemas,
};
