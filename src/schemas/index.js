const { KERBEROS_TYPE_KEYWORD, KERBEROS_INSTANCE_OF_KEYWORD } = require('../validation/keywords.js');

const ALL_ACTIONS = '*';

const Effect = {
  Allow: 'EFFECT_ALLOW',
  Deny: 'EFFECT_DENY',
};

/**
 * Shared Zod schema builders used across the runtime.
 */
class ZodSchemas {
  static buildScopeString(z) {
    return z.string().regex(/^[a-zA-Z0-9._-]*$/, 'Scope must contain only alphanumeric characters, dots, hyphens and underscores');
  }

  static buildRequestPrincipal(z) {
    return z.object({
      id: z.string(),
      policyVersion: z.string().optional(),
      scope: ZodSchemas.buildScopeString(z).optional(),
      roles: z.array(z.string()).nonempty(),
      attr: z.record(z.string(), z.unknown()).optional(),
    });
  }

  static buildRequestResource(z) {
    return z.object({
      id: z.string(),
      kind: z.string(),
      policyVersion: z.string().optional(),
      scope: ZodSchemas.buildScopeString(z).optional(),
      attr: z.record(z.string(), z.unknown()).optional(),
    });
  }

  static buildRequest(z) {
    return z.object({
      principal: ZodSchemas.buildRequestPrincipal(z),
      resource: ZodSchemas.buildRequestResource(z),
      P: ZodSchemas.buildRequestPrincipal(z),
      R: ZodSchemas.buildRequestResource(z),
      actions: z.array(z.string()).nonempty(),
      reqId: z.string().optional(),
      callId: z.string().optional(),
      includeMeta: z.boolean().optional(),
    });
  }
}

/**
 * Shared plain JSON Schema builders used with Ajv.
 */
class JsonSchemas {
  static buildScopeString() {
    return {
      type: 'string',
      pattern: '^[a-zA-Z0-9._-]*$',
    };
  }

  static buildUnknownRecordShape() {
    return {
      type: 'object',
      propertyNames: { type: 'string' },
      additionalProperties: true,
    };
  }

  static buildRecordShape(valueSchema) {
    return {
      type: 'object',
      propertyNames: { type: 'string' },
      additionalProperties: valueSchema,
    };
  }

  static buildFunctionShape() {
    return {
      [KERBEROS_TYPE_KEYWORD]: 'function',
    };
  }

  static buildInstanceOfShape(ExpectedClass) {
    return {
      [KERBEROS_INSTANCE_OF_KEYWORD]: ExpectedClass,
    };
  }

  static buildNonEmptyArrayShape(items) {
    return {
      type: 'array',
      items,
      minItems: 1,
    };
  }

  static buildObjectShape(properties, required, extras = {}) {
    // `additionalProperties: true` keeps validation lenient/forward-compatible:
    // unknown fields are accepted rather than rejected, matching the TypeBox
    // backend (lenient by default) and Zod (strips unknown keys by default).
    return {
      type: 'object',
      properties,
      required,
      additionalProperties: true,
      ...extras,
    };
  }

  static mergeObjectShapes(...shapes) {
    const properties = {};
    const required = new Set();
    const defs = {};

    for (const shape of shapes) {
      if (!shape) continue;
      Object.assign(properties, shape.properties ?? {});
      for (const key of shape.required ?? []) required.add(key);
      Object.assign(defs, shape.$defs ?? {});
    }

    const merged = {
      type: 'object',
      properties,
      required: [...required],
      additionalProperties: true,
    };

    if (Object.keys(defs).length > 0) merged.$defs = defs;

    return merged;
  }

  static buildRequestPrincipal() {
    return JsonSchemas.buildObjectShape(
      {
        id: { type: 'string' },
        policyVersion: { type: 'string' },
        scope: JsonSchemas.buildScopeString(),
        roles: JsonSchemas.buildNonEmptyArrayShape({ type: 'string' }),
        attr: JsonSchemas.buildUnknownRecordShape(),
      },
      ['id', 'roles']
    );
  }

  static buildRequestResource() {
    return JsonSchemas.buildObjectShape(
      {
        id: { type: 'string' },
        kind: { type: 'string' },
        policyVersion: { type: 'string' },
        scope: JsonSchemas.buildScopeString(),
        attr: JsonSchemas.buildUnknownRecordShape(),
      },
      ['id', 'kind']
    );
  }

  static buildRequest() {
    return JsonSchemas.buildObjectShape(
      {
        principal: JsonSchemas.buildRequestPrincipal(),
        resource: JsonSchemas.buildRequestResource(),
        P: JsonSchemas.buildRequestPrincipal(),
        R: JsonSchemas.buildRequestResource(),
        actions: JsonSchemas.buildNonEmptyArrayShape({ type: 'string' }),
        reqId: { type: 'string' },
        callId: { type: 'string' },
        includeMeta: { type: 'boolean' },
      },
      ['principal', 'resource', 'P', 'R', 'actions']
    );
  }
}

/**
 * Shared TypeBox schema builders used with Ajv.
 */
class TypeBoxSchemas {
  static buildScopeString(t) {
    return t.String({ pattern: '^[a-zA-Z0-9._-]*$' });
  }

  static buildUnknownRecordShape(t) {
    return t.Record(t.String(), t.Unknown());
  }

  static buildFunctionShape(t) {
    return t.Unsafe({
      [KERBEROS_TYPE_KEYWORD]: 'function',
    });
  }

  static buildInstanceOfShape(t, ExpectedClass) {
    return t.Unsafe({
      [KERBEROS_INSTANCE_OF_KEYWORD]: ExpectedClass,
    });
  }

  static buildNonEmptyArrayShape(t, items) {
    return t.Array(items, { minItems: 1 });
  }

  static buildRequestPrincipal(t) {
    return t.Object({
      id: t.String(),
      policyVersion: t.Optional(t.String()),
      scope: t.Optional(TypeBoxSchemas.buildScopeString(t)),
      roles: TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String()),
      attr: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
    });
  }

  static buildRequestResource(t) {
    return t.Object({
      id: t.String(),
      kind: t.String(),
      policyVersion: t.Optional(t.String()),
      scope: t.Optional(TypeBoxSchemas.buildScopeString(t)),
      attr: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
    });
  }

  static buildRequest(t) {
    return t.Object({
      principal: TypeBoxSchemas.buildRequestPrincipal(t),
      resource: TypeBoxSchemas.buildRequestResource(t),
      P: TypeBoxSchemas.buildRequestPrincipal(t),
      R: TypeBoxSchemas.buildRequestResource(t),
      actions: TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String()),
      reqId: t.Optional(t.String()),
      callId: t.Optional(t.String()),
      includeMeta: t.Optional(t.Boolean()),
    });
  }
}

module.exports = {
  ALL_ACTIONS,
  Effect,
  JsonSchemas,
  TypeBoxSchemas,
  ZodSchemas,
};
