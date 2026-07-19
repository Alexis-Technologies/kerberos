const {
  Conditions,
  ConditionsJsonSchemas,
  ConditionsTypeBoxSchemas,
  ConditionsZodSchemas,
} = require('../../Conditions');
const { JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('../../schemas');

/**
 * Zod schema builders for the ReBAC relation schema, tuples and resolver
 * arguments.
 */
class RelationsZodSchemas extends ZodSchemas {
  static buildSubjectRefShape(z) {
    // 'user' | 'user:*' | 'group#member' | { type, relation?, wildcard?, caveat? }
    return z.union([
      z.string(),
      z.object({
        type: z.string(),
        relation: z.string().optional(),
        wildcard: z.boolean().optional(),
        caveat: z.string().optional(),
      }),
    ]);
  }

  static buildPermissionExprShape(z) {
    const expr = z.lazy(() =>
      z.union([
        z.string(),
        z.object({ via: z.string(), permission: z.string(), all: z.boolean().optional() }),
        z.object({ anyOf: z.array(expr).nonempty() }),
        z.object({ allOf: z.array(expr).nonempty() }),
        z.object({ exclude: z.object({ base: expr, subtract: z.array(expr).nonempty() }) }),
      ]),
    );
    return expr;
  }

  static buildCaveatShape(z) {
    // The { match: { $expr } } branch comes before the Conditions shape: a
    // JSON-authored caveat is not a valid Conditions match until the codec
    // compiles the descriptor into a function.
    return z.union([
      z.instanceof(Conditions),
      z.object({ match: z.object({ $expr: z.string() }) }),
      ConditionsZodSchemas.buildShape(z),
    ]);
  }

  static buildDefinitionShape(z) {
    return z.object({
      relations: z.record(z.string(), z.array(RelationsZodSchemas.buildSubjectRefShape(z)).nonempty()).optional(),
      permissions: z.record(z.string(), RelationsZodSchemas.buildPermissionExprShape(z)).optional(),
    });
  }

  static buildShape(z) {
    return z.object({
      relationSchema: z.object({
        description: z.string().optional(),
        caveats: z.record(z.string(), RelationsZodSchemas.buildCaveatShape(z)).optional(),
        definitions: z.record(z.string(), RelationsZodSchemas.buildDefinitionShape(z)),
      }),
    });
  }

  static buildTupleShape(z) {
    // 'document:readme#viewer@user:emilia' | { resource, relation, subject, caveat? }
    return z.union([
      z.string(),
      z.object({
        resource: z.string(),
        relation: z.string(),
        subject: z.string(),
        caveat: z.object({ name: z.string(), context: z.record(z.string(), z.unknown()).optional() }).optional(),
      }),
    ]);
  }

  static buildCheckArgs(z) {
    // Exactly one of subject|principal and one of permission|relation is
    // enforced at runtime (always-on), keeping the schema lenient.
    return z.object({
      resource: z.union([z.string(), ZodSchemas.buildRequestResource(z)]),
      subject: z.string().optional(),
      principal: ZodSchemas.buildRequestPrincipal(z).optional(),
      permission: z.string().optional(),
      relation: z.string().optional(),
      context: z.record(z.string(), z.unknown()).optional(),
    });
  }

  static buildLookupSubjectsArgs(z) {
    return z.object({
      resource: z.union([z.string(), ZodSchemas.buildRequestResource(z)]),
      permission: z.string().optional(),
      relation: z.string().optional(),
      subjectType: z.string().optional(),
      context: z.record(z.string(), z.unknown()).optional(),
    });
  }

  static buildLookupResourcesArgs(z) {
    return z.object({
      subject: z.string().optional(),
      principal: ZodSchemas.buildRequestPrincipal(z).optional(),
      permission: z.string().optional(),
      relation: z.string().optional(),
      resourceType: z.string(),
      context: z.record(z.string(), z.unknown()).optional(),
    });
  }
}

/**
 * Plain JSON Schema builders for the ReBAC relation schema, tuples and
 * resolver arguments.
 */
class RelationsJsonSchemas extends JsonSchemas {
  // Monotonic counter that keeps each generated permission-expression `$id`
  // unique so recursive `$ref`s never collide across embedded schemas.
  static #permissionExprSeq = 0;

  static buildSubjectRefShape() {
    return {
      anyOf: [
        { type: 'string' },
        JsonSchemas.buildObjectShape(
          {
            type: { type: 'string' },
            relation: { type: 'string' },
            wildcard: { type: 'boolean' },
            caveat: { type: 'string' },
          },
          ['type'],
        ),
      ],
    };
  }

  static buildPermissionExprShape() {
    const $id = `kerberos:relation-permission-expr-${(RelationsJsonSchemas.#permissionExprSeq += 1)}`;
    const self = { $ref: $id };
    return {
      $id,
      anyOf: [
        { type: 'string' },
        JsonSchemas.buildObjectShape(
          {
            via: { type: 'string' },
            permission: { type: 'string' },
            all: { type: 'boolean' },
          },
          ['via', 'permission'],
        ),
        JsonSchemas.buildObjectShape({ anyOf: JsonSchemas.buildNonEmptyArrayShape(self) }, ['anyOf']),
        JsonSchemas.buildObjectShape({ allOf: JsonSchemas.buildNonEmptyArrayShape(self) }, ['allOf']),
        JsonSchemas.buildObjectShape(
          {
            exclude: JsonSchemas.buildObjectShape({ base: self, subtract: JsonSchemas.buildNonEmptyArrayShape(self) }, [
              'base',
              'subtract',
            ]),
          },
          ['exclude'],
        ),
      ],
    };
  }

  static buildCaveatShape() {
    return {
      anyOf: [
        JsonSchemas.buildInstanceOfShape(Conditions),
        JsonSchemas.buildObjectShape(
          { match: JsonSchemas.buildObjectShape({ $expr: { type: 'string' } }, ['$expr']) },
          ['match'],
        ),
        ConditionsJsonSchemas.buildShape(),
      ],
    };
  }

  static buildDefinitionShape() {
    return JsonSchemas.buildObjectShape(
      {
        relations: JsonSchemas.buildRecordShape(
          JsonSchemas.buildNonEmptyArrayShape(RelationsJsonSchemas.buildSubjectRefShape()),
        ),
        permissions: JsonSchemas.buildRecordShape(RelationsJsonSchemas.buildPermissionExprShape()),
      },
      [],
    );
  }

  static buildShape() {
    return JsonSchemas.buildObjectShape(
      {
        relationSchema: JsonSchemas.buildObjectShape(
          {
            description: { type: 'string' },
            caveats: JsonSchemas.buildRecordShape(RelationsJsonSchemas.buildCaveatShape()),
            definitions: JsonSchemas.buildRecordShape(RelationsJsonSchemas.buildDefinitionShape()),
          },
          ['definitions'],
        ),
      },
      ['relationSchema'],
    );
  }

  static buildTupleShape() {
    return {
      anyOf: [
        { type: 'string' },
        JsonSchemas.buildObjectShape(
          {
            resource: { type: 'string' },
            relation: { type: 'string' },
            subject: { type: 'string' },
            caveat: JsonSchemas.buildObjectShape(
              { name: { type: 'string' }, context: JsonSchemas.buildUnknownRecordShape() },
              ['name'],
            ),
          },
          ['resource', 'relation', 'subject'],
        ),
      ],
    };
  }

  static buildCheckArgs() {
    return JsonSchemas.buildObjectShape(
      {
        resource: { anyOf: [{ type: 'string' }, JsonSchemas.buildRequestResource()] },
        subject: { type: 'string' },
        principal: JsonSchemas.buildRequestPrincipal(),
        permission: { type: 'string' },
        relation: { type: 'string' },
        context: JsonSchemas.buildUnknownRecordShape(),
      },
      ['resource'],
    );
  }

  static buildLookupSubjectsArgs() {
    return JsonSchemas.buildObjectShape(
      {
        resource: { anyOf: [{ type: 'string' }, JsonSchemas.buildRequestResource()] },
        permission: { type: 'string' },
        relation: { type: 'string' },
        subjectType: { type: 'string' },
        context: JsonSchemas.buildUnknownRecordShape(),
      },
      ['resource'],
    );
  }

  static buildLookupResourcesArgs() {
    return JsonSchemas.buildObjectShape(
      {
        subject: { type: 'string' },
        principal: JsonSchemas.buildRequestPrincipal(),
        permission: { type: 'string' },
        relation: { type: 'string' },
        resourceType: { type: 'string' },
        context: JsonSchemas.buildUnknownRecordShape(),
      },
      ['resourceType'],
    );
  }
}

/**
 * TypeBox schema builders for the ReBAC relation schema, tuples and resolver
 * arguments.
 */
class RelationsTypeBoxSchemas extends TypeBoxSchemas {
  static buildSubjectRefShape(t) {
    return t.Union([
      t.String(),
      t.Object({
        type: t.String(),
        relation: t.Optional(t.String()),
        wildcard: t.Optional(t.Boolean()),
        caveat: t.Optional(t.String()),
      }),
    ]);
  }

  static buildPermissionExprShape(t) {
    return t.Recursive((Self) =>
      t.Union([
        t.String(),
        t.Object({ via: t.String(), permission: t.String(), all: t.Optional(t.Boolean()) }),
        t.Object({ anyOf: TypeBoxSchemas.buildNonEmptyArrayShape(t, Self) }),
        t.Object({ allOf: TypeBoxSchemas.buildNonEmptyArrayShape(t, Self) }),
        t.Object({
          exclude: t.Object({ base: Self, subtract: TypeBoxSchemas.buildNonEmptyArrayShape(t, Self) }),
        }),
      ]),
    );
  }

  static buildCaveatShape(t) {
    return t.Union([
      TypeBoxSchemas.buildInstanceOfShape(t, Conditions),
      t.Object({ match: t.Object({ $expr: t.String() }) }),
      ConditionsTypeBoxSchemas.buildShape(t),
    ]);
  }

  static buildDefinitionShape(t) {
    return t.Object({
      relations: t.Optional(
        t.Record(
          t.String(),
          TypeBoxSchemas.buildNonEmptyArrayShape(t, RelationsTypeBoxSchemas.buildSubjectRefShape(t)),
        ),
      ),
      permissions: t.Optional(t.Record(t.String(), RelationsTypeBoxSchemas.buildPermissionExprShape(t))),
    });
  }

  static buildShape(t) {
    return t.Object({
      relationSchema: t.Object({
        description: t.Optional(t.String()),
        caveats: t.Optional(t.Record(t.String(), RelationsTypeBoxSchemas.buildCaveatShape(t))),
        definitions: t.Record(t.String(), RelationsTypeBoxSchemas.buildDefinitionShape(t)),
      }),
    });
  }

  static buildTupleShape(t) {
    return t.Union([
      t.String(),
      t.Object({
        resource: t.String(),
        relation: t.String(),
        subject: t.String(),
        caveat: t.Optional(
          t.Object({ name: t.String(), context: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)) }),
        ),
      }),
    ]);
  }

  static buildCheckArgs(t) {
    return t.Object({
      resource: t.Union([t.String(), TypeBoxSchemas.buildRequestResource(t)]),
      subject: t.Optional(t.String()),
      principal: t.Optional(TypeBoxSchemas.buildRequestPrincipal(t)),
      permission: t.Optional(t.String()),
      relation: t.Optional(t.String()),
      context: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
    });
  }

  static buildLookupSubjectsArgs(t) {
    return t.Object({
      resource: t.Union([t.String(), TypeBoxSchemas.buildRequestResource(t)]),
      permission: t.Optional(t.String()),
      relation: t.Optional(t.String()),
      subjectType: t.Optional(t.String()),
      context: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
    });
  }

  static buildLookupResourcesArgs(t) {
    return t.Object({
      subject: t.Optional(t.String()),
      principal: t.Optional(TypeBoxSchemas.buildRequestPrincipal(t)),
      permission: t.Optional(t.String()),
      relation: t.Optional(t.String()),
      resourceType: t.String(),
      context: t.Optional(TypeBoxSchemas.buildUnknownRecordShape(t)),
    });
  }
}

module.exports = {
  RelationsJsonSchemas,
  RelationsTypeBoxSchemas,
  RelationsZodSchemas,
};
