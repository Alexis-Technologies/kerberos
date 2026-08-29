const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const jsep = require('jsep');
jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));
jsep.addUnaryOp('typeof');

const { queryPlanToPrisma, PlanKind: PrismaPlanKind } = require('@cerbos/orm-prisma');
const { queryPlanToDrizzle } = require('@cerbos/orm-drizzle');
const { sqliteTable, text, integer } = require('drizzle-orm/sqlite-core');
const { SQLiteSyncDialect } = require('drizzle-orm/sqlite-core');

const {
  Kerberos,
  createSafeExprCodec,
  deserializePolicy,
  expandRelationOperands,
  toCerbosQueryPlan,
  KerberosValidationError,
  PlanKind,
} = require('../index.js');

// The README's claim that Cerbos's ORM adapters "accept the filter" — made
// executable: real @cerbos/orm-prisma and @cerbos/orm-drizzle translate
// Kerberos planResources output (via toCerbosQueryPlan) into Prisma where
// objects and Drizzle SQL. The Kerberos-only operators are covered too:
// `relation` is materialized by expandRelationOperands first, `opaque` is
// rejected with a post-filtering directive instead of being mistranslated.

const codec = createSafeExprCodec({ jsep });

function buildEngine(rules, options = {}) {
  const policy = deserializePolicy(
    {
      resourcePolicy: {
        version: 'default',
        resource: 'document',
        ...(options.importDerivedRoles && { importDerivedRoles: options.importDerivedRoles }),
        rules,
      },
    },
    codec,
  );
  return new Kerberos(
    [policy],
    options.derivedRoles?.map((doc) => deserializePolicy(doc, codec)) ?? [],
    options.engine,
  );
}

const principal = { id: 'u1', roles: ['USER'] };

describe('toCerbosQueryPlan', () => {
  it('flattens HTTP-shaped operands into the SDK shape', async () => {
    const kerberos = buildEngine([
      {
        actions: ['view'],
        effect: 'EFFECT_ALLOW',
        roles: ['USER'],
        condition: { match: { $expr: 'R.attr.ownerId === P.id && R.attr.status === "OPEN"' } },
      },
    ]);
    const plan = await kerberos.planResources({ principal, resource: { kind: 'document' }, action: 'view' });
    assert.deepEqual(toCerbosQueryPlan(plan), {
      kind: 'KIND_CONDITIONAL',
      condition: {
        operator: 'and',
        operands: [
          { operator: 'eq', operands: [{ name: 'request.resource.attr.ownerId' }, { value: 'u1' }] },
          { operator: 'eq', operands: [{ name: 'request.resource.attr.status' }, { value: 'OPEN' }] },
        ],
      },
    });
    // The bare filter works too.
    assert.equal(toCerbosQueryPlan(plan.filter).kind, 'KIND_CONDITIONAL');
  });

  it('passes non-conditional kinds through', () => {
    assert.deepEqual(toCerbosQueryPlan({ filter: { kind: PlanKind.AlwaysAllowed } }), { kind: 'KIND_ALWAYS_ALLOWED' });
    assert.deepEqual(toCerbosQueryPlan({ kind: PlanKind.AlwaysDenied }), { kind: 'KIND_ALWAYS_DENIED' });
  });

  it('rejects malformed input', () => {
    assert.throws(() => toCerbosQueryPlan(null), KerberosValidationError);
    assert.throws(() => toCerbosQueryPlan({ kind: 'KIND_CONDITIONAL' }), KerberosValidationError);
  });
});

describe('@cerbos/orm-prisma accepts Kerberos plans', () => {
  const mapper = {
    'request.resource.attr.ownerId': { field: 'ownerId' },
    'request.resource.attr.status': { field: 'status' },
    'request.resource.id': { field: 'id' },
  };

  it('translates a conditional plan into a Prisma where object', async () => {
    const kerberos = buildEngine([
      {
        actions: ['view'],
        effect: 'EFFECT_ALLOW',
        roles: ['USER'],
        condition: { match: { $expr: 'R.attr.ownerId === P.id && R.attr.status === "OPEN"' } },
      },
    ]);
    const plan = await kerberos.planResources({ principal, resource: { kind: 'document' }, action: 'view' });
    const result = queryPlanToPrisma({ queryPlan: toCerbosQueryPlan(plan), mapper });
    assert.equal(result.kind, PrismaPlanKind.CONDITIONAL);
    assert.deepEqual(result.filters, {
      AND: [{ ownerId: { equals: 'u1' } }, { status: { equals: 'OPEN' } }],
    });
  });

  it('translates membership (`in`) conditions', async () => {
    const kerberos = buildEngine([
      {
        actions: ['view'],
        effect: 'EFFECT_ALLOW',
        roles: ['USER'],
        condition: { match: { $expr: '["OPEN", "REVIEW"].includes(R.attr.status)' } },
      },
    ]);
    const plan = await kerberos.planResources({ principal, resource: { kind: 'document' }, action: 'view' });
    const result = queryPlanToPrisma({ queryPlan: toCerbosQueryPlan(plan), mapper });
    assert.equal(result.kind, PrismaPlanKind.CONDITIONAL);
    assert.deepEqual(result.filters, { status: { in: ['OPEN', 'REVIEW'] } });
  });

  it('passes ALWAYS_ALLOWED / ALWAYS_DENIED through', async () => {
    const allowAll = buildEngine([{ actions: ['view'], effect: 'EFFECT_ALLOW', roles: ['USER'] }]);
    const allowedPlan = await allowAll.planResources({ principal, resource: { kind: 'document' }, action: 'view' });
    assert.equal(
      queryPlanToPrisma({ queryPlan: toCerbosQueryPlan(allowedPlan), mapper }).kind,
      PrismaPlanKind.ALWAYS_ALLOWED,
    );

    const deniedPlan = await allowAll.planResources({ principal, resource: { kind: 'document' }, action: 'delete' });
    assert.equal(
      queryPlanToPrisma({ queryPlan: toCerbosQueryPlan(deniedPlan), mapper }).kind,
      PrismaPlanKind.ALWAYS_DENIED,
    );
  });

  it('translates a relation plan after expandRelationOperands', async () => {
    const kerberos = buildEngine([{ actions: ['view'], effect: 'EFFECT_ALLOW', derivedRoles: ['viewer'] }], {
      importDerivedRoles: ['document_roles'],
      derivedRoles: [{ name: 'document_roles', definitions: [{ name: 'viewer', relation: 'view' }] }],
      engine: { relations: { check: async () => ({ matched: false }) } },
    });
    const plan = await kerberos.planResources({ principal, resource: { kind: 'document' }, action: 'view' });

    // Unexpanded: the converter refuses, pointing at expandRelationOperands.
    assert.throws(() => toCerbosQueryPlan(plan), /expandRelationOperands/);

    const expanded = await expandRelationOperands(plan, async () => ['d1', 'd2']);
    const result = queryPlanToPrisma({ queryPlan: toCerbosQueryPlan(expanded), mapper });
    assert.equal(result.kind, PrismaPlanKind.CONDITIONAL);
    assert.deepEqual(result.filters, { id: { in: ['d1', 'd2'] } });
  });

  it('rejects opaque plans with a post-filtering directive', async () => {
    // A live-function condition cannot be planned statically → opaque.
    const kerberos = new Kerberos(
      [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'document',
            rules: [
              {
                actions: ['view'],
                effect: 'EFFECT_ALLOW',
                roles: ['USER'],
                condition: { match: ({ R }) => R.attr.entropy > 0.5 },
              },
            ],
          },
        },
      ],
      [],
    );
    const plan = await kerberos.planResources({ principal, resource: { kind: 'document' }, action: 'view' });
    assert.throws(() => toCerbosQueryPlan(plan), /post-filter/);
  });
});

describe('@cerbos/orm-drizzle accepts Kerberos plans', () => {
  const documents = sqliteTable('documents', {
    id: text('id'),
    ownerId: text('owner_id'),
    status: text('status'),
    amount: integer('amount'),
  });
  const mapper = {
    'request.resource.attr.ownerId': documents.ownerId,
    'request.resource.attr.status': documents.status,
    'request.resource.attr.amount': documents.amount,
    'request.resource.id': documents.id,
  };
  const dialect = new SQLiteSyncDialect();

  it('translates a conditional plan into Drizzle SQL', async () => {
    const kerberos = buildEngine([
      {
        actions: ['view'],
        effect: 'EFFECT_ALLOW',
        roles: ['USER'],
        condition: { match: { $expr: 'R.attr.ownerId === P.id && R.attr.amount < 1000' } },
      },
    ]);
    const plan = await kerberos.planResources({ principal, resource: { kind: 'document' }, action: 'view' });
    const result = queryPlanToDrizzle({ queryPlan: toCerbosQueryPlan(plan), mapper });
    assert.equal(result.kind, PrismaPlanKind.CONDITIONAL);
    const query = dialect.sqlToQuery(result.filter);
    assert.match(query.sql, /"documents"\."owner_id" = \?/);
    assert.match(query.sql, /"documents"\."amount" < \?/);
    assert.deepEqual(query.params, ['u1', 1000]);
  });

  it('passes ALWAYS_ALLOWED through', async () => {
    const allowAll = buildEngine([{ actions: ['view'], effect: 'EFFECT_ALLOW', roles: ['USER'] }]);
    const plan = await allowAll.planResources({ principal, resource: { kind: 'document' }, action: 'view' });
    assert.equal(
      queryPlanToDrizzle({ queryPlan: toCerbosQueryPlan(plan), mapper }).kind,
      PrismaPlanKind.ALWAYS_ALLOWED,
    );
  });
});
