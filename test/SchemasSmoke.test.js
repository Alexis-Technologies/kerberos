const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const {
  Effect,
  Kerberos,
  MetadataJsonSchemas,
  MetadataTypeBoxSchemas,
  MetadataZodSchemas,
} = require('../src/index.js');

// Smoke coverage for the three validation backends across every DSL module:
// the same canonical policy set must construct (i.e. every schema builder must
// accept its canonical shape) and evaluate identically under Zod, plain JSON
// Schema + Ajv, and TypeBox + Ajv.

const policies = [
  {
    resourcePolicy: {
      version: 'default',
      resource: 'expense',
      importDerivedRoles: ['smoke_roles'],
      constants: { limit: 1000 },
      variables: { isOpen: ({ R }) => R.attr.status === 'OPEN' },
      rules: [
        {
          name: 'owner-edit',
          actions: ['edit'],
          effect: Effect.Allow,
          derivedRoles: ['OWNER'],
          condition: { match: ({ V, C, R }) => V.isOpen && R.attr.amount < C.limit },
          output: { when: { ruleActivated: ({ P }) => ({ editor: P.id }) } },
        },
        { actions: ['view'], effect: Effect.Allow, roles: ['USER'] },
      ],
    },
  },
  {
    principalPolicy: {
      principal: 'root',
      version: 'default',
      rules: [{ resource: 'expense', actions: [{ action: '*', effect: Effect.Allow }] }],
    },
  },
  {
    rolePolicy: {
      role: 'AUDITOR',
      version: 'default',
      rules: [{ resource: 'expense', allowActions: ['view'] }],
    },
  },
];

const derivedRoles = [
  {
    name: 'smoke_roles',
    definitions: [
      { name: 'OWNER', parentRoles: ['USER'], condition: { match: ({ P, R }) => R.attr.ownerId === P.id } },
      { name: 'REL_BACKED', relation: 'view' },
    ],
  },
];

const principal = { id: 'sally', roles: ['USER'] };
const resource = { id: 'e1', kind: 'expense', attr: { ownerId: 'sally', status: 'OPEN', amount: 100 } };

function buildBackends() {
  const { z } = require('zod');
  const Ajv = require('ajv');
  const t = require('@sinclair/typebox').Type;
  return [
    ['zod', { z }],
    ['json-schema + ajv', { ajv: new Ajv({ allowUnionTypes: true }) }],
    ['typebox + ajv', { ajv: new Ajv({ allowUnionTypes: true }), typebox: t }],
  ];
}

describe('schema builders smoke (all three backends)', () => {
  for (const [label, options] of buildBackends()) {
    it(`constructs and evaluates the canonical policy set with ${label}`, async () => {
      const kerberos = new Kerberos(policies, derivedRoles, options);

      assert.equal(await kerberos.isAllowed({ principal, action: 'edit', resource }), true);
      assert.equal(
        await kerberos.isAllowed({ principal: { id: 'root', roles: ['ADMIN'] }, action: 'delete', resource }),
        true,
      );
      assert.equal(
        await kerberos.isAllowed({ principal: { id: 'a1', roles: ['AUDITOR'] }, action: 'view', resource }),
        true,
      );
      assert.equal(await kerberos.isAllowed({ principal, action: 'delete', resource }), false);
    });
  }

  it('builds Metadata schemas across all three backends', () => {
    const { z } = require('zod');
    const t = require('@sinclair/typebox').Type;

    assert.ok(MetadataZodSchemas.buildActionMetadata(z));
    assert.ok(MetadataZodSchemas.buildActionsMetadata(z));
    assert.ok(MetadataZodSchemas.buildShape(z));
    assert.ok(MetadataJsonSchemas.buildActionMetadata());
    assert.ok(MetadataJsonSchemas.buildActionsMetadata());
    assert.ok(MetadataJsonSchemas.buildShape());
    assert.ok(MetadataTypeBoxSchemas.buildActionMetadata(t));
    assert.ok(MetadataTypeBoxSchemas.buildActionsMetadata(t));
    assert.ok(MetadataTypeBoxSchemas.buildShape(t));
  });

  it("accepts the engine's real includeMeta output across all three backends (round-trip)", async () => {
    // The drift guard the pure-existence checks above cannot provide: the
    // exported Metadata schemas must accept what checkResources actually
    // returns — including 'policy-miss' entries that carry NO matchedPolicy,
    // deny reasons, and the resolution trace.
    const { z } = require('zod');
    const Ajv = require('ajv');
    const t = require('@sinclair/typebox').Type;

    const kerberos = new Kerberos(policies, derivedRoles, { getCallId: () => 'call-smoke' });
    const { results } = await kerberos.checkResources({
      principal,
      resources: [
        // Allowed action with matchedPolicy/matchedRule + denied 'rule-miss'.
        { resource, actions: ['edit', 'transfer'] },
        // Unknown kind: every action denies with reason 'policy-miss'.
        { resource: { id: 'x1', kind: 'unknown-kind' }, actions: ['view'] },
      ],
      includeMeta: true,
    });

    const metas = results.map((result) => result.meta);
    assert.equal(metas.length, 2);
    assert.equal(metas[1].actions.view.reason, 'policy-miss');
    assert.equal('matchedPolicy' in metas[1].actions.view, false);
    assert.ok(Array.isArray(metas[0].resolution));

    const zodShape = MetadataZodSchemas.buildShape(z);
    const validateJson = new Ajv({ allowUnionTypes: true }).compile(MetadataJsonSchemas.buildShape());
    const validateTypeBox = new Ajv({ allowUnionTypes: true }).compile(MetadataTypeBoxSchemas.buildShape(t));

    for (const meta of metas) {
      assert.doesNotThrow(() => zodShape.parse(meta));
      assert.equal(validateJson(meta), true, JSON.stringify(validateJson.errors));
      assert.equal(validateTypeBox(meta), true, JSON.stringify(validateTypeBox.errors));
    }
  });
});
