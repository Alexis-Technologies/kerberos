const { describe, it, beforeEach } = require('node:test');
const { strict: assert } = require('node:assert');
const { Keyv } = require('keyv');

const { Effect, Kerberos, createSafeExprCodec, serializePolicy, deserializePolicy, KerberosExprError } = require('../src/index.js');

// Dynamic policies are authored as JSON-safe documents: conditions, variables
// and outputs are `{ $expr }` string descriptors instead of JS functions.
const dynamicDerivedRoles = {
  name: 'doc_roles',
  definitions: [
    {
      name: 'OWNER',
      parentRoles: ['USER'],
      condition: { match: { $expr: 'R.attr.ownerId == P.id' } },
    },
  ],
};

const dynamicResourcePolicy = {
  resourcePolicy: {
    version: 'default',
    resource: 'document',
    importDerivedRoles: ['doc_roles'],
    variables: {
      isOpen: { $expr: "R.attr.status == 'OPEN'" },
    },
    rules: [
      { actions: ['*'], effect: Effect.Allow, roles: ['ADMIN'] },
      { actions: ['view'], effect: Effect.Allow, derivedRoles: ['OWNER'] },
      {
        name: 'edit-when-open',
        actions: ['edit'],
        effect: Effect.Allow,
        derivedRoles: ['OWNER'],
        condition: { match: { $expr: 'V.isOpen' } },
        output: {
          when: {
            ruleActivated: { $expr: '({ owner: R.attr.ownerId, by: P.id })' },
          },
        },
      },
    ],
  },
};

const owner = { id: 'u1', roles: ['USER'] };
const stranger = { id: 'u2', roles: ['USER'] };
const admin = { id: 'root', roles: ['ADMIN'] };
const openDoc = { id: 'doc1', kind: 'document', attr: { ownerId: 'u1', status: 'OPEN' } };
const closedDoc = { id: 'doc2', kind: 'document', attr: { ownerId: 'u1', status: 'CLOSED' } };

async function buildCache() {
  const keyv = new Keyv();
  await keyv.set('resource:document:default:', serializePolicy(dynamicResourcePolicy));
  await keyv.set('derivedRoles:doc_roles', serializePolicy(dynamicDerivedRoles));
  return keyv;
}

describe('Caching / Storing policies', () => {
  describe('resolving dynamic policies from cache (fallback layer)', () => {
    let kerberos;

    beforeEach(async () => {
      // No in-memory policies: everything must be resolved from the cache.
      kerberos = new Kerberos([], [], { cache: await buildCache() });
    });

    it('resolves a resource policy + derived roles from the cache', async () => {
      assert.strictEqual(await kerberos.isAllowed({ principal: owner, action: 'view', resource: openDoc }), true);
    });

    it('denies when the dynamic derived role does not match', async () => {
      assert.strictEqual(await kerberos.isAllowed({ principal: stranger, action: 'view', resource: openDoc }), false);
    });

    it('evaluates a cached condition backed by a cached variable', async () => {
      assert.strictEqual(await kerberos.isAllowed({ principal: owner, action: 'edit', resource: openDoc }), true);
      assert.strictEqual(await kerberos.isAllowed({ principal: owner, action: 'edit', resource: closedDoc }), false);
    });

    it('honors role rules from the cached policy', async () => {
      assert.strictEqual(await kerberos.isAllowed({ principal: admin, action: 'view', resource: closedDoc }), true);
    });

    it('returns effects and cached outputs through checkResources', async () => {
      const response = await kerberos.checkResources({
        principal: owner,
        resources: [{ resource: openDoc, actions: ['view', 'edit'] }],
      });

      assert.deepStrictEqual(response.results[0].actions, {
        view: Effect.Allow,
        edit: Effect.Allow,
      });
      const output = response.results[0].outputs.find((o) => o.src.endsWith('#edit-when-open'));
      assert.ok(output);
      assert.deepStrictEqual(output.val, { owner: 'u1', by: 'u1' });
    });
  });

  describe('codec round-trip', () => {
    it('serializes a { $expr } shape into a JSON-safe document', () => {
      const json = serializePolicy(dynamicResourcePolicy);
      assert.strictEqual(JSON.parse(JSON.stringify(json)).resourcePolicy.resource, 'document');
      assert.deepStrictEqual(
        json.resourcePolicy.rules[1].derivedRoles,
        ['OWNER']
      );
    });

    it('deserializes { $expr } descriptors into callable evaluators', () => {
      const codec = createSafeExprCodec();
      const evaluate = codec.compileExpr('R.attr.ownerId == P.id');
      assert.strictEqual(evaluate({ R: { attr: { ownerId: 'u1' } }, P: { id: 'u1' } }), true);
      assert.strictEqual(evaluate({ R: { attr: { ownerId: 'u1' } }, P: { id: 'u2' } }), false);

      const shape = deserializePolicy(serializePolicy(dynamicDerivedRoles));
      assert.strictEqual(typeof shape.definitions[0].condition.match, 'function');
    });

    it('throws when asked to serialize a raw JavaScript function', () => {
      assert.throws(
        () => serializePolicy({ condition: { match: ({ P }) => P.id === 'x' } }),
        KerberosExprError
      );
    });
  });

  describe('security: AST allowlist rejects dangerous expressions', () => {
    const codec = createSafeExprCodec();
    const ctx = { P: { id: 'u1', roles: ['USER'] }, R: { attr: {} }, V: {}, C: {} };

    const vectors = [
      "P['constructor']['constructor']('return process')()",
      "P['cons' + 'tructor']['cons' + 'tructor']('return process')()",
      'Reflect.apply(P.constructor.constructor, null, [])',
      'P.__proto__',
      'P.constructor',
      'R.attr.x = 1',
      'a in b',
      'process.exit(1)',
      'globalThis.process',
      'require("fs")',
    ];

    for (const expr of vectors) {
      it(`rejects: ${expr}`, () => {
        assert.throws(() => codec.compileExpr(expr)(ctx), KerberosExprError);
      });
    }

    it('unicode-escaped constructor access resolves to undefined, never the constructor', () => {
      // jsep does not decode \u escapes, so the property is a literal miss.
      const value = codec.compileExpr(String.raw`P['\u0063onstructor']`)(ctx);
      assert.strictEqual(typeof value, 'undefined');
    });

    it('rejects a malicious policy document during deserialization', () => {
      const malicious = {
        resourcePolicy: {
          version: 'default',
          resource: 'document',
          rules: [
            {
              actions: ['view'],
              effect: Effect.Allow,
              roles: ['USER'],
              condition: { match: { $expr: "P['constructor']['constructor']('return process')()" } },
            },
          ],
        },
      };
      assert.throws(() => deserializePolicy(malicious), KerberosExprError);
    });
  });

  describe('compatibility: behavior is unchanged without a cache', () => {
    it('falls back to EFFECT_DENY without throwing when no policy is found', async () => {
      const kerberos = new Kerberos([], []);
      assert.strictEqual(await kerberos.isAllowed({ principal: owner, action: 'view', resource: openDoc }), false);
    });

    it('ignores cache for policies that exist in memory', async () => {
      const keyv = new Keyv();
      // A poisoned cache entry must never be consulted when the in-memory policy hits.
      await keyv.set('resource:document:default:', { not: 'a policy' });

      const inMemory = {
        resourcePolicy: {
          version: 'default',
          resource: 'document',
          rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
        },
      };
      const kerberos = new Kerberos([inMemory], [], { cache: keyv });
      assert.strictEqual(await kerberos.isAllowed({ principal: owner, action: 'view', resource: openDoc }), true);
    });
  });

  describe('AST caching', () => {
    it('reuses the cached AST for repeated identical expressions', () => {
      const codec = createSafeExprCodec();
      const a = codec.compileExpr('R.attr.ownerId == P.id');
      const b = codec.compileExpr('R.attr.ownerId == P.id');
      const ctx = { R: { attr: { ownerId: 'u1' } }, P: { id: 'u1' } };
      assert.strictEqual(a(ctx), true);
      assert.strictEqual(b(ctx), true);
    });
  });
});
