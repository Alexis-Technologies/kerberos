const { describe, it, beforeEach } = require('node:test');
const { strict: assert } = require('node:assert');
const { Keyv } = require('keyv');

const { Effect, Kerberos, createSafeExprCodec, serializePolicy, deserializePolicy, KerberosExprError } = require('../src/index.js');

// ---------------------------------------------------------------------------
// Shared jsep instance — configured once with all plugins for the test suite.
// In production code this is the caller's responsibility (analogous to ajv).
// ---------------------------------------------------------------------------
const jsepModule = require('jsep');
const jsep = jsepModule.default || jsepModule;
jsep.plugins.register(
  require('@jsep-plugin/object'),
  require('@jsep-plugin/ternary'),
  require('@jsep-plugin/new'),
);
jsep.addUnaryOp('typeof');

// A codec instance shared across tests.
const codec = createSafeExprCodec({ jsep });

// ---------------------------------------------------------------------------
// Dynamic policies expressed as JSON-safe { $expr } documents.
// ---------------------------------------------------------------------------
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

// Serialize with AST validation (jsep provided).
async function buildCache() {
  const keyv = new Keyv();
  await keyv.set('resource:document:default:', serializePolicy(dynamicResourcePolicy, { jsep }));
  await keyv.set('derivedRoles:doc_roles', serializePolicy(dynamicDerivedRoles, { jsep }));
  return keyv;
}

describe('Caching / Storing policies', () => {
  describe('resolving dynamic policies from cache (fallback layer)', () => {
    let kerberos;

    beforeEach(async () => {
      // No in-memory policies: everything must be resolved from the cache.
      // Pass codec.jsep so Kerberos uses the built-in AST evaluator.
      kerberos = new Kerberos([], [], { cache: await buildCache(), codec: { jsep } });
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
      const json = serializePolicy(dynamicResourcePolicy, { jsep });
      assert.strictEqual(JSON.parse(JSON.stringify(json)).resourcePolicy.resource, 'document');
      assert.deepStrictEqual(
        json.resourcePolicy.rules[1].derivedRoles,
        ['OWNER']
      );
    });

    it('serializes without jsep (structural check only, no AST validation)', () => {
      const json = serializePolicy(dynamicResourcePolicy);
      assert.strictEqual(json.resourcePolicy.resource, 'document');
    });

    it('deserializes { $expr } descriptors into callable evaluators', () => {
      const evaluate = codec.compileExpr('R.attr.ownerId == P.id');
      assert.strictEqual(evaluate({ R: { attr: { ownerId: 'u1' } }, P: { id: 'u1' } }), true);
      assert.strictEqual(evaluate({ R: { attr: { ownerId: 'u1' } }, P: { id: 'u2' } }), false);

      const shape = deserializePolicy(serializePolicy(dynamicDerivedRoles), codec);
      assert.strictEqual(typeof shape.definitions[0].condition.match, 'function');
    });

    it('throws when asked to serialize a raw JavaScript function', () => {
      assert.throws(
        () => serializePolicy({ condition: { match: ({ P }) => P.id === 'x' } }),
        KerberosExprError
      );
    });

    it('throws when a descriptor has a non-string $expr', () => {
      assert.throws(
        () => serializePolicy({ condition: { match: { $expr: 42 } } }),
        KerberosExprError
      );
      assert.throws(
        () => codec.deserialize({ condition: { match: { $expr: null } } }),
        KerberosExprError
      );
    });

    it('accepts a full codec object (createSafeExprCodec result) as codec option', async () => {
      // createSafeExprCodec returns an object with deserialize — Kerberos treats it
      // as codec.deserialize (custom path), which produces the same result.
      const fullCodec = createSafeExprCodec({ jsep });
      const kerberos = new Kerberos([], [], { cache: await buildCache(), codec: fullCodec });
      assert.strictEqual(await kerberos.isAllowed({ principal: owner, action: 'view', resource: openDoc }), true);
    });
  });

  describe('safe language builtins (Date, Math, parseInt, ...)', () => {
    it('supports new Date() and Date.now()', () => {
      const before = Date.now();
      const now = codec.compileExpr('Date.now()')({});
      const after = Date.now();
      assert.ok(now >= before && now <= after);
      assert.ok(codec.compileExpr('new Date()')({}) instanceof Date);
    });

    it('supports new Date(value) and Date instance methods', () => {
      const iso = '2024-06-01T12:00:00.000Z';
      const ctx = { R: { attr: { createdAt: iso } }, P: {}, V: {}, C: {} };
      const getTime = codec.compileExpr('new Date(R.attr.createdAt).getTime()')(ctx);
      assert.strictEqual(getTime, new Date(iso).getTime());
      assert.strictEqual(codec.compileExpr('new Date(R.attr.createdAt).toISOString()')(ctx), iso);
    });

    it('supports Date.parse and Date.UTC', () => {
      assert.strictEqual(codec.compileExpr('Date.parse("2024-01-01")')({}), Date.parse('2024-01-01'));
      assert.strictEqual(codec.compileExpr('Date.UTC(2024, 0, 1)')({}), Date.UTC(2024, 0, 1));
    });

    it('supports parseInt, parseFloat, Number, String and Boolean', () => {
      assert.strictEqual(codec.compileExpr('parseInt("42", 10)')({}), 42);
      assert.strictEqual(codec.compileExpr('parseFloat("3.14")')({}), 3.14);
      assert.strictEqual(codec.compileExpr('Number("7")')({}), 7);
      assert.strictEqual(codec.compileExpr('String(123)')({}), '123');
      assert.strictEqual(codec.compileExpr('Boolean(0)')({}), false);
      assert.strictEqual(codec.compileExpr('isNaN("x")')({}), true);
      assert.strictEqual(codec.compileExpr('isFinite(100)')({}), true);
    });

    it('evaluates a time-window condition equivalent to the expense delete rule', () => {
      const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000).toISOString();
      const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
      const expr = '(Date.now() - new Date(R.attr.createdAt).getTime()) < 3600000';
      const evaluate = codec.compileExpr(expr);

      assert.strictEqual(evaluate({ R: { attr: { createdAt: thirtyMinutesAgo } } }), true);
      assert.strictEqual(evaluate({ R: { attr: { createdAt: twoHoursAgo } } }), false);
    });

    it('resolves a cached policy that uses Date expressions', async () => {
      const recentCreatedAt = new Date(Date.now() - 30 * 60 * 1000).toISOString();
      const policy = {
        resourcePolicy: {
          version: 'default',
          resource: 'expense',
          rules: [
            {
              name: 'delete-within-hour',
              actions: ['delete'],
              effect: Effect.Allow,
              roles: ['USER'],
              condition: {
                match: { $expr: "(Date.now() - new Date(R.attr.createdAt).getTime()) < 3600000 && R.attr.status == 'OPEN'" },
              },
            },
          ],
        },
      };

      const keyv = new Keyv();
      await keyv.set('resource:expense:default:', serializePolicy(policy, { jsep }));
      const kerberos = new Kerberos([], [], { cache: keyv, codec: { jsep } });

      const resource = { id: 'e1', kind: 'expense', attr: { createdAt: recentCreatedAt, status: 'OPEN' } };
      assert.strictEqual(await kerberos.isAllowed({ principal: owner, action: 'delete', resource }), true);
    });

    it('rejects disallowed constructors and functions', () => {
      const ctx = { P: {}, R: { attr: {} }, V: {}, C: {} };
      assert.throws(() => codec.compileExpr('new Function("return process")()')(ctx), KerberosExprError);
      assert.throws(() => codec.compileExpr('new Object()')(ctx), KerberosExprError);
      assert.throws(() => codec.compileExpr('eval("1")')(ctx), KerberosExprError);
      assert.throws(() => codec.compileExpr('Date.constructor("return 1")()')(ctx), KerberosExprError);
    });
  });

  describe('security: AST allowlist rejects dangerous expressions', () => {
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
      'new Function("return process")()',
      'new Object()',
      'eval("1")',
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
      assert.throws(() => deserializePolicy(malicious, codec), KerberosExprError);
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

    it('uses cached values as-is when no codec is provided (no $expr deserialization)', async () => {
      // Plain JSON policies without $expr descriptors can be cached and restored
      // without any codec — Kerberos passes the raw value to the policy constructor.
      const policy = {
        resourcePolicy: {
          version: 'default',
          resource: 'plain',
          rules: [{ actions: ['read'], effect: Effect.Allow, roles: ['USER'] }],
        },
      };
      const keyv = new Keyv();
      await keyv.set('resource:plain:default:', policy);
      const kerberos = new Kerberos([], [], { cache: keyv }); // no codec
      const resource = { id: 'p1', kind: 'plain', attr: {} };
      assert.strictEqual(await kerberos.isAllowed({ principal: owner, action: 'read', resource }), true);
    });
  });

  describe('AST caching', () => {
    it('reuses the cached AST for repeated identical expressions', () => {
      const a = codec.compileExpr('R.attr.ownerId == P.id');
      const b = codec.compileExpr('R.attr.ownerId == P.id');
      const ctx = { R: { attr: { ownerId: 'u1' } }, P: { id: 'u1' } };
      assert.strictEqual(a(ctx), true);
      assert.strictEqual(b(ctx), true);
    });
  });
});
