const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const { Kerberos, Effect, KerberosCacheError, KerberosValidationError } = require('../src/index.js');
const { createCacheReader } = require('../src/caching/cache.js');

const policies = [
  {
    resourcePolicy: {
      version: 'default',
      resource: 'expense',
      rules: [{ name: 'user-view', actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
    },
  },
];

const principal = { id: 'sally', roles: ['USER'] };
const resource = { id: 'expense1', kind: 'expense' };

describe('Resilience', () => {
  describe('throwing logger never affects decisions', () => {
    it('should return the computed ALLOW even when logger.write throws', async () => {
      const throwingLogger = {
        info() {
          throw new Error('logger boom');
        },
        debug() {
          throw new Error('logger boom');
        },
        error() {
          throw new Error('logger boom');
        },
      };
      const kerberos = new Kerberos(policies, [], { logger: throwingLogger });

      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);

      const response = await kerberos.checkResources({ principal, resources: [{ resource, actions: ['view'] }] });
      assert.equal(response.results[0].actions.view, 'EFFECT_ALLOW');
    });

    it('should survive a logger that throws only in finally (finish log)', async () => {
      let calls = 0;
      const finishThrowingLogger = {
        info() {},
        error() {},
        debug() {
          calls += 1;
          // First debug is the start event, second is finish (inside finally).
          if (calls >= 2) throw new Error('finish boom');
        },
      };
      const kerberos = new Kerberos(policies, [], { logger: finishThrowingLogger });

      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
    });
  });

  describe('onError semantics', () => {
    const throwingConditionPolicies = [
      {
        resourcePolicy: {
          version: 'default',
          resource: 'expense',
          rules: [
            {
              actions: ['view'],
              effect: Effect.Allow,
              roles: ['USER'],
              condition: {
                match: () => {
                  throw new Error('evaluation boom');
                },
              },
            },
          ],
        },
      },
    ];

    it("should rethrow evaluation errors with the default onError: 'throw' even with a logger", async () => {
      const silentLogger = { info() {}, debug() {}, error() {} };
      const kerberos = new Kerberos(throwingConditionPolicies, [], { logger: silentLogger });

      await assert.rejects(() => kerberos.isAllowed({ principal, action: 'view', resource }), /evaluation boom/);
    });

    it("should return fallback results with onError: 'deny'", async () => {
      const kerberos = new Kerberos(throwingConditionPolicies, [], { onError: 'deny' });

      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), false);
    });

    it('should isolate per-resource evaluation failures as fail-closed DENY results', async () => {
      // Regardless of onError, a failing resource never takes down the batch:
      // it yields DENY for all its actions while other resources evaluate.
      const kerberos = new Kerberos(throwingConditionPolicies, []);

      const response = await kerberos.checkResources({
        principal,
        resources: [
          { resource, actions: ['view'] },
          { resource: { id: 'other1', kind: 'other' }, actions: ['view'] },
        ],
      });

      assert.equal(response.results.length, 2);
      assert.equal(response.results[0].actions.view, 'EFFECT_DENY');
      assert.deepEqual(response.results[0].outputs, []);
      // The unrelated resource still evaluated normally (no policy → DENY).
      assert.equal(response.results[1].actions.view, 'EFFECT_DENY');
      assert.ok(response.kerberosCallId);
    });

    it('should mark error-shaped batch denials with the evaluation-error reason under includeMeta', async () => {
      const kerberos = new Kerberos(throwingConditionPolicies, []);

      const response = await kerberos.checkResources({
        principal,
        resources: [
          { resource, actions: ['view'] },
          { resource: { id: 'other1', kind: 'other' }, actions: ['view'] },
        ],
        includeMeta: true,
      });

      // The failed resource's DENY is distinguishable from a policy DENY.
      const failedMeta = response.results[0].meta.actions.view;
      assert.equal(failedMeta.reason, 'evaluation-error');
      assert.equal(typeof failedMeta.errorName, 'string');
      // The normally-evaluated resource carries the usual policy-miss reason.
      assert.equal(response.results[1].meta.actions.view.reason, 'policy-miss');
    });

    it("should always throw KerberosValidationError for malformed arguments, even with onError: 'deny'", async () => {
      const { z } = require('zod');
      const kerberos = new Kerberos(policies, [], { onError: 'deny', z });

      await assert.rejects(() => kerberos.isAllowed({ principal, resource }), { name: 'KerberosValidationError' });
      await assert.rejects(() => kerberos.checkResources({ principal }), { name: 'KerberosValidationError' });
    });

    it('should reject invalid onError values at construction', () => {
      assert.throws(() => new Kerberos(policies, [], { onError: 'swallow' }), /Invalid onError option/);
    });
  });

  describe('cache retry', () => {
    it('should retry transient failures and succeed within the attempt budget', async () => {
      let resourceKeyCalls = 0;
      const flakyCache = {
        async get(key) {
          // Only the resource-policy key is flaky; principal/role lookups miss.
          if (key !== 'resource:document:default:') return undefined;
          resourceKeyCalls += 1;
          if (resourceKeyCalls < 3) throw new Error('ECONNRESET');
          return {
            resourcePolicy: {
              version: 'default',
              resource: 'document',
              rules: [{ actions: ['view'], effect: 'EFFECT_ALLOW', roles: ['USER'] }],
            },
          };
        },
      };
      const kerberos = new Kerberos([], [], { cache: flakyCache });

      const allowed = await kerberos.isAllowed({
        principal,
        action: 'view',
        resource: { id: 'doc1', kind: 'document' },
      });
      assert.equal(allowed, true);
      assert.equal(resourceKeyCalls, 3);
    });

    it('should surface KerberosCacheError after exhausting attempts', async () => {
      let calls = 0;
      const deadCache = {
        async get() {
          calls += 1;
          throw new Error('ETIMEDOUT');
        },
      };
      const reader = createCacheReader(deadCache, { attempts: 2 });

      await assert.rejects(
        () => reader.get('resource:x:default:'),
        (error) => {
          assert.ok(error instanceof KerberosCacheError);
          assert.match(error.message, /after 2 attempt/);
          assert.match(error.cause.message, /ETIMEDOUT/);
          return true;
        },
      );
      assert.equal(calls, 2);
    });

    it('should propagate cache errors per onError semantics from public methods', async () => {
      const deadCache = {
        async get() {
          throw new Error('ETIMEDOUT');
        },
      };

      const throwing = new Kerberos([], [], { cache: deadCache, cacheRetry: { attempts: 1 } });
      await assert.rejects(() => throwing.isAllowed({ principal, action: 'view', resource }), {
        name: 'KerberosCacheError',
      });

      const denying = new Kerberos([], [], { cache: deadCache, cacheRetry: { attempts: 1 }, onError: 'deny' });
      assert.equal(await denying.isAllowed({ principal, action: 'view', resource }), false);
    });

    it('should treat a corrupt cache entry as a miss instead of failing the request', async () => {
      const corruptCache = {
        async get(key) {
          if (key.startsWith('resource:')) return '{not-json';
          return undefined;
        },
      };
      const failingCodec = {
        deserialize() {
          throw new Error('corrupt entry');
        },
      };
      const kerberos = new Kerberos([], [], { cache: corruptCache, codec: failingCodec });

      // No throw despite default onError: 'throw' — a corrupt entry is
      // deterministic (retrying cannot help), so it resolves as a miss → DENY.
      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), false);
    });

    it('should return undefined from the disabled cache reader', async () => {
      const reader = createCacheReader(null);
      assert.equal(reader.enabled, false);
      assert.equal(await reader.get('any'), undefined);

      const noGet = createCacheReader({});
      assert.equal(noGet.enabled, false);
    });
  });

  describe('cache retry backoff and deterministic errors', () => {
    it('should not retry deterministic adapter errors (TypeError/SyntaxError)', async () => {
      let calls = 0;
      const buggyCache = {
        async get() {
          calls += 1;
          throw new TypeError('cache.get is not a function on adapter');
        },
      };
      const reader = createCacheReader(buggyCache, { attempts: 3, delayMs: 0 });

      await assert.rejects(
        () => reader.get('resource:x:default:'),
        (error) => error instanceof KerberosCacheError && error.cause instanceof TypeError,
      );
      // A programming error cannot be transient — exactly one attempt is made.
      assert.equal(calls, 1);
    });

    it('should space retries with backoff by default and allow delayMs: 0 for immediate retries', async () => {
      const failTwice = () => {
        let calls = 0;
        return {
          async get() {
            calls += 1;
            if (calls < 3) throw new Error('ECONNRESET');
            return undefined;
          },
        };
      };

      // delayMs: 0 → immediate retries (the pre-backoff behavior).
      const immediate = createCacheReader(failTwice(), { attempts: 3, delayMs: 0 });
      const startImmediate = Date.now();
      assert.equal(await immediate.get('k'), undefined);
      assert.ok(Date.now() - startImmediate < 20);

      // Default: full-jitter exponential backoff — attempts are spaced, and
      // with jitter: false the delays are exact (25 + 50 = 75ms here).
      const spaced = createCacheReader(failTwice(), { attempts: 3, jitter: false });
      const startSpaced = Date.now();
      assert.equal(await spaced.get('k'), undefined);
      assert.ok(Date.now() - startSpaced >= 70);
    });

    it('should bound a hung cache.get with timeoutMs and surface KerberosCacheError', async () => {
      const hungCache = {
        get() {
          return new Promise(() => {});
        },
      };
      const reader = createCacheReader(hungCache, { attempts: 1, timeoutMs: 40 });

      const start = Date.now();
      await assert.rejects(
        () => reader.get('resource:x:default:'),
        (error) => error instanceof KerberosCacheError && /timed out after 40ms/.test(error.message),
      );
      assert.ok(Date.now() - start < 500);
    });
  });

  describe("cacheRetry.onExhausted: 'miss' (degraded mode)", () => {
    const deadCache = {
      async get() {
        throw new Error('ECONNRESET');
      },
    };

    it('should keep evaluating static policies when the cache backend is down', async () => {
      const kerberos = new Kerberos(policies, [], {
        cache: deadCache,
        cacheRetry: { attempts: 1, onExhausted: 'miss' },
      });

      // Static resource policy decides although every cache read fails.
      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
      assert.equal(await kerberos.isAllowed({ principal, action: 'delete', resource }), false);
    });

    it("should keep the default fail-closed 'throw' semantics without the option", async () => {
      const kerberos = new Kerberos(policies, [], { cache: deadCache, cacheRetry: { attempts: 1 } });
      await assert.rejects(() => kerberos.isAllowed({ principal, action: 'view', resource }), {
        name: 'KerberosCacheError',
      });
    });

    it('should reject invalid onExhausted values at construction', () => {
      assert.throws(
        () => new Kerberos(policies, [], { cache: deadCache, cacheRetry: { onExhausted: 'ignore' } }),
        TypeError,
      );
    });
  });

  describe('cacheKeyPrefix', () => {
    it('should prepend the prefix to every policy and derived-roles cache key', async () => {
      const reads = [];
      const cache = {
        async get(key) {
          reads.push(key);
          return undefined;
        },
      };
      const withDerived = [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'expense',
            importDerivedRoles: ['dr_missing'],
            rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
          },
        },
      ];
      const kerberos = new Kerberos(withDerived, [], {
        cache,
        cacheRetry: { attempts: 1 },
        cacheKeyPrefix: 'tenantA:',
      });

      await kerberos.isAllowed({ principal, action: 'view', resource });
      assert.ok(reads.length > 0);
      for (const key of reads) assert.match(key, /^tenantA:/);
      assert.ok(reads.includes('tenantA:derivedRoles:dr_missing'));
    });

    it('should reject a non-string cacheKeyPrefix at construction', () => {
      assert.throws(() => new Kerberos(policies, [], { cacheKeyPrefix: 42 }), TypeError);
    });
  });

  describe('relationsTimeoutMs', () => {
    const relationPolicies = [
      {
        resourcePolicy: {
          version: 'default',
          resource: 'expense',
          importDerivedRoles: ['rel_roles'],
          rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['REL'] }],
        },
      },
    ];
    const relationDerivedRoles = [{ name: 'rel_roles', definitions: [{ name: 'REL', relation: 'viewer' }] }];
    const hungResolver = {
      check() {
        return new Promise(() => {});
      },
    };

    it('should bound a hung relations.check and follow onError semantics', async () => {
      const { KerberosRelationsError } = require('../src/index.js');
      const throwing = new Kerberos(relationPolicies, relationDerivedRoles, {
        relations: hungResolver,
        relationsTimeoutMs: 40,
      });
      await assert.rejects(
        () => throwing.isAllowed({ principal, action: 'view', resource }),
        (error) => error instanceof KerberosRelationsError && /timed out after 40ms/.test(error.message),
      );

      const denying = new Kerberos(relationPolicies, relationDerivedRoles, {
        relations: hungResolver,
        relationsTimeoutMs: 40,
        onError: 'deny',
      });
      assert.equal(await denying.isAllowed({ principal, action: 'view', resource }), false);
    });

    it('should bound a hung relations.list too', async () => {
      const { KerberosRelationsError } = require('../src/index.js');
      const hungListResolver = {
        check: async () => false,
        list() {
          return new Promise(() => {});
        },
      };
      const kerberos = new Kerberos(relationPolicies, relationDerivedRoles, {
        relations: hungListResolver,
        relationsTimeoutMs: 40,
      });
      await assert.rejects(
        () => kerberos.isAllowed({ principal, action: 'view', resource }),
        (error) => error instanceof KerberosRelationsError && /relations\.list timed out/.test(error.message),
      );
    });

    it('should reject invalid relationsTimeoutMs values at construction', () => {
      assert.throws(() => new Kerberos(policies, [], { relationsTimeoutMs: -1 }), TypeError);
      assert.throws(() => new Kerberos(policies, [], { relationsTimeoutMs: 'fast' }), TypeError);
    });
  });

  describe('duplicate policies', () => {
    it('should throw on duplicate resource policy keys', () => {
      assert.throws(() => new Kerberos([...policies, ...policies], []), /Duplicate resource policy/);
    });

    it('should throw on duplicate principal policy keys', () => {
      const principalPolicy = {
        principalPolicy: {
          principal: 'sally',
          version: 'default',
          rules: [{ resource: 'expense', actions: [{ action: 'view', effect: Effect.Allow }] }],
        },
      };
      assert.throws(() => new Kerberos([principalPolicy, principalPolicy], []), /Duplicate principal policy/);
    });

    it('should throw on duplicate role policy keys', () => {
      const rolePolicy = {
        rolePolicy: {
          role: 'USER',
          version: 'default',
          rules: [{ resource: 'expense', allowActions: ['view'] }],
        },
      };
      assert.throws(() => new Kerberos([rolePolicy, rolePolicy], []), /Duplicate role policy/);
    });

    it('should throw on duplicate derived roles definitions', () => {
      const derived = {
        name: 'common_roles',
        definitions: [{ name: 'OWNER', parentRoles: ['USER'], condition: { match: () => true } }],
      };
      assert.throws(() => new Kerberos(policies, [derived, derived]), /Duplicate derived roles definition/);
    });
  });

  describe('circular role policy inheritance', () => {
    it('should throw a clear error for parentRoles cycles', async () => {
      const roleA = {
        rolePolicy: {
          role: 'A',
          version: 'default',
          parentRoles: ['B'],
          rules: [{ resource: 'expense', allowActions: ['view'] }],
        },
      };
      const roleB = {
        rolePolicy: {
          role: 'B',
          version: 'default',
          parentRoles: ['A'],
          rules: [{ resource: 'expense', allowActions: ['view'] }],
        },
      };
      const kerberos = new Kerberos([roleA, roleB], []);

      await assert.rejects(
        () => kerberos.isAllowed({ principal: { id: 'u1', roles: ['A'] }, action: 'view', resource }),
        /Circular role policy inheritance/,
      );
    });
  });

  describe('typed error exports', () => {
    it('should export the typed error classes', () => {
      assert.equal(typeof KerberosCacheError, 'function');
      assert.equal(typeof KerberosValidationError, 'function');
      const { KerberosCodecError } = require('../src/index.js');
      assert.equal(typeof KerberosCodecError, 'function');
    });
  });
});
