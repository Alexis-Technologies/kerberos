const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { Effect, Kerberos } = require('../src/index.js');

// Cerbos compares resource KIND names after `namer.SanitizedResource`, on both
// sides of the comparison. Every expectation here was verified against a live
// Cerbos 0.55.0 PDP (see conformance/suites/kind_sanitize_test.yaml).

const principalPolicy = {
  principalPolicy: {
    principal: 'ryan',
    version: 'default',
    rules: [
      { resource: 'gl*', actions: [{ action: 'touch', effect: Effect.Allow }] },
      { resource: 'doc:*', actions: [{ action: 'view', effect: Effect.Allow }] },
      { resource: 'a-b', actions: [{ action: 'edit', effect: Effect.Allow }] },
      { resource: '1a:b', actions: [{ action: 'close', effect: Effect.Allow }] },
    ],
  },
};

const ryan = { id: 'ryan', roles: ['Z'] };

async function allowed(kerberos, principal, action, kind) {
  return kerberos.isAllowed({ principal, action, resource: { id: 'r0', kind } });
}

describe('resource kinds are matched the way Cerbos sanitizes them', () => {
  describe('principal-policy rules', () => {
    const kerberos = new Kerberos([principalPolicy]);

    const cases = [
      ['touch', 'gla:b', true],
      ['touch', 'gl:x', true],
      ['touch', 'glx', true],
      ['touch', 'gl', true],
      ['view', 'doc:x', false], // a pattern with `:` matches no sanitized kind
      ['view', 'doc_x', false],
      ['edit', 'a-b', true],
      ['edit', 'a_b', true],
      ['edit', 'a/b', true],
      ['edit', 'a@b', true],
      ['close', '1a:b', true], // outside the legacy name pattern: literal
      ['close', '1a_b', false],
    ];

    for (const [action, kind, expected] of cases) {
      it(`${action} on ${kind} → ${expected}`, async () => {
        assert.equal(await allowed(kerberos, ryan, action, kind), expected);
      });
    }
  });

  describe('role-policy rules', () => {
    // The resource policy grants RG both actions; the role policy narrows RG
    // to `touch` for every kind matching `gl*`.
    const kerberos = new Kerberos([
      {
        resourcePolicy: {
          version: 'default',
          resource: 'gla:b',
          rules: [{ actions: ['touch', 'view'], effect: Effect.Allow, roles: ['RG'] }],
        },
      },
      { rolePolicy: { role: 'RG', version: 'default', rules: [{ resource: 'gl*', allowActions: ['touch'] }] } },
    ]);
    const rg = { id: 'u1', roles: ['RG'] };

    it('narrows a kind the glob only reaches after sanitization', async () => {
      assert.equal(await allowed(kerberos, rg, 'touch', 'gla:b'), true);
      assert.equal(await allowed(kerberos, rg, 'view', 'gla:b'), false);
    });
  });

  describe('resource-policy lookup', () => {
    const kerberos = new Kerberos([
      {
        resourcePolicy: {
          version: 'default',
          resource: 'a-b',
          rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['*'] }],
        },
      },
    ]);
    const user = { id: 'u1', roles: ['USER'] };

    it('answers every spelling that sanitizes to the same kind', async () => {
      assert.equal(await allowed(kerberos, user, 'view', 'a-b'), true);
      assert.equal(await allowed(kerberos, user, 'view', 'a_b'), true);
      assert.equal(await allowed(kerberos, user, 'view', 'a/b'), true);
      assert.equal(await allowed(kerberos, user, 'view', 'ab'), false);
    });

    it('rejects two policies whose kinds collide after sanitization', () => {
      const build = () =>
        new Kerberos([
          {
            resourcePolicy: {
              version: 'default',
              resource: 'a-b',
              rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['*'] }],
            },
          },
          {
            resourcePolicy: {
              version: 'default',
              resource: 'a_b',
              rules: [{ actions: ['edit'], effect: Effect.Allow, roles: ['*'] }],
            },
          },
        ]);
      assert.throws(build, /Duplicate resource policy "a_b\.default\./);
    });
  });

  describe('query plans use the same matching', () => {
    const kerberos = new Kerberos([principalPolicy]);

    it('plans the principal rule for a kind reached through sanitization', async () => {
      const plan = await kerberos.planResources({ principal: ryan, action: 'touch', resource: { kind: 'gla:b' } });
      assert.equal(plan.filter.kind, 'KIND_ALWAYS_ALLOWED');

      const denied = await kerberos.planResources({ principal: ryan, action: 'view', resource: { kind: 'doc:x' } });
      assert.equal(denied.filter.kind, 'KIND_ALWAYS_DENIED');
    });
  });
});
