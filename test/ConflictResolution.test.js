const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { Effect, Kerberos } = require('../src/index.js');

/**
 * Resource-policy conflict resolution: deny overrides allow WITHIN a principal
 * role, allow overrides deny ACROSS roles (Cerbos >= 0.41 semantics).
 *
 * The cross-role case is invisible to any single-role fixture, which is exactly
 * how it stayed wrong for so long — every test here that involves two roles is
 * load-bearing. `conformance/suites/ticket_test.yaml` pins the same shapes
 * against a real Cerbos PDP.
 */

const RULES = [
  { name: 'support-allow', actions: ['close'], effect: Effect.Allow, roles: ['SUPPORT'] },
  { name: 'auditor-deny', actions: ['close'], effect: Effect.Deny, roles: ['AUDITOR'] },
];

function engine(rules, { derivedRoles = [], ...options } = {}) {
  const resourcePolicy = { version: 'default', resource: 'ticket', rules };
  if (derivedRoles.length) resourcePolicy.importDerivedRoles = derivedRoles.map((set) => set.name);
  return new Kerberos([{ resourcePolicy }], derivedRoles, options);
}

async function decide(kerberos, roles, action = 'close', attr = {}) {
  const { results } = await kerberos.checkResources({
    principal: { id: 'p1', roles },
    resources: [{ resource: { kind: 'ticket', id: 't1', attr }, actions: [action] }],
  });
  return results[0].actions[action];
}

describe('resource policy conflict resolution', () => {
  describe('across roles — allow wins (anti-lockout)', () => {
    it('a DENY scoped to another role does not veto the allowing role', async () => {
      assert.equal(await decide(engine(RULES), ['SUPPORT', 'AUDITOR']), Effect.Allow);
    });

    it('is independent of rule order', async () => {
      const reversed = [RULES[1], RULES[0]];
      assert.equal(await decide(engine(reversed), ['SUPPORT', 'AUDITOR']), Effect.Allow);
    });

    it('is independent of the order the principal lists its roles', async () => {
      assert.equal(await decide(engine(RULES), ['AUDITOR', 'SUPPORT']), Effect.Allow);
    });

    it('still denies when only the denying role is held', async () => {
      assert.equal(await decide(engine(RULES), ['AUDITOR']), Effect.Deny);
    });

    it('still allows when only the allowing role is held', async () => {
      assert.equal(await decide(engine(RULES), ['SUPPORT']), Effect.Allow);
    });

    it('names the surviving ALLOW rule in the decision trace', async () => {
      const kerberos = engine(RULES);
      const { results } = await kerberos.checkResources({
        principal: { id: 'p1', roles: ['SUPPORT', 'AUDITOR'] },
        resources: [{ resource: { kind: 'ticket', id: 't1' }, actions: ['close'] }],
        includeMeta: true,
      });
      assert.equal(results[0].meta.actions.close.matchedRule, 'resource.ticket.vdefault#support-allow');
    });
  });

  describe('within a role — deny wins', () => {
    it('denies when both rules target the same role', async () => {
      const rules = [
        { actions: ['close'], effect: Effect.Allow, roles: ['SUPPORT'] },
        { actions: ['close'], effect: Effect.Deny, roles: ['SUPPORT'] },
      ];
      assert.equal(await decide(engine(rules), ['SUPPORT']), Effect.Deny);
    });

    it('denies when the ALLOW is listed after the DENY', async () => {
      const rules = [
        { actions: ['close'], effect: Effect.Deny, roles: ['SUPPORT'] },
        { actions: ['close'], effect: Effect.Allow, roles: ['SUPPORT'] },
      ];
      assert.equal(await decide(engine(rules), ['SUPPORT']), Effect.Deny);
    });

    it('a conditional DENY only bites when its condition holds', async () => {
      const rules = [
        { actions: ['close'], effect: Effect.Allow, roles: ['SUPPORT'] },
        {
          actions: ['close'],
          effect: Effect.Deny,
          roles: ['SUPPORT'],
          condition: { match: ({ R }) => R.attr.locked === true },
        },
      ];
      const kerberos = engine(rules);
      assert.equal(await decide(kerberos, ['SUPPORT'], 'close', { locked: true }), Effect.Deny);
      assert.equal(await decide(kerberos, ['SUPPORT'], 'close', { locked: false }), Effect.Allow);
    });
  });

  describe('denies that reach every role still win', () => {
    it('a wildcard DENY covers the allowing role', async () => {
      const rules = [
        { actions: ['close'], effect: Effect.Allow, roles: ['SUPPORT'] },
        { actions: ['close'], effect: Effect.Deny, roles: ['*'] },
      ];
      assert.equal(await decide(engine(rules), ['SUPPORT', 'AUDITOR']), Effect.Deny);
      assert.equal(await decide(engine(rules), ['SUPPORT']), Effect.Deny);
    });

    it('a DENY that also enumerates the allowing role covers it', async () => {
      const rules = [
        { actions: ['close'], effect: Effect.Allow, roles: ['SUPPORT'] },
        { actions: ['close'], effect: Effect.Deny, roles: ['SUPPORT', 'AUDITOR'] },
      ];
      assert.equal(await decide(engine(rules), ['SUPPORT', 'AUDITOR']), Effect.Deny);
    });

    it('a wildcard ALLOW is carried by every role the principal holds', async () => {
      const rules = [
        { actions: ['close'], effect: Effect.Allow, roles: ['*'] },
        { actions: ['close'], effect: Effect.Deny, roles: ['AUDITOR'] },
      ];
      // SUPPORT carries the wildcard allow and is not denied.
      assert.equal(await decide(engine(rules), ['SUPPORT', 'AUDITOR']), Effect.Allow);
      // With AUDITOR alone the only role carrying the allow is also denied.
      assert.equal(await decide(engine(rules), ['AUDITOR']), Effect.Deny);
    });
  });

  describe('derived roles collapse into the role that activated them', () => {
    const derivedRoles = [
      {
        name: 'ticket_roles',
        definitions: [
          { name: 'OWNER', parentRoles: ['SUPPORT'], condition: { match: ({ P, R }) => R.attr.ownerId === P.id } },
          { name: 'REVIEWER', parentRoles: ['AUDITOR'], condition: { match: () => true } },
        ],
      },
    ];
    const rules = [
      { actions: ['close'], effect: Effect.Allow, derivedRoles: ['OWNER'] },
      { actions: ['close'], effect: Effect.Deny, derivedRoles: ['REVIEWER'] },
    ];

    it('a DENY via a derived role bound to another parent role does not veto', async () => {
      const kerberos = engine(rules, { derivedRoles });
      assert.equal(await decide(kerberos, ['SUPPORT', 'AUDITOR'], 'close', { ownerId: 'p1' }), Effect.Allow);
    });

    it('denies once the denying derived role shares the allowing parent role', async () => {
      const shared = [
        {
          name: 'ticket_roles',
          definitions: [
            { name: 'OWNER', parentRoles: ['SUPPORT'], condition: { match: ({ P, R }) => R.attr.ownerId === P.id } },
            { name: 'REVIEWER', parentRoles: ['SUPPORT', 'AUDITOR'], condition: { match: () => true } },
          ],
        },
      ];
      const kerberos = engine(rules, { derivedRoles: shared });
      assert.equal(await decide(kerberos, ['SUPPORT', 'AUDITOR'], 'close', { ownerId: 'p1' }), Effect.Deny);
    });

    it('a role-scoped DENY does not veto an allow carried by a derived role', async () => {
      const mixed = [
        { actions: ['close'], effect: Effect.Allow, derivedRoles: ['OWNER'] },
        { actions: ['close'], effect: Effect.Deny, roles: ['AUDITOR'] },
      ];
      const kerberos = engine(mixed, { derivedRoles });
      assert.equal(await decide(kerberos, ['SUPPORT', 'AUDITOR'], 'close', { ownerId: 'p1' }), Effect.Allow);
    });
  });

  describe('both evaluation drivers agree', () => {
    // The engine uses a synchronous driver when neither a cache nor a relations
    // resolver is configured, and an async one otherwise. Conflict resolution
    // lives in ResourcePolicy and is shared, but pin it anyway.
    const alwaysMiss = { get: async () => undefined };

    for (const [label, options] of [
      ['sync driver', {}],
      ['async driver', { cache: alwaysMiss }],
    ]) {
      it(`${label}: allow across roles, deny within a role`, async () => {
        const kerberos = engine(RULES, options);
        assert.equal(await decide(kerberos, ['SUPPORT', 'AUDITOR']), Effect.Allow);
        assert.equal(await decide(kerberos, ['AUDITOR']), Effect.Deny);
      });
    }
  });

  describe('a principal with no roles', () => {
    it('is still reached by wildcard rules', async () => {
      // Rejected by every validation backend, but the engine runs without one
      // by default — a `*` rule must not silently stop applying.
      const allow = [{ actions: ['close'], effect: Effect.Allow, roles: ['*'] }];
      assert.equal(await decide(engine(allow), []), Effect.Allow);
      const denied = [...allow, { actions: ['close'], effect: Effect.Deny, roles: ['*'] }];
      assert.equal(await decide(engine(denied), []), Effect.Deny);
    });
  });

  describe('query plans follow the same rule', () => {
    it('plans ALLOWED for a role combination the runtime allows', async () => {
      const kerberos = engine(RULES);
      const plan = await kerberos.planResources({
        principal: { id: 'p1', roles: ['SUPPORT', 'AUDITOR'] },
        resource: { kind: 'ticket' },
        action: 'close',
      });
      assert.equal(plan.filter.kind, 'KIND_ALWAYS_ALLOWED');
    });

    it('plans DENIED when only the denying role is held', async () => {
      const kerberos = engine(RULES);
      const plan = await kerberos.planResources({
        principal: { id: 'p1', roles: ['AUDITOR'] },
        resource: { kind: 'ticket' },
        action: 'close',
      });
      assert.equal(plan.filter.kind, 'KIND_ALWAYS_DENIED');
    });
  });
});
