const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const { Keyv } = require('keyv');

const { Effect, Kerberos } = require('../src/index.js');

// Which side of the request selects which policy type:
//   resourcePolicy  → resource.kind + resource.policyVersion + resource.scope
//   principalPolicy → principal.id  + principal.policyVersion + principal.scope
//   rolePolicy      → principal.roles[] + RESOURCE policyVersion/scope
// The role-policy row follows Cerbos's engine; the principal-policy row
// follows Cerbos's API/docs (0.41+ regressed — see conformance/DIVERGENCES.md).

const principalDefault = {
  principalPolicy: {
    principal: 'ivy',
    version: 'default',
    rules: [{ resource: 'narrow2', actions: [{ action: 'grant', effect: Effect.Allow }] }],
  },
};

const principalV2 = {
  principalPolicy: {
    principal: 'ivy',
    version: 'v2',
    rules: [{ resource: 'narrow2', actions: [{ action: 'escalate', effect: Effect.Allow }] }],
  },
};

// Inert resource policies: they exist at both versions so the resource chain
// never decides, leaving the principal layer as the only source of an allow.
const resourcePolicy = (version) => ({
  resourcePolicy: {
    version,
    resource: 'narrow2',
    rules: [{ actions: ['nothing'], effect: Effect.Allow, roles: ['NOBODY'] }],
  },
});

const rolePolicy = (version, allowActions) => ({
  rolePolicy: { role: 'RS', version, rules: [{ resource: 'narrow2', allowActions }] },
});

const resourceAllowsRS = (version) => ({
  resourcePolicy: {
    version,
    resource: 'narrow2',
    rules: [{ actions: ['ping', 'other'], effect: Effect.Allow, roles: ['RS'] }],
  },
});

function request(principalVersion, resourceVersion, action, roles = ['Z']) {
  const principal = { id: 'ivy', roles };
  if (principalVersion) principal.policyVersion = principalVersion;
  const resource = { id: 'r0', kind: 'narrow2' };
  if (resourceVersion) resource.policyVersion = resourceVersion;
  return { principal, action, resource };
}

describe('policy versions', () => {
  describe('principal policies follow principal.policyVersion', () => {
    const policies = [principalDefault, principalV2, resourcePolicy('default'), resourcePolicy('v2')];

    const cases = [
      // principalVersion, resourceVersion, grant, escalate
      [undefined, undefined, true, false],
      [undefined, 'v2', true, false],
      ['default', 'v2', true, false],
      ['v2', undefined, false, true],
      ['v2', 'default', false, true],
      ['v2', 'v2', false, true],
    ];

    for (const driver of ['sync', 'async']) {
      // The async driver is the one taken when a cache is configured; an empty
      // cache keeps the policies in memory while switching the code path.
      const build = () =>
        driver === 'sync' ? new Kerberos(policies) : new Kerberos(policies, [], { cache: new Keyv() });

      for (const [pv, rv, grant, escalate] of cases) {
        it(`${driver}: P=${pv ?? '-'} R=${rv ?? '-'} → grant ${grant}, escalate ${escalate}`, async () => {
          const kerberos = build();
          assert.equal(await kerberos.isAllowed(request(pv, rv, 'grant')), grant);
          assert.equal(await kerberos.isAllowed(request(pv, rv, 'escalate')), escalate);
        });
      }
    }

    it('planResources selects the principal policy the same way', async () => {
      const kerberos = new Kerberos(policies);
      const planFor = async (pv, rv, action) => {
        const resource = { kind: 'narrow2' };
        if (rv) resource.policyVersion = rv;
        const principal = { id: 'ivy', roles: ['Z'] };
        if (pv) principal.policyVersion = pv;
        return (await kerberos.planResources({ principal, action, resource })).filter.kind;
      };
      assert.equal(await planFor('v2', 'default', 'escalate'), 'KIND_ALWAYS_ALLOWED');
      assert.equal(await planFor('v2', 'default', 'grant'), 'KIND_ALWAYS_DENIED');
      assert.equal(await planFor(undefined, 'v2', 'grant'), 'KIND_ALWAYS_ALLOWED');
    });

    it('has no fallback to the default version', async () => {
      const kerberos = new Kerberos([principalDefault, resourcePolicy('default'), resourcePolicy('v9')]);
      assert.equal(await kerberos.isAllowed(request('v9', undefined, 'grant')), false);
    });
  });

  describe('role policies follow the resource policyVersion', () => {
    const policies = [
      rolePolicy('default', ['ping']),
      rolePolicy('v2', ['other']),
      resourceAllowsRS('default'),
      resourceAllowsRS('v2'),
    ];

    it('narrows by the version named on the resource, not on the principal', async () => {
      const kerberos = new Kerberos(policies);
      // resource default → the default role policy allowlists only `ping`
      assert.equal(await kerberos.isAllowed(request('v2', undefined, 'ping', ['RS'])), true);
      assert.equal(await kerberos.isAllowed(request('v2', undefined, 'other', ['RS'])), false);
      // resource v2 → the v2 role policy allowlists only `other`
      assert.equal(await kerberos.isAllowed(request(undefined, 'v2', 'ping', ['RS'])), false);
      assert.equal(await kerberos.isAllowed(request(undefined, 'v2', 'other', ['RS'])), true);
    });
  });

  describe('checkResources', () => {
    it('uses one principal chain and each resource its own version', async () => {
      const kerberos = new Kerberos([principalV2, principalDefault, resourcePolicy('default'), resourcePolicy('v2')]);
      const response = await kerberos.checkResources({
        principal: { id: 'ivy', roles: ['Z'], policyVersion: 'v2' },
        resources: [
          { resource: { id: 'a', kind: 'narrow2' }, actions: ['escalate', 'grant'] },
          { resource: { id: 'b', kind: 'narrow2', policyVersion: 'v2' }, actions: ['escalate', 'grant'] },
        ],
        includeMeta: true,
      });

      for (const result of response.results) {
        assert.equal(result.actions.escalate, Effect.Allow);
        assert.equal(result.actions.grant, Effect.Deny);
      }
      // The response echoes the resource's own version.
      assert.equal(response.results[0].resource.policyVersion, undefined);
      assert.equal(response.results[1].resource.policyVersion, 'v2');
      // One principal lookup per batch, at the principal's version.
      const principalLookups = response.results[0].meta.resolution.filter((entry) => entry.source === 'principal');
      assert.deepEqual(
        principalLookups.map((entry) => entry.version),
        ['v2'],
      );
    });
  });
});
