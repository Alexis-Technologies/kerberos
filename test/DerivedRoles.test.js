const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { commonRolesPolicy, principalsPolicy, resourcesPolicy } = require('./mocks/index.js');

const { DerivedRoles } = require('../src/index.js');

describe('DerivedRoles', () => {
  it('should parse schema', () => {
    const derivedRoles = new DerivedRoles(commonRolesPolicy);

    assert.strictEqual(derivedRoles.name, 'common_roles');
    assert.strictEqual(derivedRoles.roles.size, 4);
    assert.strictEqual(derivedRoles.shape.variables, undefined);
    assert.strictEqual(derivedRoles.shape.constants, undefined);
  });

  it('should get roles', () => {
    const R = resourcesPolicy.expense1;

    const derivedRoles = new DerivedRoles(commonRolesPolicy);

    assert.deepEqual(
      [...derivedRoles.get({ P: principalsPolicy.sally, principal: principalsPolicy.sally, R, resource: R })],
      ['OWNER'],
    );
    assert.deepEqual(
      [...derivedRoles.get({ P: principalsPolicy.ian, principal: principalsPolicy.ian, R, resource: R })],
      [],
    );
    assert.deepEqual(
      [...derivedRoles.get({ P: principalsPolicy.frank, principal: principalsPolicy.frank, R, resource: R })],
      ['FINANCE'],
    );
    assert.deepEqual(
      [...derivedRoles.get({ P: principalsPolicy.derek, principal: principalsPolicy.derek, R, resource: R })],
      ['FINANCE', 'FINANCE_MANAGER', 'REGION_MANAGER'],
    );
    assert.deepEqual(
      [...derivedRoles.get({ P: principalsPolicy.simon, principal: principalsPolicy.simon, R, resource: R })],
      [],
    );
    assert.deepEqual(
      [...derivedRoles.get({ P: principalsPolicy.mark, principal: principalsPolicy.mark, R, resource: R })],
      ['REGION_MANAGER'],
    );
    assert.deepEqual(
      [...derivedRoles.get({ P: principalsPolicy.sydney, principal: principalsPolicy.sydney, R, resource: R })],
      [],
    );
  });
});

describe('lazy derived-role evaluation in the engine', () => {
  const { Effect, Kerberos } = require('../src/index.js');

  function countingSet(counts, { throwing = false } = {}) {
    const condition = (name, result) => ({
      match: () => {
        counts[name] = (counts[name] ?? 0) + 1;
        if (throwing && name === 'BROKEN') throw new Error('broken condition');
        return result;
      },
    });
    return {
      name: 'lazy_roles',
      definitions: [
        { name: 'OWNER', parentRoles: ['USER'], condition: condition('OWNER', true) },
        { name: 'EDITOR', parentRoles: ['USER'], condition: condition('EDITOR', true) },
        { name: 'BROKEN', parentRoles: ['USER'], condition: condition('BROKEN', true) },
      ],
    };
  }

  const policy = (scope = '') => ({
    resourcePolicy: {
      version: 'default',
      resource: 'doc',
      scope,
      importDerivedRoles: ['lazy_roles'],
      rules: [
        { actions: ['view'], effect: Effect.Allow, roles: ['USER'] },
        { actions: ['edit'], effect: Effect.Allow, derivedRoles: ['EDITOR'] },
        { actions: ['own'], effect: Effect.Allow, derivedRoles: ['OWNER'] },
        { actions: ['break'], effect: Effect.Allow, derivedRoles: ['BROKEN'] },
      ],
    },
  });
  const principal = { id: 'p', roles: ['USER'] };
  const resource = { id: 'd', kind: 'doc' };

  it('evaluates only the derived roles a rule of the requested actions asks about', async () => {
    const counts = {};
    const kerberos = new Kerberos([policy()], [countingSet(counts)]);
    assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
    assert.deepEqual(counts, {});
    assert.equal(await kerberos.isAllowed({ principal, action: 'edit', resource }), true);
    assert.deepEqual(counts, { EDITOR: 1 });
  });

  it('still lists every active imported derived role under includeMeta', async () => {
    const counts = {};
    const kerberos = new Kerberos([policy()], [countingSet(counts)]);
    const response = await kerberos.checkResources({
      principal,
      resources: [{ resource, actions: ['edit'] }],
      includeMeta: true,
    });
    assert.deepEqual(response.results[0].meta.effectiveDerivedRoles, ['OWNER', 'EDITOR', 'BROKEN']);
    assert.deepEqual(counts, { OWNER: 1, EDITOR: 1, BROKEN: 1 });
  });

  it('does not fail a request on a throwing derived role no rule of it asks about', async () => {
    for (const includeMeta of [false, true]) {
      const kerberos = new Kerberos([policy()], [countingSet({}, { throwing: true })], { onError: 'deny' });
      const response = await kerberos.checkResources({
        principal,
        resources: [{ resource, actions: ['view', 'own'] }],
        includeMeta,
      });
      assert.deepEqual(
        response.results[0].actions,
        { view: Effect.Allow, own: Effect.Allow },
        `includeMeta ${includeMeta}`,
      );
      if (includeMeta) assert.deepEqual(response.results[0].meta.effectiveDerivedRoles, ['OWNER', 'EDITOR']);
    }
  });

  it('still fails closed when a rule of the request needs the throwing derived role', async () => {
    const kerberos = new Kerberos([policy()], [countingSet({}, { throwing: true })], { onError: 'deny' });
    const response = await kerberos.checkResources({
      principal,
      resources: [{ resource, actions: ['view', 'break'] }],
    });
    assert.deepEqual(response.results[0].actions, { view: Effect.Deny, break: Effect.Deny });
  });

  it('evaluates a set imported at several scopes once per request', async () => {
    const counts = {};
    const narrow = policy('acme');
    narrow.resourcePolicy.rules = [
      { actions: ['edit'], effect: Effect.Deny, derivedRoles: ['EDITOR'], condition: { match: () => false } },
    ];
    const kerberos = new Kerberos([policy(), narrow], [countingSet(counts)]);
    assert.equal(
      await kerberos.isAllowed({ principal, action: 'edit', resource: { ...resource, scope: 'acme' } }),
      true,
    );
    assert.deepEqual(counts, { EDITOR: 1 });
  });

  it('asks the relations resolver only about relation-backed roles a rule needs', async () => {
    const asked = [];
    const kerberos = new Kerberos(
      [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'doc',
            importDerivedRoles: ['rel_roles'],
            rules: [
              { actions: ['view'], effect: Effect.Allow, roles: ['USER'] },
              { actions: ['edit'], effect: Effect.Allow, derivedRoles: ['DOC_EDITOR'] },
            ],
          },
        },
      ],
      [{ name: 'rel_roles', definitions: [{ name: 'DOC_EDITOR', relation: 'edit' }] }],
      {
        relations: {
          async check({ relation }) {
            asked.push(relation);
            return true;
          },
        },
      },
    );
    assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
    assert.deepEqual(asked, []);
    assert.equal(await kerberos.isAllowed({ principal, action: 'edit', resource }), true);
    assert.deepEqual(asked, ['edit']);
  });

  it('rejects a condition-backed definition without parentRoles even without a validation backend', () => {
    assert.throws(
      () => new DerivedRoles({ name: 'bad', definitions: [{ name: 'X', condition: { match: () => true } }] }),
      /requires either "relation" or both "parentRoles" and "condition"/,
    );
  });
});
