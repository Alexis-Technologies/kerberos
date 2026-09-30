const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { principalsPolicy, resourcesPolicy, userRolePolicy } = require('./mocks/index.js');
const { Effect, RolePolicy } = require('../src/index.js');

describe('RolePolicy', () => {
  const rolePolicy = new RolePolicy(userRolePolicy);

  it('should expose role target and rules', () => {
    assert.strictEqual(rolePolicy.role, 'USER');
    assert.strictEqual(rolePolicy.version, 'default');
    assert.deepStrictEqual(rolePolicy.parentRoles, []);
    assert.strictEqual(rolePolicy.rules.length, 2);
  });

  it('should allow listed actions and deny missing actions for matching resources', () => {
    const principal = principalsPolicy.sally;
    const resource = resourcesPolicy.expense2;
    const req = { P: principal, principal, R: resource, resource, actions: ['create', 'delete'] };

    const { effects } = rolePolicy.check(req);

    assert.deepStrictEqual(Object.fromEntries(effects), {
      create: Effect.Allow,
      delete: Effect.Deny,
    });
  });

  it('should deny when a rule condition is not fulfilled and emit conditionNotMet output', () => {
    const principal = principalsPolicy.sally;
    const resource = resourcesPolicy.expense1;
    const req = { P: principal, principal, R: resource, resource, actions: ['view'] };

    const { effects, outputs, meta } = rolePolicy.check(req);

    assert.deepStrictEqual(Object.fromEntries(effects), {
      view: Effect.Deny,
    });
    assert.strictEqual(outputs.size, 1);
    assert.strictEqual(outputs.values().next().value.val.message, 'Role policy blocked restricted vendor view');
    assert.strictEqual(meta.actions.view.matchedPolicy, 'role.USER.vdefault');
  });

  it('should support wildcard resource matching', () => {
    const wildcardPolicy = new RolePolicy({
      rolePolicy: {
        role: 'AUDITOR',
        version: 'default',
        rules: [
          {
            resource: '*',
            allowActions: ['view'],
          },
        ],
      },
    });
    const principal = { id: 'audrey', roles: ['AUDITOR'] };
    const resource = resourcesPolicy.expense2;
    const req = { P: principal, principal, R: resource, resource, actions: ['view', 'create'] };

    const { effects } = wildcardPolicy.check(req);

    assert.deepStrictEqual(Object.fromEntries(effects), {
      view: Effect.Allow,
      create: Effect.Deny,
    });
  });
});

describe('engine lookups for ids without in-memory policies', () => {
  const { Kerberos } = require('../src/index.js');
  const policies = [
    {
      resourcePolicy: {
        version: 'default',
        resource: 'doc',
        rules: [{ actions: ['view', 'delete'], effect: Effect.Allow, roles: ['EDITOR', 'VIEWER', 'USER'] }],
      },
    },
    {
      rolePolicy: {
        role: 'VIEWER',
        version: 'default',
        rules: [{ resource: 'doc', allowActions: ['view'] }],
      },
    },
  ];
  const resource = { id: 'd1', kind: 'doc' };

  it('still records one resolution entry per role, in order, under includeMeta', async () => {
    const kerberos = new Kerberos(policies, []);
    const response = await kerberos.checkResources({
      principal: { id: 'p', roles: ['EDITOR', 'VIEWER', 'EDITOR', 'USER'] },
      resources: [{ resource, actions: ['view', 'delete'] }],
      includeMeta: true,
    });
    const roleEntries = response.results[0].meta.resolution.filter((entry) => entry.source === 'role');
    assert.deepStrictEqual(
      roleEntries.map((entry) => [entry.id, entry.matchedScope]),
      [
        ['EDITOR', null],
        ['VIEWER', ''],
        ['USER', null],
      ],
    );
    assert.deepStrictEqual(roleEntries[0].scopesSearched, ['']);
    const principalEntry = response.results[0].meta.resolution.find((entry) => entry.source === 'principal');
    assert.deepStrictEqual(principalEntry, {
      source: 'principal',
      id: 'p',
      version: 'default',
      scopesSearched: [''],
      matchedScope: null,
    });
  });

  it('keeps decisions identical with and without includeMeta', async () => {
    const kerberos = new Kerberos(policies, []);
    for (const roles of [['VIEWER'], ['EDITOR', 'VIEWER'], ['USER'], ['nobody']]) {
      const args = { principal: { id: 'p', roles }, resources: [{ resource, actions: ['view', 'delete'] }] };
      const plain = await kerberos.checkResources(args);
      const traced = await kerberos.checkResources({ ...args, includeMeta: true });
      assert.deepStrictEqual(plain.results[0].actions, traced.results[0].actions, roles.join(','));
    }
    const viewerOnly = await kerberos.checkResources({
      principal: { id: 'p', roles: ['VIEWER'] },
      resources: [{ resource, actions: ['view', 'delete'] }],
    });
    assert.deepStrictEqual(viewerOnly.results[0].actions, { view: Effect.Allow, delete: Effect.Deny });
  });

  it('still consults the cache for roles with no in-memory role policy', async () => {
    const store = new Map([
      [
        'role:EDITOR:default:',
        { rolePolicy: { role: 'EDITOR', version: 'default', rules: [{ resource: 'doc', allowActions: ['view'] }] } },
      ],
    ]);
    const kerberos = new Kerberos(policies, [], { cache: store });
    assert.equal(
      await kerberos.isAllowed({ principal: { id: 'p', roles: ['EDITOR'] }, action: 'delete', resource }),
      false,
    );
    assert.equal(
      await kerberos.isAllowed({ principal: { id: 'p', roles: ['EDITOR'] }, action: 'view', resource }),
      true,
    );
  });
});
