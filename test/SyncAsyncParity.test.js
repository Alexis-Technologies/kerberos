const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { commonRolesPolicy, principalsPolicy, resourcesPolicy, expensePolicy } = require('./mocks/index.js');
const { Kerberos } = require('../src/index.js');

// The engine has two evaluation drivers: the synchronous one (no cache, no
// relations — skips interior async frames) and the asynchronous one (cache
// and/or relations configured). Their layering/merge semantics are shared via
// private helpers, but the lookup plumbing is not — this suite pins END-TO-END
// equivalence so the drivers can never drift apart silently.
//
// The async driver is forced with an always-miss cache: every in-memory hit
// and miss then produces byte-identical responses to the plain configuration.

const parentRolePolicies = [
  {
    rolePolicy: {
      role: 'JUNIOR',
      version: 'default',
      parentRoles: ['SENIOR'],
      rules: [{ resource: 'expense', allowActions: ['view', 'approve'] }],
    },
  },
  {
    rolePolicy: {
      role: 'SENIOR',
      version: 'default',
      rules: [{ resource: 'expense', allowActions: ['view'] }],
    },
  },
];

const alwaysMissCache = {
  async get() {
    return undefined;
  },
};

function buildEngines(policies, derivedRoles) {
  return {
    syncEngine: new Kerberos(policies, derivedRoles, { getCallId: () => 'call-parity' }),
    asyncEngine: new Kerberos(policies, derivedRoles, {
      cache: alwaysMissCache,
      cacheRetry: { attempts: 1 },
      getCallId: () => 'call-parity',
    }),
  };
}

async function assertParity(policies, derivedRoles, checkArgs) {
  const { syncEngine, asyncEngine } = buildEngines(policies, derivedRoles);
  for (const includeMeta of [false, true]) {
    const args = { ...checkArgs, includeMeta };
    assert.deepEqual(await syncEngine.checkResources(args), await asyncEngine.checkResources(args));
  }
}

describe('sync/async evaluation driver parity', () => {
  it('matches on the canonical expense fixtures (roles + derived roles + outputs)', async () => {
    await assertParity([expensePolicy], [commonRolesPolicy], {
      principal: principalsPolicy.sally,
      resources: [
        { resource: resourcesPolicy.expense1, actions: ['view', 'delete', 'approve'] },
        { resource: { id: 'nothing', kind: 'unknown-kind' }, actions: ['view'] },
      ],
    });
  });

  it('matches on principal overrides layered over the resource policy', async () => {
    const principalOverride = {
      principalPolicy: {
        principal: 'sally',
        version: 'default',
        rules: [{ resource: 'expense', actions: [{ action: 'delete', effect: 'EFFECT_DENY' }] }],
      },
    };
    await assertParity([expensePolicy, principalOverride], [commonRolesPolicy], {
      principal: principalsPolicy.sally,
      resources: [{ resource: resourcesPolicy.expense1, actions: ['view', 'delete'] }],
    });
  });

  it('matches on parentRoles inheritance (intersection semantics)', async () => {
    await assertParity(parentRolePolicies, [], {
      principal: { id: 'joe', roles: ['JUNIOR'] },
      resources: [{ resource: { id: 'e1', kind: 'expense' }, actions: ['view', 'approve', 'delete'] }],
    });
  });

  it('matches on scoped lookups walking the scope chain', async () => {
    const scopedDeny = {
      resourcePolicy: {
        version: 'default',
        scope: 'acme.corp',
        resource: 'expense',
        rules: [{ actions: ['view'], effect: 'EFFECT_DENY', roles: ['USER'] }],
      },
    };
    await assertParity([expensePolicy, scopedDeny], [commonRolesPolicy], {
      principal: principalsPolicy.sally,
      resources: [
        { resource: { ...resourcesPolicy.expense1, scope: 'acme.corp' }, actions: ['view'] },
        { resource: { ...resourcesPolicy.expense1, scope: 'acme.other' }, actions: ['view'] },
      ],
    });
  });

  it('matches on isAllowed and on per-resource fail-closed isolation', async () => {
    const throwingPolicy = {
      resourcePolicy: {
        version: 'default',
        resource: 'broken',
        rules: [
          {
            actions: ['view'],
            effect: 'EFFECT_ALLOW',
            roles: ['USER'],
            condition: {
              match: () => {
                throw new Error('boom');
              },
            },
          },
        ],
      },
    };
    const { syncEngine, asyncEngine } = buildEngines([expensePolicy, throwingPolicy], [commonRolesPolicy]);

    for (const engine of [syncEngine, asyncEngine]) {
      assert.equal(
        await engine.isAllowed({
          principal: principalsPolicy.sally,
          action: 'view',
          resource: resourcesPolicy.expense1,
        }),
        true,
      );
    }

    const batch = {
      principal: principalsPolicy.sally,
      resources: [
        { resource: { id: 'b1', kind: 'broken' }, actions: ['view'] },
        { resource: resourcesPolicy.expense1, actions: ['view'] },
      ],
      includeMeta: true,
    };
    assert.deepEqual(await syncEngine.checkResources(batch), await asyncEngine.checkResources(batch));
  });
});

describe('sync/async driver parity with lifecycle hooks', () => {
  const batch = {
    principal: principalsPolicy.sally,
    resources: [
      { resource: resourcesPolicy.expense1, actions: ['view', 'delete', 'approve'] },
      { resource: { id: 'nothing', kind: 'unknown-kind' }, actions: ['view'] },
    ],
    includeMeta: true,
  };
  const single = { principal: principalsPolicy.sally, action: 'view', resource: resourcesPolicy.expense1 };

  it('request-level hooks keep the sync driver and produce identical responses', async () => {
    const plain = new Kerberos([expensePolicy], [commonRolesPolicy], { getCallId: () => 'call-parity' });
    const seen = [];
    const hooked = new Kerberos([expensePolicy], [commonRolesPolicy], {
      getCallId: () => 'call-parity',
      hooks: { beforeRequest: () => seen.push('before'), afterRequest: () => seen.push('after') },
    });
    assert.deepEqual(await hooked.checkResources(batch), await plain.checkResources(batch));
    assert.equal(await hooked.isAllowed(single), await plain.isAllowed(single));
    assert.deepEqual(seen, ['before', 'after', 'before', 'after']);
  });

  it('per-resource hooks (async form over a sync config) stay byte-identical to the plain engine', async () => {
    const plain = new Kerberos([expensePolicy], [commonRolesPolicy], { getCallId: () => 'call-parity' });
    const cached = new Kerberos([expensePolicy], [commonRolesPolicy], {
      cache: alwaysMissCache,
      cacheRetry: { attempts: 1 },
      getCallId: () => 'call-parity',
      hooks: { beforeResource() {}, afterResource() {} },
    });
    const hooked = new Kerberos([expensePolicy], [commonRolesPolicy], {
      getCallId: () => 'call-parity',
      hooks: { beforeResource() {}, afterResource() {} },
    });
    const expected = await plain.checkResources(batch);
    assert.deepEqual(await hooked.checkResources(batch), expected);
    assert.deepEqual(await cached.checkResources(batch), expected);
    assert.equal(await hooked.isAllowed(single), await plain.isAllowed(single));
  });
});
