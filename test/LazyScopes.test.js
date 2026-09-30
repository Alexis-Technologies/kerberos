const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { Effect, Kerberos } = require('../src/index.js');

// The decision walk evaluates a scope only when a bucket reaches it for an
// action: once a more specific scope decides, the less specific ones are
// never evaluated — their conditions do not run and their outputs are not
// emitted (Cerbos's rule-table walk, verified on a live 0.55 PDP).

const principal = { id: 'p', roles: ['USER'] };
const resourceAt = (scope, attr = {}) => ({ id: 'd1', kind: 'doc', scope, attr });
const output = (label) => ({
  when: { ruleActivated: () => `${label}:activated`, conditionNotMet: () => `${label}:not-met` },
});

function policies({ baseCondition, acmeCondition } = {}) {
  return [
    {
      resourcePolicy: {
        version: 'default',
        resource: 'doc',
        rules: [
          { name: 'base_view', actions: ['view'], effect: Effect.Allow, roles: ['USER'], output: output('base_view') },
          { name: 'base_edit', actions: ['edit'], effect: Effect.Allow, roles: ['USER'], output: output('base_edit') },
          ...(baseCondition
            ? [
                {
                  name: 'base_guard',
                  actions: ['view', 'edit'],
                  effect: Effect.Deny,
                  roles: ['USER'],
                  condition: { match: baseCondition },
                },
              ]
            : []),
        ],
      },
    },
    {
      resourcePolicy: {
        version: 'default',
        resource: 'doc',
        scope: 'acme',
        rules: [
          {
            name: 'acme_view',
            actions: ['view'],
            effect: Effect.Allow,
            roles: ['USER'],
            output: output('acme_view'),
            ...(acmeCondition ? { condition: { match: acmeCondition } } : {}),
          },
        ],
      },
    },
  ];
}

// Always-miss cache: forces the async driver with the same policies.
const drivers = {
  sync: (docs) => new Kerberos(docs, [], { onError: 'deny' }),
  async: (docs) => new Kerberos(docs, [], { onError: 'deny', cache: { get: async () => undefined } }),
};

const srcs = (result) => result.outputs.map((entry) => entry.src);

for (const [driver, build] of Object.entries(drivers)) {
  describe(`lazy scope evaluation (${driver} driver)`, () => {
    it('does not emit the outputs of a scope the walk never reaches', async () => {
      const kerberos = build(policies());
      const response = await kerberos.checkResources({
        principal,
        resources: [{ resource: resourceAt('acme'), actions: ['view'] }],
      });
      assert.deepEqual(response.results[0].actions, { view: Effect.Allow });
      assert.deepEqual(srcs(response.results[0]), ['resource.doc.vdefault/acme#acme_view']);
    });

    it('evaluates the parent scope when the specific one does not decide', async () => {
      const kerberos = build(policies({ acmeCondition: () => false }));
      const response = await kerberos.checkResources({
        principal,
        resources: [{ resource: resourceAt('acme'), actions: ['view'] }],
      });
      assert.deepEqual(response.results[0].actions, { view: Effect.Allow });
      assert.deepEqual(srcs(response.results[0]), [
        'resource.doc.vdefault/acme#acme_view',
        'resource.doc.vdefault#base_view',
      ]);
    });

    it('evaluates a scope only for the actions that reach it', async () => {
      const kerberos = build(policies());
      const response = await kerberos.checkResources({
        principal,
        resources: [{ resource: resourceAt('acme'), actions: ['view', 'edit'] }],
      });
      assert.deepEqual(response.results[0].actions, { view: Effect.Allow, edit: Effect.Allow });
      // `view` is decided at acme; only `edit` falls through to the base scope,
      // so base_view never runs.
      assert.deepEqual(srcs(response.results[0]), [
        'resource.doc.vdefault/acme#acme_view',
        'resource.doc.vdefault#base_edit',
      ]);
    });

    it('does not fail the request on an erroring condition in a scope it never reaches', async () => {
      const throwing = () => {
        throw new TypeError('boom');
      };
      const kerberos = build(policies({ baseCondition: throwing }));
      const decided = await kerberos.checkResources({
        principal,
        resources: [{ resource: resourceAt('acme'), actions: ['view'] }],
      });
      assert.deepEqual(decided.results[0].actions, { view: Effect.Allow });

      // A request that does reach the erroring condition still fails closed.
      const reached = await kerberos.checkResources({
        principal,
        resources: [{ resource: resourceAt('acme'), actions: ['edit'] }],
        includeMeta: true,
      });
      assert.deepEqual(reached.results[0].actions, { edit: Effect.Deny });
      assert.equal(reached.results[0].meta.actions.edit.reason, 'evaluation-error');
    });

    it('evaluates a role policy only when a bucket reaches its scope', async () => {
      let evaluations = 0;
      const kerberos = build([
        ...policies(),
        {
          rolePolicy: {
            role: 'USER',
            version: 'default',
            rules: [
              {
                resource: 'doc',
                allowActions: ['view', 'edit'],
                condition: {
                  match: () => {
                    evaluations += 1;
                    return true;
                  },
                },
              },
            ],
          },
        },
      ]);
      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource: resourceAt('acme') }), true);
      assert.equal(evaluations, 0);
      assert.equal(await kerberos.isAllowed({ principal, action: 'edit', resource: resourceAt('acme') }), true);
      assert.equal(evaluations, 1);
    });

    it('still explains a default deny with every scope evaluated', async () => {
      const kerberos = build(policies({ acmeCondition: () => false, baseCondition: () => true }));
      const response = await kerberos.checkResources({
        principal: { id: 'p', roles: ['GUEST'] },
        resources: [{ resource: resourceAt('acme'), actions: ['view'] }],
        includeMeta: true,
      });
      assert.deepEqual(response.results[0].actions, { view: Effect.Deny });
      assert.deepEqual(response.results[0].meta.actions.view, {
        reason: 'rule-miss',
        matchedPolicy: 'resource.doc.vdefault/acme',
      });
    });
  });
}
