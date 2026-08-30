const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const Ajv = require('ajv');
const { z } = require('zod');

const { Kerberos, Effect, KerberosValidationError } = require('../index.js');

// Attribute schema enforcement — Cerbos `schemas` parity: policies declare
// principalSchema/resourceSchema refs, the engine's `schemas` option maps the
// refs to validators and picks reject/warn/none. Semantics mirrored from
// Cerbos: reject denies every action with `validationErrors` on the result;
// warn reports the errors but leaves decisions alone; ignoreWhen skips
// validation only when EVERY requested action matches.

const EXPENSE_SCHEMA = {
  type: 'object',
  properties: {
    amount: { type: 'number' },
    ownerId: { type: 'string' },
  },
  required: ['amount'],
  additionalProperties: true,
};

const PRINCIPAL_SCHEMA = {
  type: 'object',
  properties: { department: { type: 'string' } },
  required: ['department'],
};

function buildEngine({ enforcement = 'reject', schemas, policies, options = {} } = {}) {
  return new Kerberos(
    policies ?? [
      {
        resourcePolicy: {
          version: 'default',
          resource: 'expense',
          schemas: schemas ?? {
            principalSchema: { ref: 'principal.json' },
            resourceSchema: { ref: 'expense.json' },
          },
          rules: [{ actions: ['view', 'approve'], effect: Effect.Allow, roles: ['USER'] }],
        },
      },
    ],
    [],
    {
      ajv: new Ajv({ allErrors: true }),
      schemas: {
        enforcement,
        definitions: { 'expense.json': EXPENSE_SCHEMA, 'principal.json': PRINCIPAL_SCHEMA },
      },
      ...options,
    },
  );
}

const goodPrincipal = { id: 'u1', roles: ['USER'], attr: { department: 'finance' } };
const goodResource = { kind: 'expense', id: 'e1', attr: { amount: 100 } };

describe('attribute schemas — reject enforcement', () => {
  const kerberos = buildEngine();

  it('valid attributes decide normally, with no validationErrors', async () => {
    assert.equal(await kerberos.isAllowed({ principal: goodPrincipal, resource: goodResource, action: 'view' }), true);
    const { results } = await kerberos.checkResources({
      principal: goodPrincipal,
      resources: [{ resource: goodResource, actions: ['view'] }],
    });
    assert.equal('validationErrors' in results[0], false);
  });

  it('invalid resource attributes deny every action with SOURCE_RESOURCE errors', async () => {
    const badResource = { kind: 'expense', id: 'e1', attr: { amount: 'lots' } };
    const { results } = await kerberos.checkResources({
      principal: goodPrincipal,
      resources: [{ resource: badResource, actions: ['view', 'approve'] }],
      includeMeta: true,
    });
    assert.deepEqual(results[0].actions, { view: Effect.Deny, approve: Effect.Deny });
    assert.equal(results[0].validationErrors.length, 1);
    assert.deepEqual(results[0].validationErrors[0], {
      path: '/amount',
      message: 'must be number',
      source: 'SOURCE_RESOURCE',
    });
    assert.equal(results[0].meta.actions.view.reason, 'invalid-attributes');
  });

  it('invalid principal attributes deny with SOURCE_PRINCIPAL errors', async () => {
    const badPrincipal = { id: 'u1', roles: ['USER'], attr: {} };
    const { results } = await kerberos.checkResources({
      principal: badPrincipal,
      resources: [{ resource: goodResource, actions: ['view'] }],
    });
    assert.equal(results[0].actions.view, Effect.Deny);
    assert.equal(results[0].validationErrors[0].source, 'SOURCE_PRINCIPAL');
  });

  it('missing attr bags validate as empty objects', async () => {
    const bareResource = { kind: 'expense', id: 'e1' };
    const { results } = await kerberos.checkResources({
      principal: goodPrincipal,
      resources: [{ resource: bareResource, actions: ['view'] }],
    });
    assert.equal(results[0].actions.view, Effect.Deny);
    assert.equal(results[0].validationErrors.length, 1); // required: amount
  });

  it('isAllowed fails closed on invalid attributes', async () => {
    const badResource = { kind: 'expense', id: 'e1', attr: {} };
    assert.equal(await kerberos.isAllowed({ principal: goodPrincipal, resource: badResource, action: 'view' }), false);
  });

  it('a principal policy cannot rescue a rejected request', async () => {
    const engine = new Kerberos(
      [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'expense',
            schemas: { resourceSchema: { ref: 'expense.json' } },
            rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
          },
        },
        {
          principalPolicy: {
            principal: 'u1',
            version: 'default',
            rules: [{ resource: 'expense', actions: [{ action: 'view', effect: Effect.Allow }] }],
          },
        },
      ],
      [],
      {
        ajv: new Ajv({ allErrors: true }),
        schemas: { enforcement: 'reject', definitions: { 'expense.json': EXPENSE_SCHEMA } },
      },
    );
    const badResource = { kind: 'expense', id: 'e1', attr: {} };
    assert.equal(await engine.isAllowed({ principal: goodPrincipal, resource: badResource, action: 'view' }), false);
  });

  it('collects every error when the validator reports them all', async () => {
    const badBoth = await kerberos.checkResources({
      principal: { id: 'u1', roles: ['USER'], attr: {} },
      resources: [{ resource: { kind: 'expense', id: 'e1', attr: {} }, actions: ['view'] }],
    });
    const sources = badBoth.results[0].validationErrors.map((error) => error.source);
    assert.deepEqual(sources.sort(), ['SOURCE_PRINCIPAL', 'SOURCE_RESOURCE']);
  });
});

describe('attribute schemas — warn enforcement', () => {
  const kerberos = buildEngine({ enforcement: 'warn' });

  it('reports validationErrors but leaves the decision alone', async () => {
    const badResource = { kind: 'expense', id: 'e1', attr: {} };
    const { results } = await kerberos.checkResources({
      principal: goodPrincipal,
      resources: [{ resource: badResource, actions: ['view'] }],
    });
    assert.equal(results[0].actions.view, Effect.Allow);
    assert.equal(results[0].validationErrors.length, 1);
  });

  it('audit entries carry the validation errors', async () => {
    const entries = [];
    const logger = { info: (entry) => entries.push(entry), debug: () => {} };
    const engine = buildEngine({ enforcement: 'warn', options: { logger } });
    await engine.checkResources({
      principal: goodPrincipal,
      resources: [{ resource: { kind: 'expense', id: 'e1', attr: {} }, actions: ['view'] }],
    });
    const withErrors = entries.filter((entry) => entry.validationErrors);
    assert.equal(withErrors.length, 1);
    assert.equal(withErrors[0].validationErrors[0].source, 'SOURCE_RESOURCE');
  });
});

describe('attribute schemas — disabled', () => {
  it('policies with schemas are inert without the engine option (Cerbos default)', async () => {
    const engine = new Kerberos(
      [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'expense',
            schemas: { resourceSchema: { ref: 'expense.json' } },
            rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
          },
        },
      ],
      [],
    );
    const badResource = { kind: 'expense', id: 'e1', attr: {} };
    assert.equal(await engine.isAllowed({ principal: goodPrincipal, resource: badResource, action: 'view' }), true);
  });

  it("enforcement: 'none' disables validation explicitly", async () => {
    const engine = buildEngine({ enforcement: 'none' });
    const badResource = { kind: 'expense', id: 'e1', attr: {} };
    assert.equal(await engine.isAllowed({ principal: goodPrincipal, resource: badResource, action: 'view' }), true);
  });
});

describe('attribute schemas — ignoreWhen', () => {
  const kerberos = buildEngine({
    schemas: { resourceSchema: { ref: 'expense.json', ignoreWhen: { actions: ['create', 'draft:*'] } } },
  });
  const badResource = { kind: 'expense', id: 'e1', attr: {} };

  it('skips validation when EVERY action matches the globs', async () => {
    const { results } = await kerberos.checkResources({
      principal: goodPrincipal,
      resources: [{ resource: badResource, actions: ['create', 'draft:save'] }],
    });
    assert.equal('validationErrors' in results[0], false);
    assert.equal(results[0].actions.create, Effect.Deny); // rule-miss, not schema
  });

  it('validates when any action falls outside the globs', async () => {
    const { results } = await kerberos.checkResources({
      principal: goodPrincipal,
      resources: [{ resource: badResource, actions: ['create', 'view'] }],
    });
    assert.equal(results[0].validationErrors.length, 1);
    assert.equal(results[0].actions.view, Effect.Deny);
  });
});

describe('attribute schemas — scope chains', () => {
  it('uses the most specific policy in the chain that declares schemas', async () => {
    const engine = new Kerberos(
      [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'expense',
            schemas: { resourceSchema: { ref: 'strict.json' } },
            rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
          },
        },
        {
          resourcePolicy: {
            version: 'default',
            resource: 'expense',
            scope: 'acme',
            schemas: { resourceSchema: { ref: 'lenient.json' } },
            rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
          },
        },
      ],
      [],
      {
        ajv: new Ajv({ allErrors: true }),
        schemas: {
          enforcement: 'reject',
          definitions: {
            'strict.json': { type: 'object', required: ['amount'] },
            'lenient.json': { type: 'object' },
          },
        },
      },
    );
    const bare = { kind: 'expense', id: 'e1', attr: {} };
    // Scoped request → the acme policy's lenient schema applies.
    assert.equal(
      await engine.isAllowed({ principal: goodPrincipal, resource: { ...bare, scope: 'acme' }, action: 'view' }),
      true,
    );
    // Unscoped request → the base policy's strict schema applies.
    assert.equal(await engine.isAllowed({ principal: goodPrincipal, resource: bare, action: 'view' }), false);
  });
});

describe('attribute schemas — definition kinds and configuration errors', () => {
  it('accepts Zod schemas as definitions', async () => {
    const engine = new Kerberos(
      [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'expense',
            schemas: { resourceSchema: { ref: 'expense.zod' } },
            rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
          },
        },
      ],
      [],
      { schemas: { definitions: { 'expense.zod': z.object({ amount: z.number() }) } } },
    );
    const { results } = await engine.checkResources({
      principal: goodPrincipal,
      resources: [{ resource: { kind: 'expense', id: 'e1', attr: { amount: 'x' } }, actions: ['view'] }],
    });
    assert.equal(results[0].actions.view, Effect.Deny);
    assert.equal(results[0].validationErrors[0].path, '/amount');
  });

  it('accepts validator functions as definitions', async () => {
    const engine = new Kerberos(
      [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'expense',
            schemas: { resourceSchema: { ref: 'expense.fn' } },
            rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
          },
        },
      ],
      [],
      {
        schemas: {
          definitions: {
            'expense.fn': (attr) => (typeof attr.amount === 'number' ? [] : ['amount must be a number']),
          },
        },
      },
    );
    const { results } = await engine.checkResources({
      principal: goodPrincipal,
      resources: [{ resource: { kind: 'expense', id: 'e1', attr: {} }, actions: ['view'] }],
    });
    assert.deepEqual(results[0].validationErrors, [
      { path: '', message: 'amount must be a number', source: 'SOURCE_RESOURCE' },
    ]);
  });

  it('a JSON Schema definition without ajv throws at construction', () => {
    assert.throws(
      () => new Kerberos([], [], { schemas: { definitions: { 'x.json': { type: 'object' } } } }),
      KerberosValidationError,
    );
  });

  it('a policy referencing an undefined schema throws (always, regardless of onError)', async () => {
    const engine = new Kerberos(
      [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'expense',
            schemas: { resourceSchema: { ref: 'missing.json' } },
            rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
          },
        },
      ],
      [],
      { onError: 'deny', schemas: { definitions: {} } },
    );
    await assert.rejects(
      engine.isAllowed({ principal: goodPrincipal, resource: goodResource, action: 'view' }),
      KerberosValidationError,
    );
  });

  it('rejects invalid enforcement levels', () => {
    assert.throws(() => new Kerberos([], [], { schemas: { enforcement: 'maybe', definitions: {} } }), TypeError);
  });

  it('rejects malformed schemas blocks in policies', () => {
    assert.throws(
      () =>
        new Kerberos(
          [
            {
              resourcePolicy: {
                version: 'default',
                resource: 'expense',
                schemas: { resourceSchema: { ref: '' } },
                rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
              },
            },
          ],
          [],
          { z },
        ),
      /ref/,
    );
  });
});

describe('attribute schemas — driver parity', () => {
  it('the async driver (cache-backed) agrees with the sync driver', async () => {
    const policies = [
      {
        resourcePolicy: {
          version: 'default',
          resource: 'expense',
          schemas: { resourceSchema: { ref: 'expense.json' } },
          rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
        },
      },
    ];
    const schemas = { enforcement: 'reject', definitions: { 'expense.json': EXPENSE_SCHEMA } };
    const syncEngine = new Kerberos(policies, [], { ajv: new Ajv({ allErrors: true }), schemas });
    const asyncEngine = new Kerberos(policies, [], { ajv: new Ajv({ allErrors: true }), schemas, cache: new Map() });

    for (const attr of [{ amount: 1 }, {}, { amount: 'x' }]) {
      const args = {
        principal: goodPrincipal,
        resources: [{ resource: { kind: 'expense', id: 'e1', attr }, actions: ['view'] }],
      };
      const [syncResult, asyncResult] = await Promise.all([
        syncEngine.checkResources(args),
        asyncEngine.checkResources(args),
      ]);
      assert.deepEqual(syncResult.results[0].actions, asyncResult.results[0].actions);
      assert.deepEqual(syncResult.results[0].validationErrors, asyncResult.results[0].validationErrors);
    }
  });
});
