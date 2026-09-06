const { describe, it } = require('node:test');
const assert = require('node:assert').strict;
const { z } = require('zod');

const { Kerberos, Effect, KerberosValidationError } = require('../src/index.js');
const { RelationResolver } = require('../relations.js');

const tick = () => new Promise((resolve) => setImmediate(resolve));

const expensePolicy = {
  resourcePolicy: {
    version: 'default',
    resource: 'expense',
    rules: [{ name: 'user-view', actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
  },
};
const brokenPolicy = {
  resourcePolicy: {
    version: 'default',
    resource: 'broken',
    rules: [
      {
        actions: ['view'],
        effect: Effect.Allow,
        roles: ['USER'],
        condition: {
          match: () => {
            throw new Error('condition boom');
          },
        },
      },
    ],
  },
};
const policies = [expensePolicy, brokenPolicy];

const principal = { id: 'sally', roles: ['USER'], attr: { secret: 'do-not-leak' } };
const resource = { id: 'expense1', kind: 'expense', attr: { owner: 'sally' } };
const brokenResource = { id: 'b1', kind: 'broken' };

const ENGINE_EVENTS = [
  'request:start',
  'request:end',
  'request:error',
  'decision',
  'plan',
  'relations:resolved',
  'cache:hit',
  'cache:miss',
  'cache:error',
];

function subscribeAll(target, names) {
  const events = [];
  for (const name of names) target.on(name, (payload) => events.push({ name, payload }));
  return { events, names: () => events.map((event) => event.name) };
}

function engine(options = {}) {
  return new Kerberos(policies, [], { getCallId: () => 'call-events', ...options });
}

async function withPatchedWarn(callback) {
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (message) => warnings.push(message);
  try {
    await callback(warnings);
  } finally {
    console.warn = originalWarn;
  }
  return warnings;
}

describe('engine events — order and payloads', () => {
  it('isAllowed: request:start → decision → request:end', async () => {
    const kerberos = engine();
    const { events, names } = subscribeAll(kerberos, ENGINE_EVENTS);
    assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource, reqId: 'r1' }), true);
    assert.deepEqual(names(), ['request:start', 'decision', 'request:end']);

    const [start, decision, end] = events.map((event) => event.payload);
    assert.deepEqual(start, { callId: 'call-events', reqKind: 'IsAllowed', reqId: 'r1' });
    assert.deepEqual(decision, {
      callId: 'call-events',
      reqKind: 'IsAllowed',
      reqId: 'r1',
      index: 0,
      principal: { id: 'sally', roles: ['USER'] },
      resource: { kind: 'expense', id: 'expense1' },
      actions: { view: Effect.Allow },
    });
    assert.equal(end.success, true);
    assert.equal(typeof end.durationMs, 'number');
    assert.equal('error' in end, false);
  });

  it('checkResources: one decision per resource; planResources: plan', async () => {
    const kerberos = engine();
    const { events, names } = subscribeAll(kerberos, ENGINE_EVENTS);
    await kerberos.checkResources({
      principal,
      resources: [
        { resource, actions: ['view'] },
        {
          resource: { id: 'expense2', kind: 'expense', scope: 'acme', policyVersion: 'default' },
          actions: ['view', 'delete'],
        },
      ],
    });
    assert.deepEqual(names(), ['request:start', 'decision', 'decision', 'request:end']);
    assert.deepEqual(events[2].payload.resource, {
      kind: 'expense',
      id: 'expense2',
      scope: 'acme',
      policyVersion: 'default',
    });
    assert.deepEqual(events[2].payload.actions, { view: Effect.Allow, delete: Effect.Deny });
    assert.equal(events[2].payload.index, 1);
    // No reqId given → no reqId key (fresh, minimal objects).
    assert.equal('reqId' in events[0].payload, false);

    events.length = 0;
    const plan = await kerberos.planResources({ principal, resource: { kind: 'expense' }, actions: ['view'] });
    assert.equal(plan.filter.kind, 'KIND_ALWAYS_ALLOWED');
    assert.deepEqual(names(), ['request:start', 'plan', 'request:end']);
    assert.deepEqual(events[1].payload, {
      callId: 'call-events',
      reqKind: 'PlanResources',
      principal: { id: 'sally', roles: ['USER'] },
      resource: { kind: 'expense' },
      actions: ['view'],
      filterKind: 'KIND_ALWAYS_ALLOWED',
      opaqueCount: 0,
      relationCount: 0,
    });
  });

  it('validation error: request:start → request:error → request:end (success: false, string error)', async () => {
    const kerberos = engine({ z });
    const { events, names } = subscribeAll(kerberos, ENGINE_EVENTS);
    await assert.rejects(() => kerberos.isAllowed({ principal }), KerberosValidationError);
    assert.deepEqual(names(), ['request:start', 'request:error', 'request:end']);
    const [, error, end] = events.map((event) => event.payload);
    assert.equal(typeof error.error, 'string');
    assert.equal(error.errorName, 'KerberosValidationError');
    assert.equal(end.success, false);
    assert.equal(end.errorName, 'KerberosValidationError');
    assert.equal(end.error, error.error);
  });

  it("evaluation error: request:error, then the fail-closed decision under onError: 'deny'", async () => {
    const throwing = engine();
    const throwingSeen = subscribeAll(throwing, ENGINE_EVENTS);
    await assert.rejects(() => throwing.isAllowed({ principal, action: 'view', resource: brokenResource }));
    assert.deepEqual(throwingSeen.names(), ['request:start', 'request:error', 'request:end']);

    const denying = engine({ onError: 'deny' });
    const { events, names } = subscribeAll(denying, ENGINE_EVENTS);
    assert.equal(await denying.isAllowed({ principal, action: 'view', resource: brokenResource }), false);
    assert.deepEqual(names(), ['request:start', 'request:error', 'decision', 'request:end']);
    const decision = events[2].payload;
    assert.deepEqual(decision.actions, { view: Effect.Deny });
    assert.equal(decision.reason, 'evaluation-error');
    assert.equal(decision.errorName, 'Error');
    assert.equal(events[3].payload.success, false);

    // Per-resource fail-closed decisions inside a batch carry the marker too.
    events.length = 0;
    const response = await denying.checkResources({
      principal,
      resources: [
        { resource: brokenResource, actions: ['view'] },
        { resource, actions: ['view'] },
      ],
    });
    assert.deepEqual(
      response.results.map((result) => result.actions.view),
      [Effect.Deny, Effect.Allow],
    );
    assert.deepEqual(names(), ['request:start', 'decision', 'decision', 'request:end']);
    assert.equal(events[1].payload.reason, 'evaluation-error');
    assert.equal('reason' in events[2].payload, false);
    assert.equal(events[3].payload.success, true);
  });

  it('never leaks attribute bags or Error objects, and hands out fresh objects', async () => {
    const kerberos = engine({ onError: 'deny' });
    const { events } = subscribeAll(kerberos, ENGINE_EVENTS);
    await kerberos.isAllowed({ principal, action: 'view', resource });
    await kerberos.isAllowed({ principal, action: 'view', resource: brokenResource });
    for (const { payload } of events) {
      assert.equal(JSON.stringify(payload).includes('do-not-leak'), false);
      assert.equal(JSON.stringify(payload).includes('owner'), false);
      if ('error' in payload) assert.equal(typeof payload.error, 'string');
    }
    const first = events.find((event) => event.name === 'decision').payload;
    first.principal.roles.push('MUTATED');
    assert.deepEqual(principal.roles, ['USER']);
    events.length = 0;
    await kerberos.isAllowed({ principal, action: 'view', resource });
    assert.deepEqual(events.find((event) => event.name === 'decision').payload.principal.roles, ['USER']);
  });
});

describe('engine events — cache and relations', () => {
  const key = 'resource:expense:default:';

  it('emits cache:miss / cache:hit / cache:error (no callId on the policy-cache path)', async () => {
    const missing = new Kerberos([], [], { cache: { async get() {} }, cacheRetry: { attempts: 1 } });
    const miss = subscribeAll(missing, ENGINE_EVENTS);
    assert.equal(await missing.isAllowed({ principal, action: 'view', resource }), false);
    assert.ok(miss.events.some((event) => event.name === 'cache:miss' && event.payload.key === key));
    assert.equal('callId' in miss.events.find((event) => event.name === 'cache:miss').payload, false);

    const hitting = new Kerberos([], [], {
      cache: {
        async get(k) {
          return k === key ? expensePolicy : undefined;
        },
      },
      cacheRetry: { attempts: 1 },
    });
    const hit = subscribeAll(hitting, ENGINE_EVENTS);
    assert.equal(await hitting.isAllowed({ principal, action: 'view', resource }), true);
    assert.deepEqual(
      hit.events.filter((event) => event.name === 'cache:hit').map((event) => event.payload),
      [{ key }],
    );

    const failing = new Kerberos([], [], {
      cache: {
        async get() {
          throw new Error('backend down');
        },
      },
      cacheRetry: { attempts: 1, onExhausted: 'miss' },
    });
    const failed = subscribeAll(failing, ENGINE_EVENTS);
    assert.equal(await failing.isAllowed({ principal, action: 'view', resource }), false);
    // Every chain read (principal policy first, then the resource policy)
    // fails and degrades to a miss, so one cache:error per key.
    const cacheError = failed.events.find((event) => event.name === 'cache:error' && event.payload.key === key).payload;
    assert.equal(cacheError.errorName, 'KerberosCacheError');
    assert.match(cacheError.error, /backend down/);

    const corrupt = new Kerberos([], [], {
      cache: {
        async get(k) {
          return k === key ? { not: 'a policy' } : undefined;
        },
      },
      cacheRetry: { attempts: 1 },
    });
    const corrupted = subscribeAll(corrupt, ENGINE_EVENTS);
    assert.equal(await corrupt.isAllowed({ principal, action: 'view', resource }), false);
    assert.equal(
      corrupted.events.find((event) => event.name === 'cache:error').payload.errorName,
      'KerberosCodecError',
    );
  });

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

  it('emits relations:resolved for list-first and check-fallback resolvers', async () => {
    const listing = new Kerberos(relationPolicies, relationDerivedRoles, {
      getCallId: () => 'call-rel',
      relations: {
        check: async () => true,
        list: async () => new Set(['viewer']),
      },
    });
    const listed = subscribeAll(listing, ENGINE_EVENTS);
    assert.equal(await listing.isAllowed({ principal, action: 'view', resource }), true);
    const resolved = listed.events.find((event) => event.name === 'relations:resolved').payload;
    assert.deepEqual(resolved, {
      callId: 'call-rel',
      principal: { id: 'sally', roles: ['USER'] },
      resource: { kind: 'expense', id: 'expense1' },
      relations: ['viewer'],
      granted: ['viewer'],
      mode: 'list',
      durationMs: resolved.durationMs,
    });
    assert.equal(typeof resolved.durationMs, 'number');

    const checking = new Kerberos(relationPolicies, relationDerivedRoles, {
      relations: { check: async () => false },
    });
    const checked = subscribeAll(checking, ENGINE_EVENTS);
    assert.equal(await checking.isAllowed({ principal, action: 'view', resource }), false);
    const viaCheck = checked.events.find((event) => event.name === 'relations:resolved').payload;
    assert.equal(viaCheck.mode, 'check');
    assert.deepEqual(viaCheck.granted, []);
  });
});

describe('RelationResolver events', () => {
  const schema = {
    relationSchema: {
      definitions: {
        user: {},
        doc: { relations: { viewer: ['user'] }, permissions: { view: 'viewer' } },
      },
    },
  };
  const tuples = [{ resource: 'doc:d1', relation: 'viewer', subject: 'user:sally' }];
  const RESOLVER_EVENTS = [
    'request:start',
    'request:end',
    'request:error',
    'relation:checked',
    'cache:hit',
    'cache:miss',
    'cache:error',
  ];

  it('check: request:start → relation:checked → request:end, correlated by callId', async () => {
    const resolver = new RelationResolver({ schema, tuples });
    const { events, names } = subscribeAll(resolver, RESOLVER_EVENTS);
    assert.equal(await resolver.check({ resource: 'doc:d1', permission: 'view', subject: 'user:sally' }), true);
    assert.deepEqual(names(), ['request:start', 'relation:checked', 'request:end']);
    const [start, checked, end] = events.map((event) => event.payload);
    assert.equal(typeof start.callId, 'string');
    assert.deepEqual(start, { callId: start.callId, kind: 'check' });
    assert.deepEqual(checked, {
      callId: start.callId,
      kind: 'check',
      resource: { kind: 'doc', id: 'd1' },
      relation: 'view',
      subject: 'user:sally',
      allowed: true,
    });
    assert.equal(end.success, true);

    events.length = 0;
    await resolver.list(
      { resource: 'doc:d1', relations: ['view', 'viewer'], subject: 'user:sally' },
      { callId: 'engine-1' },
    );
    assert.deepEqual(names(), ['request:start', 'relation:checked', 'relation:checked', 'request:end']);
    for (const { payload } of events) assert.equal(payload.callId, 'engine-1');
    assert.deepEqual(
      events.filter((event) => event.name === 'relation:checked').map((event) => event.payload.relation),
      ['view', 'viewer'],
    );
  });

  it('cache:* events carry kind "relation" and the call id; failures raise request:error', async () => {
    const resolver = new RelationResolver({
      schema,
      tuples,
      cache: {
        async get(key) {
          if (key.includes('bad')) throw new Error('down');
          if (key.includes('corrupt')) return { not: 'an array' };
          if (key.includes('hit')) return ['user:sally'];
          return undefined;
        },
      },
      cacheRetry: { attempts: 1 },
    });
    const { events, names } = subscribeAll(resolver, RESOLVER_EVENTS);

    assert.equal(
      await resolver.check({ resource: 'doc:d2', permission: 'view', subject: 'user:sally' }, { callId: 'c1' }),
      false,
    );
    assert.deepEqual(names(), ['request:start', 'cache:miss', 'relation:checked', 'request:end']);
    assert.deepEqual(events[1].payload, { key: 'rel:doc:d2:viewer', kind: 'relation', callId: 'c1' });

    events.length = 0;
    assert.equal(await resolver.check({ resource: 'doc:hit', permission: 'view', subject: 'user:sally' }), true);
    assert.equal(events[1].name, 'cache:hit');

    events.length = 0;
    await assert.rejects(() => resolver.check({ resource: 'doc:bad', permission: 'view', subject: 'user:sally' }));
    assert.deepEqual(names(), ['request:start', 'cache:error', 'request:error', 'request:end']);
    assert.equal(events[1].payload.errorName, 'KerberosCacheError');
    assert.equal(events[2].payload.errorName, 'KerberosCacheError');
    assert.equal(events[3].payload.success, false);

    events.length = 0;
    await assert.rejects(() => resolver.check({ resource: 'doc:corrupt', permission: 'view', subject: 'user:sally' }));
    assert.equal(events[1].name, 'cache:error');
    assert.equal(events[1].payload.errorName, 'KerberosCodecError');
  });

  it('a throwing listener is swallowed, counted once per sink, and never affects resolution', async () => {
    const resolver = new RelationResolver({ schema, tuples });
    resolver.on('relation:checked', () => {
      throw new Error('listener boom');
    });
    const warnings = await withPatchedWarn(async () => {
      for (let i = 0; i < 2; i++) {
        assert.equal(await resolver.check({ resource: 'doc:d1', permission: 'view', subject: 'user:sally' }), true);
        await tick();
      }
    });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /relations: the event listener threw/);
  });

  it('the diagnostics logger failures are counted under the logger sink (warned once)', async () => {
    const resolver = new RelationResolver({
      schema,
      tuples,
      cache: {
        async get() {
          return { not: 'an array' };
        },
      },
      cacheRetry: { attempts: 1 },
      logger: {
        info() {},
        debug() {},
        error() {
          throw new Error('sink down');
        },
      },
    });
    const warnings = await withPatchedWarn(async () => {
      for (let i = 0; i < 2; i++) {
        await assert.rejects(() => resolver.check({ resource: 'doc:d2', permission: 'view', subject: 'user:sally' }));
      }
    });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /diagnostics logger threw/);
  });
});

describe('engine events — listener safety and subscription API', () => {
  it('a throwing listener never affects the decision; warned once per sink', async () => {
    const kerberos = engine();
    kerberos.on('decision', () => {
      throw new Error('listener boom');
    });
    const warnings = await withPatchedWarn(async () => {
      for (let i = 0; i < 3; i++) {
        assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
        await tick();
      }
    });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /event listener threw and was swallowed/);
  });

  it('a rejecting async listener is contained (no unhandled rejection)', async () => {
    const unhandled = [];
    const onUnhandled = (reason) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    try {
      const kerberos = engine();
      kerberos.on('request:end', async () => {
        await tick();
        throw new Error('async listener boom');
      });
      await withPatchedWarn(async () => {
        assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
        await tick();
        await tick();
      });
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
    assert.deepEqual(unhandled, []);
  });

  it('on/once/off/removeAllListeners are chainable; listenerCount reflects subscriptions', async () => {
    const kerberos = engine();
    const seen = [];
    const listener = () => seen.push('on');
    const chained = kerberos
      .on('decision', listener)
      .once('decision', () => seen.push('once'))
      .on('plan', listener);
    assert.equal(chained, kerberos);
    assert.equal(kerberos.listenerCount('decision'), 2);
    await kerberos.isAllowed({ principal, action: 'view', resource });
    await kerberos.isAllowed({ principal, action: 'view', resource });
    assert.deepEqual(seen, ['on', 'once', 'on']);

    assert.equal(kerberos.off('decision', listener), kerberos);
    assert.equal(kerberos.listenerCount('decision'), 0);
    assert.equal(kerberos.removeAllListeners('plan'), kerberos);
    assert.equal(kerberos.listenerCount('plan'), 0);
    kerberos.on('plan', listener).on('decision', listener);
    assert.equal(kerberos.removeAllListeners(), kerberos);
    assert.equal(kerberos.listenerCount('plan') + kerberos.listenerCount('decision'), 0);

    assert.throws(() => kerberos.on('decision', 'nope'), TypeError);
    assert.throws(() => kerberos.off('decision'), TypeError);
  });
});
