const { describe, it } = require('node:test');
const assert = require('node:assert').strict;
const { z } = require('zod');

const { Kerberos, Effect, KerberosHookError, KerberosValidationError } = require('../src/index.js');
const { RelationResolver } = require('../relations.js');
const { ENGINE_HOOKS, RESOLVER_HOOKS, createHookRunner } = require('../src/hooks.js');

const policies = [
  {
    resourcePolicy: {
      version: 'default',
      resource: 'expense',
      rules: [{ name: 'user-view', actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
    },
  },
  {
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
  },
];

const principal = { id: 'sally', roles: ['USER'] };
const resource = { id: 'expense1', kind: 'expense' };
const brokenResource = { id: 'b1', kind: 'broken' };

function recorder(overrides = {}) {
  const calls = [];
  const hooks = {};
  for (const name of ENGINE_HOOKS) {
    hooks[name] = (...args) => {
      calls.push([name, ...args]);
      if (overrides[name]) return overrides[name](...args);
      return undefined;
    };
  }
  return { calls, hooks, names: () => calls.map((call) => call[0]) };
}

function engine(hooks, options = {}) {
  return new Kerberos(policies, [], { hooks, getCallId: () => 'call-hooks', ...options });
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

describe('createHookRunner', () => {
  it('returns the disabled runner for null/undefined/empty/all-null hooks', async () => {
    for (const hooks of [undefined, null, {}, { beforeRequest: null, onError: undefined }]) {
      const runner = createHookRunner(hooks);
      assert.equal(runner.enabled, false);
      assert.equal(runner.hasResourceHooks, false);
      for (const name of ENGINE_HOOKS) assert.equal(runner[name](), undefined);
    }
  });

  it('rejects malformed options with a TypeError', () => {
    assert.throws(() => createHookRunner('nope'), TypeError);
    assert.throws(() => createHookRunner([]), TypeError);
    assert.throws(() => createHookRunner({ beforeAll() {} }), /unknown hook "beforeAll"/);
    assert.throws(() => createHookRunner({ beforeRequest: 42 }), /"beforeRequest" must be a function/);
    assert.throws(() => createHookRunner({ beforeResource() {} }, { allowed: RESOLVER_HOOKS }), /unknown hook/);
    assert.throws(() => new Kerberos(policies, [], { hooks: { afterEach() {} } }), TypeError);
  });

  it('exposes hasResourceHooks only for per-resource hooks', () => {
    assert.equal(createHookRunner({ beforeRequest() {} }).hasResourceHooks, false);
    assert.equal(createHookRunner({ afterResource() {} }).hasResourceHooks, true);
    assert.equal(createHookRunner({ beforeResource() {} }).enabled, true);
  });

  it('wraps throwing hooks in KerberosHookError and swallows the failure-path ones', async () => {
    const swallowed = [];
    const boom = new Error('boom');
    const plainReason = 'not-an-error';
    const runner = createHookRunner(
      {
        beforeRequest() {
          throw boom;
        },
        afterRequest() {
          throw boom;
        },
        // A rejecting (non-Error) reason exercises the same swallow path.
        onError: async () => {
          // oxlint-disable-next-line no-throw-literal -- a non-Error reason exercises the String(error) branch
          throw plainReason;
        },
      },
      { onSwallowed: (error, name) => swallowed.push([name, error]) },
    );
    await assert.rejects(
      () => runner.beforeRequest({}),
      (error) =>
        error instanceof KerberosHookError &&
        error.hook === 'beforeRequest' &&
        error.cause === boom &&
        /The beforeRequest hook failed: boom/.test(error.message),
    );
    await assert.rejects(() => runner.afterRequest({}, { success: true }), { hook: 'afterRequest' });
    await runner.afterRequest({}, { success: false });
    await runner.onError(boom, {});
    // Unconfigured hooks resolve without calling anything.
    await runner.beforeResource({}, {});
    await runner.afterResource({}, {}, {});
    assert.deepEqual(swallowed, [
      ['afterRequest', boom],
      ['onError', 'not-an-error'],
    ]);
  });

  it('keeps swallowing when onSwallowed itself throws, and formats non-Error causes', async () => {
    const plainReason = 'plain string';
    const runner = createHookRunner(
      {
        onError() {
          throw new Error('x');
        },
        beforeRequest: async () => {
          // oxlint-disable-next-line no-throw-literal -- a non-Error reason exercises the String(error) branch
          throw plainReason;
        },
      },
      {
        onSwallowed() {
          throw new Error('reporter down');
        },
      },
    );
    await runner.onError(new Error('original'), {});
    await assert.rejects(() => runner.beforeRequest({}), /The beforeRequest hook failed: plain string/);
    // No onSwallowed at all is fine too.
    await createHookRunner({
      onError() {
        throw new Error('x');
      },
    }).onError(new Error('original'), {});
  });
});

describe('engine hooks — order and context', () => {
  it('isAllowed: beforeRequest → beforeResource → afterResource → afterRequest with shared ctx', async () => {
    const { calls, hooks, names } = recorder();
    const kerberos = engine(hooks);

    assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource, reqId: 'r1' }), true);
    assert.deepEqual(names(), ['beforeRequest', 'beforeResource', 'afterResource', 'afterRequest']);

    const [, ctx] = calls[0];
    assert.equal(ctx.reqKind, 'IsAllowed');
    assert.equal(ctx.callId, 'call-hooks');
    assert.equal(ctx.reqId, 'r1');
    assert.equal(ctx.args.principal.id, 'sally');
    assert.equal(ctx.args.action, 'view');
    for (const call of calls) assert.equal(call[1] === ctx || call[2] === ctx, true, 'ctx object is shared');

    const [, , info] = calls[1];
    assert.deepEqual(info, { index: 0, total: 1, resource: ctx.args.resource, actions: ['view'] });
    const [, , , result] = calls[2];
    assert.deepEqual(result.actions, { view: Effect.Allow });
    assert.deepEqual(result.outputs, []);
    assert.ok(result.meta);
    const [, , summary] = calls[3];
    assert.equal(summary.success, true);
    assert.equal(typeof summary.durationMs, 'number');
    assert.equal('error' in summary, false);
  });

  it('checkResources: one beforeResource/afterResource pair per resource, canonical EFFECT_* results', async () => {
    const { calls, hooks, names } = recorder();
    const kerberos = engine(hooks);

    const response = await kerberos.checkResources(
      {
        principal,
        resources: [
          { resource, actions: ['view'] },
          { resource: { id: 'expense2', kind: 'expense' }, actions: ['view', 'delete'] },
        ],
      },
      true,
    );
    assert.deepEqual(response.results[1].actions, { view: true, delete: false });
    assert.deepEqual(names(), [
      'beforeRequest',
      'beforeResource',
      'beforeResource',
      'afterResource',
      'afterResource',
      'afterRequest',
    ]);
    const infos = calls.filter((call) => call[0] === 'beforeResource').map((call) => call[2]);
    assert.deepEqual(
      infos.map((info) => [info.index, info.total, info.resource.id, info.actions]),
      [
        [0, 2, 'expense1', ['view']],
        [1, 2, 'expense2', ['view', 'delete']],
      ],
    );
    const results = calls.filter((call) => call[0] === 'afterResource').map((call) => call[3].actions);
    assert.deepEqual(results, [{ view: Effect.Allow }, { view: Effect.Allow, delete: Effect.Deny }]);
    assert.equal(calls.filter((call) => call[0] === 'afterRequest').length, 1);
  });

  it('planResources: request-level hooks only', async () => {
    const { calls, hooks, names } = recorder();
    const kerberos = engine(hooks);
    const plan = await kerberos.planResources({ principal, resource: { kind: 'expense' }, action: 'view' });
    assert.equal(plan.filter.kind, 'KIND_ALWAYS_ALLOWED');
    assert.deepEqual(names(), ['beforeRequest', 'afterRequest']);
    assert.equal(calls[0][1].reqKind, 'PlanResources');
    assert.equal(calls[0][1].args.action, 'view');
  });

  it('hands hooks the VALIDATED arguments (the Zod output, not the raw input)', async () => {
    const { calls, hooks } = recorder();
    const kerberos = engine(hooks, { z });
    const args = { principal, action: 'view', resource };
    await kerberos.isAllowed(args);
    const ctx = calls[0][1];
    assert.notEqual(ctx.args, args);
    assert.deepEqual(ctx.args.principal, principal);
  });

  it('fires no hook at all for malformed arguments (KerberosValidationError)', async () => {
    const { calls, hooks } = recorder();
    const kerberos = engine(hooks, { z, onError: 'deny' });
    await assert.rejects(() => kerberos.isAllowed({ principal }), KerberosValidationError);
    await assert.rejects(() => kerberos.checkResources({ principal }), KerberosValidationError);
    await assert.rejects(
      () => kerberos.planResources({ principal, resource: { kind: 'expense' }, actions: [] }),
      KerberosValidationError,
    );
    assert.deepEqual(calls, []);
  });

  it('is inert with hooks: {} (disabled runner) and keeps the request-level hooks off the resource path', async () => {
    const kerberos = engine({});
    assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
    const seen = [];
    const requestOnly = engine({ beforeRequest: () => seen.push('before') });
    assert.equal(await requestOnly.isAllowed({ principal, action: 'view', resource }), true);
    assert.deepEqual(seen, ['before']);
  });
});

describe('engine hooks — error contract', () => {
  it('evaluation error: onError then afterRequest({ success: false, error }) — throw mode', async () => {
    const { calls, hooks, names } = recorder();
    const kerberos = engine(hooks);
    await assert.rejects(() => kerberos.isAllowed({ principal, action: 'view', resource: brokenResource }), {
      message: 'condition boom',
    });
    assert.deepEqual(names(), ['beforeRequest', 'beforeResource', 'onError', 'afterRequest']);
    const [, error, ctx] = calls[2];
    assert.equal(error.message, 'condition boom');
    assert.equal(ctx.reqKind, 'IsAllowed');
    const [, , summary] = calls[3];
    assert.equal(summary.success, false);
    assert.equal(summary.error, error);
    assert.equal('failClosed' in summary, false);
  });

  it("evaluation error under onError: 'deny': fail-closed result, summary.failClosed", async () => {
    const { calls, hooks, names } = recorder();
    const kerberos = engine(hooks, { onError: 'deny' });
    assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource: brokenResource }), false);
    assert.deepEqual(names(), ['beforeRequest', 'beforeResource', 'onError', 'afterRequest']);
    const [, , summary] = calls[3];
    assert.deepEqual([summary.success, summary.failClosed, summary.error.message], [false, true, 'condition boom']);
  });

  it('a throwing beforeRequest vetoes the request as KerberosHookError (throw) or a fail-closed result (deny)', async () => {
    const boom = new Error('veto');
    const { calls, hooks, names } = recorder({
      beforeRequest() {
        throw boom;
      },
    });
    const throwing = engine(hooks);
    await assert.rejects(
      () => throwing.isAllowed({ principal, action: 'view', resource }),
      (error) => error instanceof KerberosHookError && error.hook === 'beforeRequest' && error.cause === boom,
    );
    assert.deepEqual(names(), ['beforeRequest', 'onError', 'afterRequest']);
    assert.equal(calls[1][1].hook, 'beforeRequest');
    assert.equal(calls[2][2].success, false);

    calls.length = 0;
    const denying = engine(hooks, { onError: 'deny' });
    assert.equal(await denying.isAllowed({ principal, action: 'view', resource }), false);
    const batch = await denying.checkResources({ principal, resources: [{ resource, actions: ['view'] }] });
    assert.deepEqual(batch.results[0].actions, { view: Effect.Deny });
    const plan = await denying.planResources({ principal, resource: { kind: 'expense' }, action: 'view' });
    assert.equal(plan.filter.kind, 'KIND_ALWAYS_DENIED');
    assert.deepEqual(names(), [
      'beforeRequest',
      'onError',
      'afterRequest',
      'beforeRequest',
      'onError',
      'afterRequest',
      'beforeRequest',
      'onError',
      'afterRequest',
    ]);
    for (const call of calls.filter((entry) => entry[0] === 'afterRequest')) assert.equal(call[2].failClosed, true);
  });

  it('a throwing success-path afterRequest follows onError; the onError hook is NOT invoked and afterRequest runs once', async () => {
    const { calls, hooks, names } = recorder({
      afterRequest() {
        throw new Error('after boom');
      },
    });
    await assert.rejects(
      () => engine(hooks).isAllowed({ principal, action: 'view', resource }),
      (error) => error instanceof KerberosHookError && error.hook === 'afterRequest',
    );
    assert.deepEqual(names(), ['beforeRequest', 'beforeResource', 'afterResource', 'afterRequest']);

    calls.length = 0;
    assert.equal(await engine(hooks, { onError: 'deny' }).isAllowed({ principal, action: 'view', resource }), false);
    assert.deepEqual(names(), ['beforeRequest', 'beforeResource', 'afterResource', 'afterRequest']);
  });

  it('a throwing afterRequest after a failed request is swallowed (warned once) and never masks the cause', async () => {
    const { hooks } = recorder({
      afterRequest(ctx, summary) {
        if (!summary.success) throw new Error('cleanup boom');
      },
    });
    const kerberos = engine(hooks);
    const warnings = await withPatchedWarn(async () => {
      for (let i = 0; i < 2; i++) {
        await assert.rejects(() => kerberos.isAllowed({ principal, action: 'view', resource: brokenResource }), {
          message: 'condition boom',
        });
      }
    });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /lifecycle hook threw and was swallowed/);
  });

  it('a throwing onError hook is swallowed and the original error still surfaces', async () => {
    const { hooks, names } = recorder({
      onError() {
        throw new Error('handler boom');
      },
    });
    await withPatchedWarn(async () => {
      await assert.rejects(() => engine(hooks).isAllowed({ principal, action: 'view', resource: brokenResource }), {
        message: 'condition boom',
      });
    });
    assert.deepEqual(names(), ['beforeRequest', 'beforeResource', 'onError', 'afterRequest']);
  });

  it('checkResources isolates a throwing per-resource hook to that resource', async () => {
    const { calls, hooks } = recorder({
      beforeResource(ctx, info) {
        if (info.index === 0) throw new Error('resource veto');
      },
      afterResource(ctx, info) {
        if (info.index === 2) throw new Error('after veto');
      },
    });
    const kerberos = engine(hooks);
    const response = await kerberos.checkResources({
      principal,
      includeMeta: true,
      resources: [
        { resource, actions: ['view'] },
        { resource: { id: 'expense2', kind: 'expense' }, actions: ['view'] },
        { resource: { id: 'expense3', kind: 'expense' }, actions: ['view'] },
      ],
    });
    assert.deepEqual(
      response.results.map((result) => result.actions.view),
      [Effect.Deny, Effect.Allow, Effect.Deny],
    );
    assert.deepEqual(response.results[0].meta.actions.view, {
      reason: 'evaluation-error',
      errorName: 'KerberosHookError',
    });
    assert.deepEqual(response.results[2].meta.actions.view, {
      reason: 'evaluation-error',
      errorName: 'KerberosHookError',
    });
    // The batch itself succeeded: no onError, afterRequest sees success.
    const names = calls.map((call) => call[0]);
    assert.equal(names.includes('onError'), false);
    assert.equal(calls.at(-1)[0], 'afterRequest');
    assert.equal(calls.at(-1)[2].success, true);
  });

  it('isAllowed routes a throwing per-resource hook through onError semantics', async () => {
    const { hooks } = recorder({
      afterResource() {
        throw new Error('after veto');
      },
    });
    await assert.rejects(
      () => engine(hooks).isAllowed({ principal, action: 'view', resource }),
      (error) => error instanceof KerberosHookError && error.hook === 'afterResource',
    );
    assert.equal(await engine(hooks, { onError: 'deny' }).isAllowed({ principal, action: 'view', resource }), false);
  });

  it('per-resource hooks over the async driver (cache configured) behave the same', async () => {
    const { hooks, names } = recorder();
    const kerberos = engine(hooks, { cache: { async get() {} }, cacheRetry: { attempts: 1 } });
    const response = await kerberos.checkResources({
      principal,
      resources: [
        { resource, actions: ['view'] },
        { resource: brokenResource, actions: ['view'] },
      ],
    });
    assert.deepEqual(
      response.results.map((result) => result.actions.view),
      [Effect.Allow, Effect.Deny],
    );
    assert.deepEqual(names(), ['beforeRequest', 'beforeResource', 'beforeResource', 'afterResource', 'afterRequest']);
  });
});

describe('RelationResolver hooks', () => {
  const schema = {
    relationSchema: {
      definitions: {
        user: {},
        doc: { relations: { viewer: ['user'] }, permissions: { view: 'viewer' } },
      },
    },
  };
  const tuples = [{ resource: 'doc:d1', relation: 'viewer', subject: 'user:sally' }];

  function resolverRecorder(overrides = {}) {
    const calls = [];
    const hooks = {};
    for (const name of RESOLVER_HOOKS) {
      hooks[name] = (...args) => {
        calls.push([name, ...args]);
        if (overrides[name]) return overrides[name](...args);
        return undefined;
      };
    }
    return { calls, hooks, names: () => calls.map((call) => call[0]) };
  }

  it('runs beforeRequest/afterRequest around every public method with kind + callId', async () => {
    const { calls, hooks, names } = resolverRecorder();
    const resolver = new RelationResolver({ schema, tuples, hooks });

    assert.equal(await resolver.check({ resource: 'doc:d1', permission: 'view', subject: 'user:sally' }), true);
    assert.deepEqual(names(), ['beforeRequest', 'afterRequest']);
    const ctx = calls[0][1];
    assert.equal(ctx.kind, 'check');
    assert.equal(typeof ctx.callId, 'string');
    assert.equal(ctx.args.permission, 'view');
    assert.equal(calls[1][1], ctx);
    assert.equal(calls[1][2].success, true);

    calls.length = 0;
    await resolver.list({ resource: 'doc:d1', relations: ['view'], subject: 'user:sally' }, { callId: 'engine-call' });
    await resolver.lookupSubjects({ resource: 'doc:d1', permission: 'view' });
    await resolver.lookupResources({ subject: 'user:sally', permission: 'view', resourceType: 'doc' });
    assert.deepEqual(
      calls.filter((call) => call[0] === 'beforeRequest').map((call) => call[1].kind),
      ['list', 'lookupSubjects', 'lookupResources'],
    );
    assert.equal(calls[0][1].callId, 'engine-call');
  });

  it('rejects unknown resolver hooks (only beforeRequest/afterRequest/onError)', () => {
    assert.throws(() => new RelationResolver({ schema, tuples, hooks: { beforeResource() {} } }), TypeError);
  });

  it('always propagates KerberosHookError (no onError option); the engine converts it under deny', async () => {
    const { calls, hooks, names } = resolverRecorder({
      beforeRequest() {
        throw new Error('resolver veto');
      },
    });
    const resolver = new RelationResolver({ schema, tuples, hooks });
    await assert.rejects(
      () => resolver.check({ resource: 'doc:d1', permission: 'view', subject: 'user:sally' }),
      (error) => error instanceof KerberosHookError && error.hook === 'beforeRequest',
    );
    assert.deepEqual(names(), ['beforeRequest', 'onError', 'afterRequest']);
    assert.equal(calls[2][2].success, false);

    const relationPolicies = [
      {
        resourcePolicy: {
          version: 'default',
          resource: 'doc',
          importDerivedRoles: ['rel_roles'],
          rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['VIEWER'] }],
        },
      },
    ];
    const derived = [{ name: 'rel_roles', definitions: [{ name: 'VIEWER', relation: 'view' }] }];
    const denying = new Kerberos(relationPolicies, derived, { relations: resolver, onError: 'deny' });
    assert.equal(await denying.isAllowed({ principal, action: 'view', resource: { id: 'd1', kind: 'doc' } }), false);
    const throwing = new Kerberos(relationPolicies, derived, { relations: resolver });
    await assert.rejects(
      () => throwing.isAllowed({ principal, action: 'view', resource: { id: 'd1', kind: 'doc' } }),
      KerberosHookError,
    );
  });

  it('swallows a failing afterRequest after a failed call and warns once', async () => {
    const { hooks } = resolverRecorder({
      afterRequest(ctx, summary) {
        if (!summary.success) throw new Error('cleanup boom');
      },
      onError() {
        throw new Error('handler boom');
      },
    });
    // The failure must happen AFTER beforeRequest (validation errors fire no
    // hooks): a cache-backed read of a tuple document that is not static.
    const resolver = new RelationResolver({
      schema,
      tuples,
      hooks,
      cache: {
        async get() {
          throw new Error('cache down');
        },
      },
      cacheRetry: { attempts: 1 },
    });
    const warnings = await withPatchedWarn(async () => {
      for (let i = 0; i < 2; i++) {
        await assert.rejects(() => resolver.check({ resource: 'doc:d2', permission: 'view', subject: 'user:sally' }), {
          name: 'KerberosCacheError',
        });
      }
    });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /relations: the lifecycle hook threw/);
  });

  it('a throwing success-path afterRequest surfaces as KerberosHookError', async () => {
    const resolver = new RelationResolver({
      schema,
      tuples,
      hooks: {
        afterRequest() {
          throw new Error('after boom');
        },
      },
    });
    await assert.rejects(
      () => resolver.check({ resource: 'doc:d1', permission: 'view', subject: 'user:sally' }),
      (error) => error instanceof KerberosHookError && error.hook === 'afterRequest',
    );
  });
});
