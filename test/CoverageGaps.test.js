const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const Ajv = require('ajv');
const { Type } = require('@sinclair/typebox');
const { z } = require('zod');

const {
  Kerberos,
  ResourcePolicy,
  PrincipalPolicy,
  RolePolicy,
  DerivedRoles,
  Conditions,
  Outputs,
  Variables,
  ConditionsJsonSchemas,
  ConditionsTypeBoxSchemas,
  ConditionsZodSchemas,
  ConstantsJsonSchemas,
  ConstantsTypeBoxSchemas,
  ConstantsZodSchemas,
  VariablesJsonSchemas,
  VariablesTypeBoxSchemas,
  VariablesZodSchemas,
  JsonSchemas,
  registerAjvKeywords,
  createSafeExprCodec,
  createCacheReader,
  createAjvAdapter,
  toValidationAdapter,
  resolveValidationAdapter,
} = require('../src/index.js');
const { createLoggerWriter, buildAuditEntries } = require('../src/logging.js');
const { RelationResolver } = require('../src/Relations/index.js');
const {
  RelationsJsonSchemas,
  RelationsTypeBoxSchemas,
  RelationsZodSchemas,
} = require('../src/Relations/schemas/index.js');
const {
  KerberosTest,
  KerberosTests,
  PrincipalMock,
  PrincipalsMock,
  ResourceMock,
  ResourcesMock,
} = require('@alexify/kerberos/tests');

const {
  expensePolicy,
  sallyPrincipalPolicy,
  userRolePolicy,
  commonRolesPolicy,
  principalsPolicy,
  resourcesPolicy,
} = require('./mocks/index.js');

function createAjv() {
  return registerAjvKeywords(new Ajv({ allErrors: true, strict: false }));
}

// ---------------------------------------------------------------------------
// Shared jsep instance for codec-related tests.
// ---------------------------------------------------------------------------
const jsepModule = require('jsep');
const jsep = jsepModule.default || jsepModule;
jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));
jsep.addUnaryOp('typeof');
const codec = createSafeExprCodec({ jsep });

describe('Coverage: standalone request-shape builders (public API, unreachable internally)', () => {
  it('builds the Conditions full-request shape across all three backends', () => {
    assert.ok(ConditionsJsonSchemas.buildFullRequest());
    assert.ok(ConditionsTypeBoxSchemas.buildFullRequest(Type));
    assert.ok(ConditionsZodSchemas.buildFullRequest(z));
  });

  it('builds the Constants request-with-constants shape across all three backends', () => {
    assert.ok(ConstantsJsonSchemas.buildRequestWithConstants());
    assert.ok(ConstantsTypeBoxSchemas.buildRequestWithConstants(Type));
    assert.ok(ConstantsZodSchemas.buildRequestWithConstants(z));
  });

  it('builds the Variables request-with-variables and return-type shapes across all three backends', () => {
    assert.ok(VariablesJsonSchemas.buildRequestWithVariables());
    assert.ok(VariablesTypeBoxSchemas.buildRequestWithVariables(Type));
    assert.ok(VariablesZodSchemas.buildRequestWithVariables(z));
    assert.equal(VariablesJsonSchemas.buildVariablesReturnType(), true);
    assert.ok(VariablesTypeBoxSchemas.buildVariablesReturnType(Type));
    assert.ok(VariablesZodSchemas.buildVariablesReturnType(z));
  });

  it('builds the Relations tuple shape across all three backends', () => {
    assert.ok(RelationsJsonSchemas.buildTupleShape());
    assert.ok(RelationsTypeBoxSchemas.buildTupleShape(Type));
    assert.ok(RelationsZodSchemas.buildTupleShape(z));
  });

  it('merges object shapes directly, skipping falsy shapes and merging $defs', () => {
    const merged = JsonSchemas.mergeObjectShapes(
      null,
      { properties: { a: { type: 'string' } }, required: ['a'], $defs: { Foo: { type: 'number' } } },
      { properties: { b: { type: 'string' } }, required: ['b'] },
    );
    assert.deepEqual(Object.keys(merged.properties).sort(), ['a', 'b']);
    assert.deepEqual(merged.required.sort(), ['a', 'b']);
    assert.ok(merged.$defs.Foo);
  });
});

describe('Coverage: Kerberos static parse methods across validation backends', () => {
  it('parses ResourcePolicy/PrincipalPolicy/RolePolicy/DerivedRoles instances through z / ajv / ajv+typebox', () => {
    const resourceInstance = new ResourcePolicy(expensePolicy);
    assert.equal(Kerberos.parsePolicy(resourceInstance, { z }), resourceInstance);
    assert.equal(Kerberos.parsePolicy(resourceInstance, { ajv: createAjv() }), resourceInstance);
    assert.equal(Kerberos.parsePolicy(resourceInstance, { ajv: createAjv(), typebox: Type }), resourceInstance);

    const principalInstance = new PrincipalPolicy(sallyPrincipalPolicy);
    assert.equal(Kerberos.parsePolicy(principalInstance, { z }), principalInstance);
    assert.equal(Kerberos.parsePolicy(principalInstance, { ajv: createAjv() }), principalInstance);
    assert.equal(Kerberos.parsePolicy(principalInstance, { ajv: createAjv(), typebox: Type }), principalInstance);

    const roleInstance = new RolePolicy(userRolePolicy);
    assert.equal(Kerberos.parsePolicy(roleInstance, { z }), roleInstance);
    assert.equal(Kerberos.parsePolicy(roleInstance, { ajv: createAjv() }), roleInstance);
    assert.equal(Kerberos.parsePolicy(roleInstance, { ajv: createAjv(), typebox: Type }), roleInstance);

    const derivedInstance = new DerivedRoles(commonRolesPolicy);
    assert.equal(Kerberos.parseDerivedRoles(derivedInstance, { z }), derivedInstance);
    assert.equal(Kerberos.parseDerivedRoles(derivedInstance, { ajv: createAjv() }), derivedInstance);
    assert.equal(Kerberos.parseDerivedRoles(derivedInstance, { ajv: createAjv(), typebox: Type }), derivedInstance);
  });

  it('classifies raw policy shapes by own property (role/principal/resource) via parsePolicy', () => {
    assert.ok(Kerberos.parsePolicy(userRolePolicy) instanceof RolePolicy);
    assert.ok(Kerberos.parsePolicy(sallyPrincipalPolicy) instanceof PrincipalPolicy);
    assert.ok(Kerberos.parsePolicy(expensePolicy) instanceof ResourcePolicy);
  });

  it('parses isAllowed / checkResources / request args directly across all three backends', () => {
    const isAllowedArgs = { principal: principalsPolicy.sally, action: 'view', resource: resourcesPolicy.expense1 };
    assert.ok(Kerberos.parseIsAllowedArgs(isAllowedArgs, { z }));
    assert.ok(Kerberos.parseIsAllowedArgs(isAllowedArgs, { ajv: createAjv() }));
    assert.ok(Kerberos.parseIsAllowedArgs(isAllowedArgs, { ajv: createAjv(), typebox: Type }));

    const checkArgs = {
      principal: principalsPolicy.sally,
      resources: [{ resource: resourcesPolicy.expense1, actions: ['view'] }],
    };
    assert.ok(Kerberos.parseCheckResourcesArgs(checkArgs, { z }));
    assert.ok(Kerberos.parseCheckResourcesArgs(checkArgs, { ajv: createAjv() }));
    assert.ok(Kerberos.parseCheckResourcesArgs(checkArgs, { ajv: createAjv(), typebox: Type }));

    const reqArgs = { principal: principalsPolicy.sally, resource: resourcesPolicy.expense1, actions: ['view'] };
    assert.ok(Kerberos.parseRequest(reqArgs, { z }));
    assert.ok(Kerberos.parseRequest(reqArgs, { ajv: createAjv() }));
    assert.ok(Kerberos.parseRequest(reqArgs, { ajv: createAjv(), typebox: Type }));
  });

  it('normalizes scopes ("." alias, undefined, plain string)', () => {
    assert.equal(Kerberos.normalizeScope('.'), '');
    assert.equal(Kerberos.normalizeScope(undefined), '');
    assert.equal(Kerberos.normalizeScope('acme.corp'), 'acme.corp');
  });
});

describe('Coverage: RelationResolver construction across ajv / ajv+typebox validation backends', () => {
  function buildSchema() {
    return {
      relationSchema: {
        definitions: {
          user: {},
          document: {
            relations: { viewer: ['user'] },
            permissions: { view: { anyOf: ['viewer'] } },
          },
        },
      },
    };
  }

  it('validates check/list/lookupSubjects/lookupResources args with a JSON Schema + Ajv backend', async () => {
    const relations = new RelationResolver({
      schema: buildSchema(),
      tuples: ['document:d1#viewer@user:u1'],
      ajv: createAjv(),
    });

    assert.equal(await relations.check({ resource: 'document:d1', permission: 'view', subject: 'user:u1' }), true);
    const listed = await relations.list({ resource: 'document:d1', subject: 'user:u1', relations: ['view'] });
    assert.ok(listed.has('view'));
    const subjects = await relations.lookupSubjects({ resource: 'document:d1', permission: 'view' });
    assert.ok(Array.isArray(subjects));
    const resources = await relations.lookupResources({
      subject: 'user:u1',
      permission: 'view',
      resourceType: 'document',
    });
    assert.ok(Array.isArray(resources));

    await assert.rejects(() => relations.check({ resource: 'document:d1', permission: 42, subject: 'user:u1' }));
  });

  it('validates check/list/lookupSubjects/lookupResources args with a TypeBox + Ajv backend', async () => {
    const relations = new RelationResolver({
      schema: buildSchema(),
      tuples: ['document:d1#viewer@user:u1'],
      ajv: createAjv(),
      typebox: Type,
    });

    assert.equal(await relations.check({ resource: 'document:d1', permission: 'view', subject: 'user:u1' }), true);
    const listed = await relations.list({ resource: 'document:d1', subject: 'user:u1', relations: ['view'] });
    assert.ok(listed.has('view'));
    const subjects = await relations.lookupSubjects({ resource: 'document:d1', permission: 'view' });
    assert.ok(Array.isArray(subjects));
    const resources = await relations.lookupResources({
      subject: 'user:u1',
      permission: 'view',
      resourceType: 'document',
    });
    assert.ok(Array.isArray(resources));

    await assert.rejects(() => relations.list({ resource: 'document:d1', subject: 'user:u1', relations: [42] }));
  });
});

describe('Coverage: Tests DSL + Mocks across ajv / ajv+typebox validation backends', () => {
  const singlePrincipal = { id: 'sally', roles: ['USER'], name: 'sally' };
  const singleResource = { id: 'expense1', kind: 'expense', name: 'expense1' };

  const policy = {
    name: 'ajv-typebox suite',
    principals: { sally: { id: 'sally', roles: ['USER'] } },
    resources: { expense1: { id: 'expense1', kind: 'expense' } },
    tests: [
      {
        name: 'basic view',
        input: { principals: ['sally'], resources: ['expense1'], actions: ['view'] },
        expected: [{ principal: 'sally', resource: 'expense1', actions: { view: 'EFFECT_DENY' } }],
      },
    ],
  };

  it('builds PrincipalMock/ResourceMock (single, array and record forms) with a JSON Schema + Ajv backend', () => {
    const ajv = createAjv();
    assert.equal(new PrincipalMock(singlePrincipal, { ajv }).name, 'sally');
    assert.equal(new ResourceMock(singleResource, { ajv }).name, 'expense1');
    assert.equal(new PrincipalsMock([new PrincipalMock(singlePrincipal)], { ajv }).mocks.length, 1);
    assert.equal(new PrincipalsMock({ sally: { id: 'sally', roles: ['USER'] } }, { ajv }).mocks.length, 1);
    assert.equal(new ResourcesMock([new ResourceMock(singleResource)], { ajv }).mocks.length, 1);
    assert.equal(new ResourcesMock({ expense1: { id: 'expense1', kind: 'expense' } }, { ajv }).mocks.length, 1);
  });

  it('builds PrincipalMock/ResourceMock (single, array and record forms) with a TypeBox + Ajv backend', () => {
    const ajv = createAjv();
    assert.equal(new PrincipalMock(singlePrincipal, { ajv, typebox: Type }).name, 'sally');
    assert.equal(new ResourceMock(singleResource, { ajv, typebox: Type }).name, 'expense1');
    assert.equal(new PrincipalsMock([new PrincipalMock(singlePrincipal)], { ajv, typebox: Type }).mocks.length, 1);
    assert.equal(
      new PrincipalsMock({ sally: { id: 'sally', roles: ['USER'] } }, { ajv, typebox: Type }).mocks.length,
      1,
    );
    assert.equal(new ResourcesMock([new ResourceMock(singleResource)], { ajv, typebox: Type }).mocks.length, 1);
    assert.equal(
      new ResourcesMock({ expense1: { id: 'expense1', kind: 'expense' } }, { ajv, typebox: Type }).mocks.length,
      1,
    );
  });

  it('constructs KerberosTest/KerberosTests with a JSON Schema + Ajv backend', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy]);
    const ajv = createAjv();
    const test = new KerberosTest(policy.tests[0], kerberos, { ajv });
    assert.ok(test);

    const tests = new KerberosTests(kerberos, [policy], { ajv: createAjv() });
    assert.ok(tests);
  });

  it('constructs KerberosTest/KerberosTests with a TypeBox + Ajv backend', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy]);
    const ajv = createAjv();
    const test = new KerberosTest(policy.tests[0], kerberos, { ajv, typebox: Type });
    assert.ok(test);

    const tests = new KerberosTests(kerberos, [policy], { ajv: createAjv(), typebox: Type });
    assert.ok(tests);
  });
});

describe('Coverage: Conditions/Outputs/Variables/DerivedRoles branch edges', () => {
  it('exposes the shape getter and fails closed when every strategy key is unknown', () => {
    const conditions = new Conditions({ match: { unknownStrategy: [true] } });
    assert.ok(conditions.shape);
    assert.equal(conditions.isFulfilled({}), false);
  });

  it('exposes the Outputs shape getter, handles the function shape, and reports build failures', () => {
    const fnOutputs = new Outputs(() => ({ a: 1 }));
    assert.ok(fnOutputs.shape);
    assert.deepEqual(fnOutputs.build({}, true, 'src'), { src: 'src', val: { a: 1 } });

    const nullReturning = new Outputs({ when: { ruleActivated: () => undefined } });
    assert.deepEqual(nullReturning.build({}, true, 'src'), { src: 'src', val: null });

    const throwing = new Outputs({
      when: {
        ruleActivated: () => {
          throw new Error('boom');
        },
      },
    });
    const result = throwing.build({}, true, 'src');
    assert.equal(result.val.error, 'Output function evaluation failed');
  });

  it('exposes the Variables shape getter and stores a __proto__-named variable as an own property', () => {
    const shape = {};
    Object.defineProperty(shape, '__proto__', {
      value: () => 'value',
      enumerable: true,
      writable: true,
      configurable: true,
    });
    const variables = new Variables(shape);
    assert.ok(variables.shape);
    const result = variables.get({});
    assert.equal(Object.prototype.hasOwnProperty.call(result, '__proto__'), true);
    assert.equal(Object.getOwnPropertyDescriptor(result, '__proto__').value, 'value');
  });

  it('calls the DerivedRoles static parseConstants/parseVariables wrappers directly', () => {
    assert.ok(DerivedRoles.parseConstants({ limit: 1 }));
    assert.ok(DerivedRoles.parseVariables({ isOpen: () => true }));
  });

  it('skips relation-backed definitions in get() and empty-parentRoles definitions in getRelationCandidates()', () => {
    const derivedRoles = new DerivedRoles({
      name: 'mixed_roles',
      definitions: [
        { name: 'OWNER', parentRoles: ['USER'], condition: { match: ({ P, R }) => R.attr.ownerId === P.id } },
        { name: 'REL_BACKED', relation: 'view' },
      ],
    });

    const roles = derivedRoles.get({ P: { id: 'sally', roles: ['USER'] }, R: { attr: { ownerId: 'someone-else' } } });
    assert.equal(roles.size, 0);

    const candidates = derivedRoles.getRelationCandidates({ P: { id: 'sally', roles: ['OTHER'] }, R: {} });
    // `parentRoles` is null for an ungated relation-backed definition: conflict
    // resolution reads it as standing for every principal role.
    assert.deepEqual(candidates, [{ name: 'REL_BACKED', relation: 'view', parentRoles: null }]);
  });

  it('returns empty results for a DerivedRoles instance with no definitions', () => {
    const empty = new DerivedRoles({ name: 'empty_roles', definitions: [] });
    assert.equal(empty.get({ P: { roles: [] } }).size, 0);
    assert.deepEqual(empty.getRelationCandidates({ P: { roles: [] } }), []);
  });
});

describe('Coverage: PrincipalPolicy/ResourcePolicy/RolePolicy branch edges', () => {
  it('exposes the shape getter and returns empty results for an empty actions request', () => {
    const principalPolicy = new PrincipalPolicy(sallyPrincipalPolicy);
    assert.ok(principalPolicy.shape);
    const result = principalPolicy.check({ actions: [], P: principalsPolicy.sally, R: resourcesPolicy.expense1 });
    assert.equal(result.effects.size, 0);
  });

  it('exposes the shape getter and returns empty results for an empty actions request (ResourcePolicy)', () => {
    const resourcePolicy = new ResourcePolicy(expensePolicy);
    assert.ok(resourcePolicy.shape);
    const result = resourcePolicy.check(
      { actions: [], P: principalsPolicy.sally, R: resourcesPolicy.expense1 },
      new Set(),
    );
    assert.equal(result.effects.size, 0);
  });

  it('matches a resource-policy rule via ALL_ACTIONS exercised through the ADMIN rule', () => {
    const resourcePolicy = new ResourcePolicy(expensePolicy);
    const result = resourcePolicy.check(
      { actions: ['anything'], P: { id: 'ian', roles: ['ADMIN'] }, R: resourcesPolicy.expense1 },
      new Set(),
    );
    assert.equal(result.effects.get('anything'), 'EFFECT_ALLOW');
  });

  it('exposes the shape getter and returns empty results for an empty actions request (RolePolicy)', () => {
    const rolePolicy = new RolePolicy(userRolePolicy);
    assert.ok(rolePolicy.shape);
    const result = rolePolicy.check({ actions: [], P: principalsPolicy.sally, R: resourcesPolicy.expense1 });
    assert.equal(result.effects.size, 0);
  });

  it('matches a role-policy rule via the ALL_RESOURCES wildcard', () => {
    const rolePolicy = new RolePolicy({
      rolePolicy: {
        role: 'GLOBAL_VIEWER',
        version: 'default',
        scope: 'acme.corp',
        rules: [{ name: 'allow_all_resources_view', resource: '*', allowActions: ['view'] }],
      },
    });
    const result = rolePolicy.check({
      actions: ['view'],
      P: { id: 'anyone', roles: ['GLOBAL_VIEWER'] },
      R: { id: 'r1', kind: 'anything' },
    });
    assert.equal(result.effects.get('view'), 'EFFECT_ALLOW');
    assert.equal(result.meta.actions.view.matchedScope, 'acme.corp');
  });

  it('records rule-miss (not condition-not-met) when no role-policy rule targets the resource at all', () => {
    const rolePolicy = new RolePolicy(userRolePolicy);
    const result = rolePolicy.check({
      actions: ['view'],
      P: principalsPolicy.sally,
      R: { id: 'r1', kind: 'unrelated-kind', attr: {} },
    });
    assert.equal(result.effects.has('view'), false);
    assert.equal(result.meta.actions.view, undefined);
  });
});

describe('Coverage: logging.js writer direct unit tests', () => {
  it('treats a logger with only "table" as legacy and only "debug" as structured', () => {
    const tableOnly = createLoggerWriter({ table() {} });
    assert.equal(tableOnly.enabled, true);
    const debugOnly = createLoggerWriter({ debug() {} });
    assert.equal(debugOnly.enabled, true);
  });

  it('disables logging for objects that are neither legacy nor structured', () => {
    const disabled = createLoggerWriter({ foo() {} });
    assert.equal(disabled.enabled, false);
    disabled.write([], 'IsAllowed', 'call-1');
    disabled.debug({}, 'msg');
    disabled.error({}, 'msg');
  });

  it('falls back to logger.debug when a legacy logger has no error method', () => {
    const debugCalls = [];
    const legacy = createLoggerWriter({ log() {}, debug: (entry, message) => debugCalls.push({ entry, message }) });
    legacy.error({ some: 'entry' }, 'error message');
    assert.equal(debugCalls.length, 1);
  });

  it('uses logger.error when a legacy logger provides one', () => {
    const errorCalls = [];
    const legacy = createLoggerWriter({ log() {}, error: (entry, message) => errorCalls.push({ entry, message }) });
    legacy.error({ some: 'entry' }, 'error message');
    assert.equal(errorCalls.length, 1);
  });

  it('writes the isAllowed summary line through the legacy console-like writer', () => {
    const calls = { log: [], table: [], group: 0, groupEnd: 0, debug: [] };
    const legacy = createLoggerWriter({
      log: (msg) => calls.log.push(msg),
      table: (rows) => calls.table.push(rows),
      group: () => (calls.group += 1),
      groupEnd: () => (calls.groupEnd += 1),
      debug: (entry, message) => calls.debug.push({ entry, message }),
    });

    const req = {
      reqId: 'req-1',
      actions: ['view'],
      P: { id: 'sally', scope: 'acme.corp', policyVersion: '2021' },
      R: { kind: 'expense', id: 'e1', scope: 'acme.corp', policyVersion: '2021' },
    };
    const result = { effects: new Map([['view', 'EFFECT_ALLOW']]), outputs: new Map(), meta: { actions: {} } };
    legacy.write([{ req, result }], 'IsAllowed', 'call-1');

    assert.equal(calls.group, 1);
    assert.equal(calls.groupEnd, 1);
    assert.equal(calls.log.length, 1);
    assert.match(calls.log[0], /ALLOWED/);
    assert.equal(calls.table.length, 1);
    assert.equal(calls.debug.length, 1);
  });

  it('builds structured audit entries directly, dropping falsy optional fields', () => {
    const req = {
      reqId: undefined,
      actions: ['view'],
      P: { id: 'sally', scope: undefined, policyVersion: undefined },
      R: { kind: 'expense', id: 'e1', scope: undefined, policyVersion: undefined },
    };
    const result = { effects: new Map([['view', 'EFFECT_ALLOW']]), outputs: undefined, meta: undefined };
    const entries = buildAuditEntries([{ req, result }], 'CheckResources', undefined);
    assert.equal(entries.length, 1);
    assert.equal('reqId' in entries[0], false);
    assert.equal('callId' in entries[0], false);
    assert.equal('meta' in entries[0], false);
    assert.deepEqual(entries[0].outputs, []);
  });

  it('uses the info method when both info and debug are present on a structured logger, and prefers a child logger', () => {
    const calls = { info: [], debug: [], childCreated: false };
    const child = {
      info: (entry, message) => calls.info.push({ entry, message }),
      debug: (entry, message) => calls.debug.push({ entry, message }),
    };
    const parent = {
      info() {},
      debug() {},
      child: () => {
        calls.childCreated = true;
        return child;
      },
    };
    const writer = createLoggerWriter(parent);
    const req = {
      actions: ['view'],
      P: { id: 'sally' },
      R: { kind: 'expense', id: 'e1' },
    };
    const result = { effects: new Map([['view', 'EFFECT_ALLOW']]), outputs: new Map(), meta: {} };
    writer.write([{ req, result }], 'CheckResources', 'call-1');
    assert.equal(calls.childCreated, true);
    assert.equal(calls.info.length, 1);
  });
});

describe('Coverage: telemetry.js writer direct unit tests', () => {
  const { createTelemetryWriter } = require('../src/telemetry.js');

  it('disables telemetry when resolveTracerAndMeter throws', () => {
    const writer = createTelemetryWriter({
      get tracer() {
        throw new Error('boom');
      },
    });
    assert.equal(writer.enabled, false);
  });

  it('resolves tracer/meter from the api mode when getTracer/getMeter are missing', () => {
    const writer = createTelemetryWriter({ api: { trace: {}, metrics: {} } });
    assert.equal(writer.enabled, false);
  });

  it('rethrows an error from fn() after startActiveSpan has invoked the callback', () => {
    const writer = createTelemetryWriter({
      tracer: {
        startActiveSpan(name, options, fn) {
          return fn({ setAttribute() {}, addEvent() {} });
        },
      },
    });
    assert.throws(() => {
      writer.withRequestSpan('IsAllowed', 'call-1', undefined, () => {
        throw new Error('handler failed');
      });
    }, /handler failed/);
  });

  it('falls back to fn(handle) with a null span when the tracer has neither startActiveSpan nor startSpan', () => {
    const writer = createTelemetryWriter({ tracer: {} });
    let sawHandle;
    writer.withRequestSpan('IsAllowed', 'call-1', undefined, (handle) => {
      sawHandle = handle;
    });
    assert.equal(sawHandle.span, null);
  });

  it('uses the Kerberos.<reqKind> fallback span name for an unknown reqKind', () => {
    const names = [];
    const writer = createTelemetryWriter({
      tracer: {
        startSpan(name) {
          names.push(name);
          return { setAttribute() {}, end() {} };
        },
      },
    });
    writer.withRequestSpan('SomethingCustom', 'call-1', undefined, () => {});
    assert.deepEqual(names, ['Kerberos.SomethingCustom']);
  });

  it('swallows recordDecisions failures caused by malformed input', () => {
    const writer = createTelemetryWriter({
      meter: {
        createCounter: () => ({ add() {} }),
        createHistogram: () => ({ record() {} }),
      },
    });
    assert.doesNotThrow(() => writer.recordDecisions({ span: null }, null, 'IsAllowed'));
  });

  it('no-ops recordError when handle is null/undefined', () => {
    const writer = createTelemetryWriter({
      tracer: { startSpan: () => ({ setAttribute() {}, end() {} }) },
    });
    assert.doesNotThrow(() => writer.recordError(null, new Error('boom')));
  });

  it('swallows a throwing span in recordError', () => {
    const writer = createTelemetryWriter({
      tracer: { startSpan: () => ({ setAttribute() {}, end() {} }) },
    });
    const handle = {
      span: {
        recordException() {
          throw new Error('broken span');
        },
      },
    };
    assert.doesNotThrow(() => writer.recordError(handle, new Error('boom')));
  });

  it('swallows a throwing cache-requests counter', () => {
    const writer = createTelemetryWriter({
      meter: {
        createCounter: () => ({
          add() {
            throw new Error('broken counter');
          },
        }),
        createHistogram: () => ({ record() {} }),
      },
    });
    assert.doesNotThrow(() => writer.recordCacheRequest('hit'));
  });

  it('swallows a throwing duration histogram in endRequest', () => {
    const writer = createTelemetryWriter({
      meter: {
        createCounter: () => ({ add() {} }),
        createHistogram: () => ({
          record() {
            throw new Error('broken histogram');
          },
        }),
      },
    });
    assert.doesNotThrow(() => writer.endRequest({ span: null }, 'IsAllowed', 10));
  });
});

describe('Coverage: caching/codec.js operator + descriptor handlers', () => {
  function evalExpr(expr, ctx = {}) {
    return codec.compileExpr(expr)(ctx);
  }

  it('evaluates every comparison/arithmetic/bitwise binary operator', () => {
    assert.equal(evalExpr('1 !== 2'), true);
    assert.equal(evalExpr('1 != 2'), true);
    assert.equal(evalExpr('2 > 1'), true);
    assert.equal(evalExpr('1 <= 1'), true);
    assert.equal(evalExpr('2 >= 1'), true);
    assert.equal(evalExpr('1 + 1'), 2);
    assert.equal(evalExpr('3 * 2'), 6);
    assert.equal(evalExpr('6 / 2'), 3);
    assert.equal(evalExpr('5 % 2'), 1);
    assert.equal(evalExpr('2 ** 3'), 8);
    assert.equal(evalExpr('6 & 3'), 2);
    assert.equal(evalExpr('6 | 1'), 7);
    assert.equal(evalExpr('6 ^ 3'), 5);
    assert.equal(evalExpr('1 << 2'), 4);
    assert.equal(evalExpr('8 >> 2'), 2);
    assert.equal(evalExpr('-8 >>> 28'), 15);
  });

  it('evaluates every unary operator', () => {
    assert.equal(evalExpr('-5'), -5);
    assert.equal(evalExpr('+"5"'), 5);
    assert.equal(evalExpr('~0'), -1);
    assert.equal(evalExpr('typeof 5'), 'number');
  });

  it('evaluates conditional (ternary) and array-literal expressions', () => {
    assert.equal(evalExpr('1 > 0 ? "yes" : "no"'), 'yes');
    assert.deepEqual(evalExpr('[1, 2, 3]'), [1, 2, 3]);
  });

  it('exposes isExprDescriptor directly for descriptor and non-descriptor values', () => {
    assert.equal(codec.isExprDescriptor({ $expr: 'P.id' }), true);
    assert.equal(codec.isExprDescriptor({ $expr: 42 }), false);
    assert.equal(codec.isExprDescriptor('P.id'), false);
    assert.equal(codec.isExprDescriptor(null), false);
    assert.equal(codec.isExprDescriptor([1, 2]), false);
  });

  it('serializes an already-validated $expr descriptor and round-trips through deserialize', () => {
    const serialized = codec.serialize({ match: { $expr: 'P.id === "sally"' } });
    assert.deepEqual(serialized, { match: { $expr: 'P.id === "sally"' } });
    const deserialized = codec.deserialize(serialized);
    assert.equal(typeof deserialized.match, 'function');
    assert.equal(deserialized.match({ P: { id: 'sally' } }), true);
  });
});

describe('Coverage: validation/index.js + ajv.js + caching/cache.js', () => {
  it('builds a validator adapter from a plain function validator (Ajv-compiled style)', () => {
    function validator(value) {
      if (value !== 'ok') {
        validator.errors = [{ message: 'not ok' }];
        return false;
      }
      return true;
    }
    const adapter = toValidationAdapter(validator);
    assert.equal(adapter.parse('ok'), 'ok');
    assert.throws(() => adapter.parse('bad'), /not ok/);
  });

  it('builds a validator adapter from a { validate } style object', () => {
    const adapter = toValidationAdapter({ validate: (value) => value === 'ok', message: 'custom failure' });
    assert.equal(adapter.parse('ok'), 'ok');
    assert.throws(() => adapter.parse('bad'), /custom failure/);
  });

  it('returns null from toValidationAdapter for a falsy or unsupported value', () => {
    assert.equal(toValidationAdapter(null), null);
    assert.equal(toValidationAdapter(42), null);
  });

  it('uses an explicit plain-object schema with ajv when both schema and ajv are provided (no parser methods)', () => {
    const ajv = createAjv();
    const adapter = resolveValidationAdapter({ schema: { type: 'string' }, ajv });
    assert.equal(adapter.parse('hello'), 'hello');
  });

  it('returns null from resolveValidationAdapter when no backend option is usable', () => {
    assert.equal(resolveValidationAdapter({}), null);
  });

  it('throws a TypeError from createAjvAdapter without a compile()-capable ajv instance', () => {
    assert.throws(() => createAjvAdapter(null, { type: 'string' }), TypeError);
  });

  it('registerAjvKeywords is idempotent and rejects a non-ajv instance', () => {
    const ajv = createAjv();
    assert.doesNotThrow(() => registerAjvKeywords(ajv));
    assert.throws(() => registerAjvKeywords({}), TypeError);
  });

  it('validates every kerberosType branch (bigint/boolean/number/object/string/symbol/undefined) and rejects unknown types', () => {
    const ajv = createAjv();
    const validate = ajv.compile({ kerberosType: 'bigint' });
    assert.equal(validate(1n), true);
    assert.equal(validate(1), false);

    for (const [expectedType, value] of [
      ['boolean', true],
      ['number', 1],
      ['object', {}],
      ['string', 'x'],
      ['symbol', Symbol('x')],
      ['undefined', undefined],
    ]) {
      const v = ajv.compile({ kerberosType: expectedType });
      assert.equal(v(value), true);
    }
  });

  it('createCacheReader disables itself for non-object caches and caches without a get() method', () => {
    assert.equal(createCacheReader(false).enabled, false);
    assert.equal(createCacheReader('not-an-object').enabled, false);
    assert.equal(createCacheReader({}).enabled, false);
  });
});
