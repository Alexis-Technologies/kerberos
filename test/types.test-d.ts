import { expectAssignable, expectType } from 'tsd';
import {
  Effect,
  Kerberos,
  PlanKind,
  expandRelationOperands,
  type KerberosDerivedRoles,
  type KerberosPolicy,
  type KerberosTelemetryApi,
  type KerberosTelemetryOptions,
  type PlanExpressionOperand,
  type PlanFilter,
  type PlanResourcesResponse,
} from '../index.js';

const policy = {
  resourcePolicy: {
    version: 'default',
    resource: 'report_manager_global_settings',
    importDerivedRoles: ['report_manager_roles'],
    rules: [
      {
        actions: ['read', 'update'],
        effect: Effect.Allow,
        derivedRoles: ['SYSTEM_TENANT_ADMIN'],
      },
    ],
  },
} as const;

// Must compile without assertion:
const _policyCheck: KerberosPolicy = policy;

const derivedRoles = {
  name: 'report_manager_roles',
  definitions: [
    {
      name: 'ADMIN',
      parentRoles: ['admin'],
      condition: { match: () => true },
    },
  ],
} as const;

// Must compile without `as unknown as`:
const _derivedCheck: KerberosDerivedRoles = derivedRoles;

new Kerberos([policy], [derivedRoles]);

// Backward compatibility: mutable policy objects without `as const`
const mutablePolicy: KerberosPolicy = {
  resourcePolicy: {
    version: 'default',
    resource: 'expense',
    rules: [
      {
        actions: ['view'],
        effect: Effect.Allow,
        roles: ['USER'],
      },
    ],
  },
};

const mutableDerivedRoles: KerberosDerivedRoles = {
  name: 'common_roles',
  definitions: [
    {
      name: 'ADMIN',
      parentRoles: ['admin'],
      condition: { match: () => true },
    },
  ],
};

new Kerberos([mutablePolicy], [mutableDerivedRoles]);

// telemetry option accepts the api-module shape and the instances shape
declare const otelApi: KerberosTelemetryApi;
const telemetryApiMode: KerberosTelemetryOptions = { api: otelApi, includeIdentity: false };
const telemetryInstancesMode: KerberosTelemetryOptions = {
  tracer: { startSpan: (name: string) => ({ end: () => {} }) },
  meter: {
    createCounter: () => ({ add: () => {} }),
    createHistogram: () => ({ record: () => {} }),
  },
};
new Kerberos([mutablePolicy], [mutableDerivedRoles], { telemetry: telemetryApiMode });
new Kerberos([mutablePolicy], [mutableDerivedRoles], { telemetry: telemetryInstancesMode });

// isAllowed accepts optional reqId
declare const kerberos: Kerberos;
kerberos.isAllowed({
  reqId: 'correlation-id',
  principal: { id: 'user1', roles: ['USER'] },
  action: 'read',
  resource: { id: 'doc1', kind: 'document' },
});

// planResources: kind-level resource (no id), single action or actions[]
expectType<Promise<PlanResourcesResponse>>(
  kerberos.planResources({
    principal: { id: 'user1', roles: ['USER'] },
    resource: { kind: 'document', attr: { status: 'OPEN' } },
    action: 'read',
    includeMeta: true,
  }),
);
kerberos.planResources({
  principal: { id: 'user1', roles: ['USER'] },
  resource: { kind: 'document' },
  actions: ['read', 'edit'],
});

declare const planResponse: PlanResourcesResponse;
expectType<PlanFilter>(planResponse.filter);
expectType<PlanKind>(planResponse.filter.kind);
expectAssignable<PlanKind>(PlanKind.AlwaysAllowed);
expectType<'KIND_CONDITIONAL'>(PlanKind.Conditional);
// PlanKind/Effect are const objects, not `enum`s — the raw wire strings that a
// serialized plan or a JSON policy actually carries stay assignable.
expectAssignable<PlanKind>('KIND_ALWAYS_DENIED');
expectAssignable<Effect>('EFFECT_ALLOW');
// The operand union accepts nested expressions, variables and literals.
const conditionalOperand: PlanExpressionOperand = {
  expression: {
    operator: 'eq',
    operands: [{ variable: 'request.resource.attr.status' }, { value: 'OPEN' }],
  },
};
void conditionalOperand;

expectType<Promise<PlanResourcesResponse>>(expandRelationOperands(planResponse, async () => ['id1']));
expectType<Promise<PlanResourcesResponse>>(expandRelationOperands(planResponse, () => new Set(['id1'])));

// Lifecycle hooks: typed, discriminated context; events: typed, chainable.
import {
  KerberosHookError,
  type KerberosDecisionEvent,
  type KerberosHookContext,
  type KerberosHooks,
  type KerberosRequestSummary,
  type KerberosResourceHookInfo,
  type KerberosResourceHookResult,
} from '../index.js';

const hooks: KerberosHooks = {
  beforeRequest(ctx) {
    expectType<KerberosHookContext>(ctx);
    expectType<string>(ctx.callId);
    if (ctx.reqKind === 'IsAllowed') expectType<string>(ctx.args.action);
    if (ctx.reqKind === 'CheckResources') expectType<number>(ctx.args.resources.length);
    if (ctx.reqKind === 'PlanResources') expectType<'PlanResources'>(ctx.reqKind);
  },
  async afterRequest(ctx, summary) {
    expectType<KerberosRequestSummary>(summary);
    expectType<boolean>(summary.success);
    expectType<true | undefined>(summary.failClosed);
  },
  beforeResource(ctx, info) {
    expectType<KerberosResourceHookInfo>(info);
    expectType<number>(info.index);
  },
  afterResource(ctx, info, result) {
    expectType<KerberosResourceHookResult>(result);
    expectType<Effect>(result.actions.view);
  },
  onError(error, ctx) {
    expectType<unknown>(error);
    expectType<string>(ctx.callId);
  },
};
const hookedEngine = new Kerberos([mutablePolicy], [mutableDerivedRoles], { hooks });
// @ts-expect-error — unknown hook names are rejected.
new Kerberos([mutablePolicy], [mutableDerivedRoles], { hooks: { beforeAll() {} } });

expectType<Kerberos>(
  hookedEngine
    .on('decision', (event) => {
      expectType<KerberosDecisionEvent>(event);
      expectType<string>(event.callId);
      expectType<Record<string, Effect>>(event.actions);
    })
    .once('request:end', (event) => expectType<boolean>(event.success))
    .off('plan', () => {})
    .removeAllListeners('cache:hit')
    .removeAllListeners(),
);
expectType<number>(hookedEngine.listenerCount('decision'));
// @ts-expect-error — a typo'd event name is a type error, not an untyped listener.
hookedEngine.on('decisions', () => {});
// @ts-expect-error — listeners must be functions.
hookedEngine.on('decision', 'nope');

const hookError = new KerberosHookError('x');
expectType<'KerberosHookError'>(hookError.name);
expectType<'beforeRequest' | 'afterRequest' | 'beforeResource' | 'afterResource' | 'onError' | null>(hookError.hook);
