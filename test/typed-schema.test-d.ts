import { expectAssignable, expectError, expectType } from 'tsd';
import {
  Effect,
  Kerberos,
  type ActionOf,
  type CheckResourcesResponse,
  type KerberosPolicy,
  type PlanResourcesResponse,
  type PrincipalRoleOf,
  type RequestPrincipal,
  type ResourceAttrOf,
  type ResourceKindOf,
} from '../index.js';
import { RelationResolver } from '../relations.js';

/**
 * Typed authoring: an application declares its authorization domain once and
 * every policy shape, request and response narrows to it. These assertions are
 * the contract — they must keep holding as `index.d.ts` evolves.
 */
type AppSchema = {
  principal: { roles: 'admin' | 'user'; attr: { department: string; clearance: number } };
  resources: {
    document: { actions: 'view' | 'edit' | 'delete'; attr: { ownerId: string; status: 'draft' | 'published' } };
    invoice: { actions: 'view' | 'approve'; attr: { amount: number } };
  };
};

// ---------------------------------------------------------------------------
// Schema projections
// ---------------------------------------------------------------------------

expectType<'document' | 'invoice'>({} as ResourceKindOf<AppSchema>);
expectType<'view' | 'edit' | 'delete'>({} as ActionOf<AppSchema, 'document'>);
expectType<'view' | 'approve'>({} as ActionOf<AppSchema, 'invoice'>);
// Unparameterized, `ActionOf` is the union across every kind.
expectType<'view' | 'edit' | 'delete' | 'approve'>({} as ActionOf<AppSchema>);
expectType<'admin' | 'user'>({} as PrincipalRoleOf<AppSchema>);
expectType<{ amount: number }>({} as ResourceAttrOf<AppSchema, 'invoice'>);

// ---------------------------------------------------------------------------
// Requests: the resource kind narrows the action and the attribute bag
// ---------------------------------------------------------------------------

declare const app: Kerberos<AppSchema>;

app.isAllowed({
  principal: { id: 'u1', roles: ['admin'], attr: { department: 'eng', clearance: 3 } },
  resource: { kind: 'document', id: 'd1', attr: { ownerId: 'u1', status: 'draft' } },
  action: 'edit',
});

// 'approve' belongs to `invoice`, not to `document`.
expectError(
  app.isAllowed({
    principal: { id: 'u1', roles: ['admin'] },
    resource: { kind: 'document', id: 'd1' },
    action: 'approve',
  }),
);

// Undeclared resource kind.
expectError(
  app.isAllowed({
    principal: { id: 'u1', roles: ['admin'] },
    resource: { kind: 'ledger', id: 'l1' },
    action: 'view',
  }),
);

// Undeclared role.
expectError(
  app.isAllowed({
    principal: { id: 'u1', roles: ['superuser'] },
    resource: { kind: 'document', id: 'd1' },
    action: 'view',
  }),
);

// Attribute bag is checked against the kind: `status` has a literal union.
expectError(
  app.isAllowed({
    principal: { id: 'u1', roles: ['admin'] },
    resource: { kind: 'document', id: 'd1', attr: { ownerId: 'u1', status: 'archived' } },
    action: 'view',
  }),
);

// Principal attributes are checked too (`clearance` is a number).
expectError(
  app.isAllowed({
    principal: { id: 'u1', roles: ['admin'], attr: { department: 'eng', clearance: 'high' } },
    resource: { kind: 'document', id: 'd1' },
    action: 'view',
  }),
);

// ---------------------------------------------------------------------------
// checkResources: heterogeneous batches stay per-entry typed
// ---------------------------------------------------------------------------

app.checkResources({
  principal: { id: 'u1', roles: ['user'] },
  resources: [
    { resource: { kind: 'document', id: 'd1' }, actions: ['view', 'edit'] },
    { resource: { kind: 'invoice', id: 'i1' }, actions: ['approve'] },
  ],
});

// `edit` is not an `invoice` action, even inside a mixed batch.
expectError(
  app.checkResources({
    principal: { id: 'u1', roles: ['user'] },
    resources: [{ resource: { kind: 'invoice', id: 'i1' }, actions: ['edit'] }],
  }),
);

// `effectAsBoolean` selects the effect representation through overloads.
expectType<Promise<CheckResourcesResponse<AppSchema, Effect>>>(
  app.checkResources({ principal: { id: 'u1', roles: ['user'] }, resources: [] }),
);
expectType<Promise<CheckResourcesResponse<AppSchema, boolean>>>(
  app.checkResources({ principal: { id: 'u1', roles: ['user'] }, resources: [] }, true),
);
declare const asBoolean: boolean;
expectType<Promise<CheckResourcesResponse<AppSchema, Effect | boolean>>>(
  app.checkResources({ principal: { id: 'u1', roles: ['user'] }, resources: [] }, asBoolean),
);

// ---------------------------------------------------------------------------
// planResources
// ---------------------------------------------------------------------------

expectType<Promise<PlanResourcesResponse<AppSchema>>>(
  app.planResources({
    principal: { id: 'u1', roles: ['user'] },
    resource: { kind: 'invoice' },
    action: 'approve',
  }),
);

expectError(
  app.planResources({
    principal: { id: 'u1', roles: ['user'] },
    resource: { kind: 'invoice' },
    action: 'delete',
  }),
);

// ---------------------------------------------------------------------------
// Policy authoring: `resource:` discriminates the rules
// ---------------------------------------------------------------------------

const documentPolicy: KerberosPolicy<AppSchema> = {
  resourcePolicy: {
    version: 'default',
    resource: 'document',
    rules: [
      { actions: ['view', 'edit'], effect: Effect.Allow, roles: ['admin'] },
      // Raw wire strings are assignable — this is what a stored policy carries.
      { actions: ['*'], effect: 'EFFECT_DENY', roles: ['*'] },
      {
        actions: ['edit'],
        effect: Effect.Allow,
        roles: ['user'],
        // Condition callbacks see the narrowed `R.attr` / `P.attr`.
        condition: { match: ({ R, P }) => R.attr?.ownerId === P.id && R.attr?.status === 'draft' },
      },
      // Serialized `$expr` conditions are accepted as well.
      { actions: ['delete'], effect: Effect.Allow, roles: ['admin'], condition: { match: { $expr: 'P.id == R.id' } } },
    ],
  },
};
void documentPolicy;

// `approve` is not a `document` action.
expectError<KerberosPolicy<AppSchema>>({
  resourcePolicy: {
    version: 'default',
    resource: 'document',
    rules: [{ actions: ['approve'], effect: Effect.Allow, roles: ['admin'] }],
  },
});

// A condition reading an attribute the kind does not declare.
expectError<KerberosPolicy<AppSchema>>({
  resourcePolicy: {
    version: 'default',
    resource: 'invoice',
    rules: [
      { actions: ['view'], effect: Effect.Allow, roles: ['user'], condition: { match: ({ R }) => R.attr?.ownerId } },
    ],
  },
});

const invoiceRolePolicy: KerberosPolicy<AppSchema> = {
  rolePolicy: {
    role: 'user',
    version: 'default',
    rules: [{ resource: 'invoice', allowActions: ['view'] }],
  },
};
void invoiceRolePolicy;

expectError<KerberosPolicy<AppSchema>>({
  rolePolicy: {
    role: 'user',
    version: 'default',
    rules: [{ resource: 'invoice', allowActions: ['delete'] }],
  },
});

const principalPolicy: KerberosPolicy<AppSchema> = {
  principalPolicy: {
    principal: 'u1',
    version: 'default',
    rules: [{ resource: 'document', actions: [{ action: 'delete', effect: Effect.Deny }] }],
  },
};
void principalPolicy;

new Kerberos<AppSchema>([documentPolicy, invoiceRolePolicy, principalPolicy], []);

// ---------------------------------------------------------------------------
// Backward compatibility: without a schema every position stays open
// ---------------------------------------------------------------------------

// The built-in ReBAC resolver stays usable under a typed schema.
declare const resolver: RelationResolver;
new Kerberos<AppSchema>([], [], { relations: resolver });

declare const untyped: Kerberos;
untyped.isAllowed({
  principal: { id: 'u1', roles: ['anything'] },
  resource: { kind: 'whatever', id: 'x', attr: { free: 'form' } },
  action: 'any-action',
});
expectAssignable<RequestPrincipal>({ id: 'u1', roles: ['a', 'b'], attr: { any: 1 } });
expectType<string>({} as ResourceKindOf);
expectType<string>({} as ActionOf);
