# TypeScript

Kerberos.js ships hand-maintained types. By default every position is open — `kind` and `action` are `string`, `attr` is `Record<string, unknown>` — which is what you want for policies loaded from a store at runtime.

When your resource kinds are known at compile time, declare them once and the whole surface narrows to them.

## Declaring a schema

```typescript
import { Kerberos, Effect, type KerberosPolicy } from '@alexify/kerberos';

type AppSchema = {
  principal: {
    roles: 'admin' | 'user';
    attr: { department: string; clearance: number };
  };
  resources: {
    document: { actions: 'view' | 'edit' | 'delete'; attr: { ownerId: string; status: 'draft' | 'published' } };
    invoice: { actions: 'view' | 'approve'; attr: { amount: number } };
  };
};

const kerberos = new Kerberos<AppSchema>(policies, derivedRoles);
```

Both keys are optional — declare only `resources` if you do not want to enumerate roles.

## What it buys you

The resource kind drives everything else. `action`, `attr`, and the condition callbacks all narrow to the kind you named:

```typescript
await kerberos.isAllowed({
  principal: { id: 'u1', roles: ['admin'], attr: { department: 'eng', clearance: 3 } },
  resource: { kind: 'document', id: 'd1', attr: { ownerId: 'u1', status: 'draft' } },
  action: 'edit', // ✅ autocompleted from `document`'s actions
});

await kerberos.isAllowed({
  principal: { id: 'u1', roles: ['admin'] },
  resource: { kind: 'document', id: 'd1' },
  action: 'approve', // ❌ 'approve' belongs to `invoice`, not `document`
});
```

Policy documents are checked the same way — `resource:` discriminates the rules, so a typo in an action or a role is a compile error rather than a silent `EFFECT_DENY` at 3am:

```typescript
const policy: KerberosPolicy<AppSchema> = {
  resourcePolicy: {
    version: 'default',
    resource: 'document',
    rules: [
      { actions: ['view', 'edit'], effect: Effect.Allow, roles: ['admin'] },
      {
        actions: ['edit'],
        effect: Effect.Allow,
        roles: ['user'],
        // R.attr is { ownerId: string; status: 'draft' | 'published' }
        condition: { match: ({ R, P }) => R.attr?.ownerId === P.id && R.attr?.status === 'draft' },
      },
    ],
  },
};
```

The same narrowing applies to [principal policies](/guide/policy-types#principalpolicy) (`resource:` narrows each entry's `action`) and [role policies](/guide/policy-types#rolepolicy) (`resource:` narrows `allowActions`, and `role` / `parentRoles` are checked against the declared roles).

## Batches and plans

`checkResources` keeps each batch entry typed independently, so a mixed batch still catches a wrong action per kind:

```typescript
const { results } = await kerberos.checkResources({
  principal: { id: 'u1', roles: ['user'] },
  resources: [
    { resource: { kind: 'document', id: 'd1' }, actions: ['view', 'edit'] },
    { resource: { kind: 'invoice', id: 'i1' }, actions: ['approve'] },
  ],
});
```

The second argument selects the effect representation through overloads:

```typescript
await kerberos.checkResources(args); // results[].actions is Record<Action, Effect>
await kerberos.checkResources(args, true); // results[].actions is Record<Action, boolean>
```

[`planResources`](/guide/query-plans) narrows `action` / `actions` against the planned kind in the same way.

## Schema helper types

Exported so you can build your own typed wrappers (an Express middleware, a React hook) over the same schema:

| Type | Resolves to |
| ---- | ----------- |
| `ResourceKindOf<S>` | Union of declared resource kinds. |
| `ActionOf<S, K>` | Actions for kind `K`; every action across all kinds when `K` is omitted. |
| `ResourceAttrOf<S, K>` | Attribute bag of kind `K`. |
| `PrincipalRoleOf<S>` / `PrincipalAttrOf<S>` | Declared principal roles / attributes. |
| `RequestPrincipal<S>`, `RequestResource<S, K>`, `BaseRequest<S, K>` | Request shapes. |
| `PolicyEvalRequest<S, K>` | The `{ P, R, V, C }` envelope a condition/variable/output callback receives. |
| `CheckResourcesArgs<S>`, `CheckResourcesResponse<S, E>` | `checkResources` arguments and response. |
| `PlanResourcesArgs<S, K>`, `PlanResourcesResponse<S>` | `planResources` arguments and response. |
| `AnySchema` | The permissive default used when no schema is supplied. |

An example wrapper:

```typescript
import type { ActionOf, RequestPrincipal, ResourceKindOf } from '@alexify/kerberos';

async function assertAllowed<K extends ResourceKindOf<AppSchema>>(
  principal: RequestPrincipal<AppSchema>,
  kind: K,
  id: string,
  action: ActionOf<AppSchema, K>,
): Promise<void> {
  if (!(await kerberos.isAllowed({ principal, resource: { kind, id }, action }))) {
    throw new Error(`${principal.id} may not ${action} ${kind}:${id}`);
  }
}
```

::: warning Compile-time only
Typing has **no runtime cost and no runtime enforcement**. A schema constrains the policies and requests you write in TypeScript; it does not validate policies loaded from a cache at runtime. For that, use [schema validation](/guide/schema-validation).
:::

## `Effect` and `PlanKind` are const objects

Neither is a TypeScript `enum`, so the raw wire strings that a stored policy or a serialized plan actually carries stay assignable:

```typescript
const rule = { actions: ['view'], effect: 'EFFECT_ALLOW', roles: ['user'] }; // ✅ no `Effect.Allow` needed

if (planResponse.filter.kind === 'KIND_ALWAYS_DENIED') return [];
```

`Effect.Allow` and `PlanKind.Conditional` keep working exactly as before — they are just typed as the literal strings they hold at runtime.
