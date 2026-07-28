# Kerberos class

`Kerberos` is the sole runtime engine: you construct it once with your policies and derived roles, then ask it questions. Three public methods answer them — [`isAllowed`](#kerberos-isallowed-args-promise-boolean) for a single decision, [`checkResources`](#kerberos-checkresources-args-effectasboolean-false-promise-checkresourcesresponse) for a batch, and [`planResources`](#kerberos-planresources-args-promise-planresourcesresponse) for a database filter.

## `new Kerberos(policies, derivedRoles?, options?)`

| Parameter | Type | Description |
| --------- | ---- | ----------- |
| `policies` | `Array<ResourcePolicy \| PrincipalPolicy \| RolePolicy \| object>` | Static policies loaded into memory. Plain objects are auto-detected by their `resourcePolicy` / `principalPolicy` / `rolePolicy` key. May be empty when policies are resolved from a `cache`. |
| `derivedRoles` | `Array<DerivedRoles \| object>` | Optional derived-role definition sets. |
| `options` | `object` | Optional configuration — see [Configuration Options](/guide/configuration). |

## `kerberos.isAllowed(args) => Promise<boolean>`

Evaluates a **single** action against a single resource and returns a boolean.

- `args.principal` — the principal (`id`, `roles`, optional `policyVersion`, `scope`, `attr`).
- `args.action` — the action to check.
- `args.resource` — the resource (`id`, `kind`, optional `policyVersion`, `scope`, `attr`).
- `args.reqId` — optional correlation id echoed in logs.
- `args.includeMeta` — when `true`, enables decision tracing (visible in audit logs).

```javascript
const allowed = await kerberos.isAllowed({
  principal: { id: 'user1', roles: ['USER'], policyVersion: 'default', scope: 'acme.corp' },
  action: 'view',
  resource: { id: 'expense1', kind: 'expense', attr: { amount: 5000, status: 'OPEN' } },
  reqId: 'optional-correlation-id', // optional
});
```

## `kerberos.checkResources(args, effectAsBoolean = false) => Promise<CheckResourcesResponse>`

Evaluates **multiple resources and actions** in a single request.

- `args.principal` — the principal (`id`, `roles`, optional `policyVersion`, `scope`, `attr`).
- `args.resources` — array of `{ resource, actions }` entries.
- `args.reqId` — optional correlation id echoed in the response and logs.
- `args.includeMeta` — when `true`, includes evaluation [metadata](/guide/decision-metadata).
- `effectAsBoolean` — when `true`, action results are `true`/`false` instead of `EFFECT_ALLOW`/`EFFECT_DENY`.

```javascript
const response = await kerberos.checkResources({
  principal: { id: 'user1', roles: ['USER'] },
  resources: [{ resource: { id: 'expense1', kind: 'expense' }, actions: ['view', 'create'] }],
});
// {
//   kerberosCallId: 'b9c4362d-…',          // always present, for audit correlation
//   reqId: '…',                            // present only if provided in the request
//   results: [{ resource, actions, outputs, meta? }],
// }
```

## `kerberos.planResources(args) => Promise<PlanResourcesResponse>`

Builds a **resources query plan**: instead of a yes/no decision for one resource, it returns a *filter* describing **which** resources of a kind the principal may act on — ready to translate into a database query. See [Query Plans](/guide/query-plans).

- `args.principal` — the principal (`id`, `roles`, optional `policyVersion`, `scope`, `attr`).
- `args.resource` — the resource **kind** (`kind`, optional `policyVersion`, `scope`, `attr`). No `id`: `attr` carries only the *known* attributes; everything else stays unknown and surfaces in the filter.
- `args.action` **or** `args.actions` — exactly one of them; multiple actions plan the conjunction (Cerbos AND semantics). The wildcard `'*'` cannot be planned.
- `args.reqId` / `args.includeMeta` — as in `checkResources`; `includeMeta` adds `filterDebug`, `matchedScopes` and the `resolution` trace.

```javascript
const plan = await kerberos.planResources({
  principal: { id: 'user1', roles: ['USER'] },
  resource: { kind: 'expense' },
  action: 'view',
});
// {
//   kerberosCallId: '…', action: 'view', resourceKind: 'expense', policyVersion: 'default',
//   filter: { kind: 'KIND_ALWAYS_ALLOWED' | 'KIND_ALWAYS_DENIED' | 'KIND_CONDITIONAL', condition? },
// }
```
