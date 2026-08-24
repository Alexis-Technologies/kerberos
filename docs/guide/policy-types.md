# Policy Types

Kerberos.js supports three policy types:

- **`resourcePolicy`**: selected by `resource.kind`, `resource.policyVersion`, and `resource.scope`
- **`principalPolicy`**: selected by `principal.id`, `principal.policyVersion`, and `principal.scope`
- **`rolePolicy`**: selected by each `principal.roles[]`, `principal.policyVersion`, and `principal.scope`

You can pass either type on its own or mix them in the same constructor call:

```javascript
const kerberos = new Kerberos(
  [
    expenseResourcePolicy,
    sallyPrincipalPolicy,
    userRolePolicy,
  ],
  [commonRoles]
);
```

## ResourcePolicy

`ResourcePolicy` is the workhorse policy type, selected by `resource.kind`. Rules are matched by action, then by `roles` or `derivedRoles`, and may also use `conditions`, `variables`, `constants`, `outputs`, versions, and scopes — see the [Quick Start](/guide/getting-started) for a complete example.

### Conflict resolution

Conflicts are resolved **per principal role**, matching Cerbos: `EFFECT_DENY` overrides `EFFECT_ALLOW` **within** a role, and an `EFFECT_ALLOW` from **any** role wins across roles. Rule order never decides the outcome.

This is deliberate anti-lockout behaviour — picking up an extra, less privileged role can never take away access another role grants:

```javascript
rules: [
  { actions: ['close'], effect: Effect.Allow, roles: ['SUPPORT'] },
  { actions: ['close'], effect: Effect.Deny, roles: ['AUDITOR'] },
];
// principal roles ['SUPPORT', 'AUDITOR'] -> EFFECT_ALLOW
```

A deny that is meant to hold regardless has to cover the role carrying the allow — either with the `'*'` wildcard or by naming it:

```javascript
{ actions: ['close'], effect: Effect.Deny, roles: ['*'] }                 // always denies
{ actions: ['close'], effect: Effect.Deny, roles: ['SUPPORT', 'AUDITOR'] } // denies both roles
```

Derived roles do not form a dimension of their own: a rule reached through `derivedRoles` counts for the principal roles listed in that definition's `parentRoles`.

## PrincipalPolicy

`PrincipalPolicy` follows the Cerbos-style model for principal-specific overrides. It is bound to a single principal and targets `resource + action` directly instead of `roles` / `derivedRoles`.

```javascript
const sallyPrincipalPolicy = {
  principalPolicy: {
    principal: 'sally',
    version: 'default',
    scope: 'acme.corp',
    constants: {
      restrictedVendor: 'Flux Water Gear',
    },
    variables: {
      isRestrictedVendor: ({ R, C }) => R.attr.vendor === C.restrictedVendor,
    },
    rules: [
      {
        resource: 'expense',
        actions: [
          {
            name: 'deny-restricted-vendor-view',
            action: 'view',
            effect: Effect.Deny,
            condition: {
              match: ({ V }) => V.isRestrictedVendor,
            },
          },
          {
            name: 'allow-delete-override',
            action: 'delete',
            effect: Effect.Allow,
          },
        ],
      },
    ],
  },
};
```

## RolePolicy

`RolePolicy` follows the Cerbos-style role-centric model. It is bound to a single role, targets `resource + allowActions`, and behaves as an allowlist for matching resources. If a matching role policy exists for the current resource and the action is not listed in `allowActions`, Kerberos returns `EFFECT_DENY` for that role layer.

```javascript
const userRolePolicy = {
  rolePolicy: {
    role: 'USER',
    version: 'default',
    scope: 'acme.corp',
    constants: {
      restrictedVendor: 'Flux Water Gear',
    },
    variables: {
      isRestrictedVendor: ({ R, C }) => R.attr.vendor === C.restrictedVendor,
    },
    rules: [
      {
        resource: 'expense',
        allowActions: ['create'],
      },
      {
        resource: 'expense',
        allowActions: ['view'],
        condition: {
          match: ({ V }) => V.isRestrictedVendor === false,
        },
      },
    ],
  },
};
```

`RolePolicy` also supports `parentRoles`. When present, the child role can only keep actions that are also allowed by each locally defined parent role policy. Missing parent role policies are treated as external IdP roles and do not impose extra constraints inside Kerberos.

## Mixed Policy Evaluation

When mixed policy types are present, Kerberos resolves each action in this order:

1. Find the matching `PrincipalPolicy` for the request principal.
2. If it returns an explicit `EFFECT_ALLOW` or `EFFECT_DENY`, use that result.
3. Otherwise, evaluate all matching `RolePolicy` entries for the principal roles.
4. If multiple role policies apply to the same action, `EFFECT_DENY` wins over `EFFECT_ALLOW`.
5. If the role layer is not applicable for that action, fall back to the matching `ResourcePolicy`. Before its rules are matched, the imported **derived roles are resolved**: condition-backed definitions evaluate synchronously, and relation-backed definitions (the `relation:` field) resolve through the configured [`relations` resolver](/guide/rebac) (ReBAC) — `list`-first with parallel `check` fallback, one shared memo per request. The resulting `effectiveDerivedRoles` then participate in rule matching alongside plain `roles`.
6. If nothing matches, return `EFFECT_DENY`.

The decision is computed **per action** — different actions in the same request may be resolved by different policy layers. Each lookup (principal / role / resource) walks the [scope search chain](/guide/scopes) and `policyVersion`, and checks in-memory policies first, then the optional `cache`.

```mermaid
flowchart TD
    A([Request: principal · resource · action]) --> P{{"PrincipalPolicy<br/>(by principal.id)"}}
    P -->|"EFFECT_ALLOW / EFFECT_DENY"| DONE([Action effect resolved])
    P -->|no matching rule| R{{"RolePolicy layer<br/>(one per principal.roles[])"}}

    R -->|"EFFECT_DENY (wins over Allow)"| DONE
    R -->|"EFFECT_ALLOW"| DONE
    R -->|role layer not applicable| DR

    subgraph DR ["Derived-roles resolution (importDerivedRoles)"]
        direction TB
        SYNC["Condition-backed definitions<br/>(sync: parentRoles + condition)"] --> EDR([effectiveDerivedRoles])
        REL["Relation-backed definitions (relation: field)<br/>async via the relations resolver (ReBAC):<br/>list-first, parallel check fallback, shared memo"] --> EDR
    end

    EDR --> RES{{"ResourcePolicy<br/>(by resource.kind — rules match roles / derivedRoles)"}}

    RES -->|"EFFECT_ALLOW / EFFECT_DENY"| DONE
    RES -->|no rule matched| DEF([Default: EFFECT_DENY])
    DEF --> DONE
```

::: info Within the role layer
every `RolePolicy` matching a `principal.roles[]` entry is evaluated; `EFFECT_DENY` wins over `EFFECT_ALLOW`. When a role declares `parentRoles`, the child keeps only the actions that are **also** allowed by each locally defined parent role policy (intersection).
:::

This keeps Kerberos.js aligned with the Cerbos-style principal override model described in the [Cerbos principal policies documentation](https://docs.cerbos.dev/cerbos/latest/policies/principal_policies) while extending the runtime with role-centric policy evaluation similar to [Cerbos role policies](https://docs.cerbos.dev/cerbos/latest/policies/role_policies).
