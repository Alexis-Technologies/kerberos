# Scopes and Policy Versions

Kerberos.js supports scoped policies and policy versions, allowing you to organize policies for different environments or versions.

Policy selection depends on the policy type:

- **`ResourcePolicy`**
  - `resource.kind`
  - `resource.policyVersion` (defaults to `'default'` when omitted)
  - `resource.scope`
- **`PrincipalPolicy`**
  - `principal.id`
  - `principal.policyVersion` (defaults to `'default'` when omitted)
  - `principal.scope`
- **`RolePolicy`**
  - each `principal.roles[]` entry (plus every `parentRoles` ancestor)
  - `resource.policyVersion` (defaults to `'default'` when omitted)
  - `resource.scope`

Scope behavior follows the Cerbos-style model:

- If `scope` is **not** provided for the relevant side of the lookup, Kerberos.js evaluates only the base policy without a scope.
- If `scope` **is** provided, Kerberos.js searches from the most specific scope to the least specific scope, and finally falls back to the base policy.
- Example search chain for `scope: 'acme.corp'`: `acme.corp -> acme -> ''`

When both policy types are loaded, Kerberos first resolves principal overrides using the principal's scope/version chain, and falls back to the resource layer — resource policies and role policies, both keyed by the resource's version and scope — when no principal policy decides the action.

## Which version applies to what

| Policy            | Looked up by                                          | Version                   | Scope chain       |
| ----------------- | ----------------------------------------------------- | ------------------------- | ----------------- |
| `resourcePolicy`  | `resource.kind`                                       | `resource.policyVersion`  | `resource.scope`  |
| `principalPolicy` | `principal.id`                                        | `principal.policyVersion` | `principal.scope` |
| `rolePolicy`      | each `principal.roles[]` (+ `parentRoles` ancestors)  | `resource.policyVersion`  | `resource.scope`  |
| `derivedRoles`    | name, from the resource policy's `importDerivedRoles` | — (unversioned)           | —                 |

Three consequences:

- The version is **fixed along the whole scope chain** — the walk never crosses versions — and there is **no fallback**: asking for a version no policy carries resolves to nothing rather than to `'default'`.
- A request may mix versions. `principal.policyVersion: 'v2'` with an unversioned resource evaluates the principal policy at `v2` and the resource/role layer at `'default'`.
- In `checkResources` the principal chain is resolved once per batch while every resource uses its own `policyVersion`; `planResources` echoes the resource's version back as `policyVersion`.

Cerbos 0.41+ differs here: it selects principal policies by the **resource's** version, a regression against its own documentation and its pre-0.41 engine. When the same policies are served by both engines, send the same value in both fields. See [DIVERGENCES.md](https://github.com/Alexis-Technologies/kerberos/blob/main/conformance/DIVERGENCES.md).

## How the scope chain is evaluated

Matching Cerbos's `SCOPE_PERMISSIONS_OVERRIDE_PARENT` (its default), the chain is not a lookup for one policy — every policy found along it participates, and evaluation is **per action, per principal role**:

- The first scope whose policy produces a decision (allow or deny) for an action and a role **seals** it; policies further up cannot change it.
- A rule whose condition fails decides nothing — the walk **falls through** to the parent scope for that action.
- The walk runs per principal role, so a deny sealing one role at a specific scope does not stop another role from winning an allow at the base scope (allow from any role wins across roles).
- A scope with no policy at all is simply skipped (Cerbos's `lenientScopeSearch`; Kerberos has no strict mode).

Which scope drives which policy type: **resource policies and role policies** walk the *resource's* scope chain; **principal policies** walk the *principal's*. (Cerbos's docs describe role-policy scope as the principal's, but its engine — and a live PDP — match it against the resource's; see [DIVERGENCES.md](https://github.com/Alexis-Technologies/kerberos/blob/main/conformance/DIVERGENCES.md).)

## Wildcards

Name fields glob, exactly as in Cerbos: a bare `*` matches anything; in any other pattern `*` matches within a single `:`-delimited segment (`view:*` matches `view:public` but neither the bare `view` nor `view:a:b`), and `**` crosses segments. Globs work in resource-policy `actions` and `roles`, principal-policy `resource` and `action`, role-policy `resource` and `allowActions`, and derived-role `parentRoles`. `rules[].derivedRoles` references are exact names — Cerbos's schema rejects globs there too.

Resource **kind** names are compared after Cerbos's own sanitization (`namer.SanitizedResource`): for a name shaped like `foo`, `foo:bar`, `foo-bar` or `foo/bar`, every run of characters outside `[A-Za-z0-9_.]` becomes `_` — on the policy field and on `resource.kind` alike. So `gk*` does match the kind `gka:b` (which is `gka_b` at match time), `doc:*` matches no kind at all (a pattern is never sanitized, and no sanitized kind keeps a `:`), and `ka-b`, `ka_b` and `ka/b` are one and the same resource — declaring policies for two of those spellings throws `Duplicate resource policy`. Principal ids and role names are not sanitized.


Example:

```javascript
const results = await kerberos.checkResources({
  reqId: 'test-request',
  principal: {
    id: 'alice',
    policyVersion: '20210210',  // Optional: selects the principal policy version
    scope: 'acme.corp',         // Optional: principal policy scope chain
    roles: ['employee'],
    attr: {
      department: 'accounting',
      geography: 'GB'
    }
  },
  resources: [
    {
      resource: {
        id: 'XX125',
        kind: 'leave_request',
        policyVersion: '20210210', // Optional: specify resource policy version
        scope: 'acme.corp',        // Optional: specify resource scope
        attr: {
          department: 'accounting',
          owner: 'john'
        }
      },
      actions: ['view:public', 'approve', 'create']
    }
  ],
  includeMeta: true  // Optional: include metadata in response
});
```
