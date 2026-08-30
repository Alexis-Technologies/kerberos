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
  - each `principal.roles[]` entry
  - `principal.policyVersion` (defaults to `'default'` when omitted)
  - `principal.scope`

Scope behavior follows the Cerbos-style model:

- If `scope` is **not** provided for the relevant side of the lookup, Kerberos.js evaluates only the base policy without a scope.
- If `scope` **is** provided, Kerberos.js searches from the most specific scope to the least specific scope, and finally falls back to the base policy.
- Example search chain for `scope: 'acme.corp'`: `acme.corp -> acme -> ''`

When both policy types are loaded, Kerberos first resolves principal overrides using the principal scope/version chain and then falls back to resource policy lookup when the principal policy is not applicable for a given action.

## How the scope chain is evaluated

Matching Cerbos's `SCOPE_PERMISSIONS_OVERRIDE_PARENT` (its default), the chain is not a lookup for one policy — every policy found along it participates, and evaluation is **per action, per principal role**:

- The first scope whose policy produces a decision (allow or deny) for an action and a role **seals** it; policies further up cannot change it.
- A rule whose condition fails decides nothing — the walk **falls through** to the parent scope for that action.
- The walk runs per principal role, so a deny sealing one role at a specific scope does not stop another role from winning an allow at the base scope (allow from any role wins across roles).
- A scope with no policy at all is simply skipped (Cerbos's `lenientScopeSearch`; Kerberos has no strict mode).

Which scope drives which policy type: **resource policies and role policies** walk the *resource's* scope chain; **principal policies** walk the *principal's*. (Cerbos's docs describe role-policy scope as the principal's, but its engine — and a live PDP — match it against the resource's; see [DIVERGENCES.md](https://github.com/Alexis-Technologies/kerberos/blob/main/conformance/DIVERGENCES.md).)

## Wildcards

Name fields glob, exactly as in Cerbos: a bare `*` matches anything; in any other pattern `*` matches within a single `:`-delimited segment (`view:*` matches `view:public` but neither the bare `view` nor `view:a:b`), and `**` crosses segments. Globs work in resource-policy `actions` and `roles`, principal-policy `resource` and `action`, role-policy `resource` and `allowActions`, and derived-role `parentRoles`. `rules[].derivedRoles` references are exact names — Cerbos's schema rejects globs there too.


Example:

```javascript
const results = await kerberos.checkResources({
  reqId: 'test-request',
  principal: {
    id: 'alice',
    policyVersion: '20210210',  // Optional: available in request context and logs
    scope: 'acme.corp',         // Optional: available in request context and logs
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
