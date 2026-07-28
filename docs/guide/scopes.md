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
