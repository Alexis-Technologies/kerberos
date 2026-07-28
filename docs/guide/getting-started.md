# Quick Start

A resource policy with a **derived role** (a role computed per request — here, "the owner of this expense"), checked through both public APIs:

```javascript
import { Kerberos, Effect } from '@alexify/kerberos';

const expensePolicy = {
  resourcePolicy: {
    resource: 'expense', // applies to resources of kind 'expense'
    version: 'default',
    importDerivedRoles: ['common_roles'],
    rules: [
      { actions: ['*'], effect: Effect.Allow, roles: ['ADMIN'] },
      { actions: ['view', 'delete'], effect: Effect.Allow, derivedRoles: ['OWNER'] },
      {
        actions: ['view'],
        effect: Effect.Allow,
        roles: ['USER'],
        condition: { match: ({ R }) => R.attr.status === 'OPEN' },
      },
    ],
  },
};

const commonRoles = {
  name: 'common_roles',
  definitions: [
    { name: 'OWNER', parentRoles: ['USER'], condition: { match: ({ P, R }) => R.attr.ownerId === P.id } },
  ],
};

const kerberos = new Kerberos([expensePolicy], [commonRoles]);

// Single decision:
await kerberos.isAllowed({
  principal: { id: 'sally', roles: ['USER'] },
  action: 'delete',
  resource: { id: 'expense1', kind: 'expense', attr: { ownerId: 'sally', status: 'OPEN' } },
}); // → true (OWNER derived role)

// Batch decisions:
const response = await kerberos.checkResources({
  principal: { id: 'frank', roles: ['USER'] },
  resources: [
    { resource: { id: 'expense1', kind: 'expense', attr: { ownerId: 'sally', status: 'OPEN' } }, actions: ['view', 'delete'] },
  ],
});
// {
//   kerberosCallId: 'b9c4362d-…', // generated UUID for audit correlation
//   results: [{
//     resource: { id: 'expense1', kind: 'expense' },
//     actions: { view: 'EFFECT_ALLOW', delete: 'EFFECT_DENY' },
//     outputs: [],
//   }],
// }
```

From here: [principal and role policies](/guide/policy-types) for overrides and allowlists, [`planResources`](/guide/query-plans) for "which resources can this principal access" filters, [dynamic policies](/guide/caching) for cache-stored rules, and [ReBAC](/guide/rebac) for relationship-based access.
