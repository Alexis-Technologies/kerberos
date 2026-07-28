# Decision metadata (includeMeta)

When `includeMeta: true` is set, the response includes additional metadata about policy evaluation:

```javascript
const results = await kerberos.checkResources({
  principal: { 
    id: 'alice', 
    scope: 'acme.corp',
    roles: ['employee'] 
  },
  resources: [
    {
      resource: { 
        id: 'XX125', 
        kind: 'leave_request',
        policyVersion: '20210210',
        scope: 'acme.corp' 
      },
      actions: ['view:public', 'approve']
    }
  ],
  includeMeta: true
});

console.log(results);
// {
//   reqId: 'test-request',
//   kerberosCallId: 'b9c4362d-b92a-4c2b-9d49-845f00d7a372',
//   results: [
//     {
//       resource: {
//         id: 'XX125',
//         kind: 'leave_request',
//         policyVersion: '20210210',
//         scope: 'acme.corp'
//       },
//       actions: {
//         'view:public': 'EFFECT_ALLOW',
//         'approve': 'EFFECT_DENY'
//       },
//       outputs: [
//         {
//           src: 'resource.leave_request.v20210210/acme.corp#rule-001',
//           val: 'create_allowed:john'
//         }
//       ],
//       meta: {
//         actions: {
//           'view:public': {
//             matchedPolicy: 'resource.leave_request.v20210210/acme.corp',
//             matchedRule: 'resource.leave_request.v20210210/acme.corp#rule-001',
//             matchedScope: 'acme.corp'
//           },
//           'approve': {
//             matchedPolicy: 'resource.leave_request.v20210210/acme.corp',
//             reason: 'condition-not-met'
//           }
//         },
//         effectiveDerivedRoles: [
//           'employee_that_owns_the_record',
//           'any_employee'
//         ],
//         resolution: [
//           { source: 'principal', id: 'alice', version: 'default',
//             scopesSearched: ['acme.corp', 'acme', ''], matchedScope: null },
//           { source: 'resource', id: 'leave_request', version: '20210210',
//             scopesSearched: ['acme.corp', 'acme', ''], matchedScope: 'acme.corp' }
//         ]
//       }
//     }
//   ]
// }
```

Per action, `meta.actions[action]` includes:

- **matchedPolicy**: The policy source that produced the decision — a resource source such as `resource.expense.vdefault/acme.corp`, a principal source such as `principal.sally.vdefault/acme.corp`, or a role source such as `role.USER.vdefault`
- **matchedRule**: The exact rule that produced the decision
- **matchedScope**: The scope of the matched policy (present for scoped policies)
- **reason** (denied actions only): why nothing allowed the action — `'rule-miss'` (no rule targeted the action / matched the principal's roles), `'condition-not-met'` (a rule targeted it but its condition failed) or `'policy-miss'` (no applicable policy existed at all)

At the result level:

- **effectiveDerivedRoles**: derived roles that activated for this resource
- **resolution** (decision trace): every policy lookup that was attempted — `{ source, id, version, scopesSearched, matchedScope, origin? }` entries (with `origin: 'cache'` for cache-resolved policies) plus `{ source: 'relations', name, relation, matched, reason? }` entries for [relation-backed derived roles](/guide/rebac). The same trace appears in [`planResources` meta](/guide/query-plans).
