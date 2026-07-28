# Outputs

Kerberos.js supports outputs functionality similar to Cerbos. You can define output expressions that are evaluated when policy rules are activated or when conditions are not met. These outputs are included in the API response and can be used to provide detailed information about policy decisions.

## Defining Outputs

You can add output functions to your policy rules:

```javascript
const policyWithOutputs = {
  resourcePolicy: {
    version: 'default',
    resource: 'system_access',
    rules: [
      {
        name: 'working-hours-only',
        actions: ['*'],
        effect: Effect.Deny,
        roles: ['*'],
        condition: {
          match: () => {
            const now = new Date();
            return now.getHours() > 18 || now.getHours() < 8;
          }
        },
        output: {
          when: {
            ruleActivated: ({ P, R }) => ({
              principal: P.id,
              resource: R.id,
              timestamp: new Date().toISOString(),
              message: "System can only be accessed between 0800 and 1800"
            }),
            conditionNotMet: ({ P, R }) => ({
              principal: P.id,
              resource: R.id,
              timestamp: new Date().toISOString(),
              message: "System can be accessed at this time"
            })
          }
        }
      },
      {
        name: 'admin-access',
        actions: ['*'],
        effect: Effect.Allow,
        roles: ['admin'],
        output: {
          when: {
            ruleActivated: ({ P }) => ({
              message: "Admin access granted",
              admin: P.id
            })
          }
        }
      }
    ]
  }
};
```

## Using checkResources with Outputs

The `checkResources` method returns outputs in the response:

```javascript
const results = await kerberos.checkResources({
  principal: {
    id: 'john',
    roles: ['user']
  },
  resources: [
    {
      resource: {
        id: 'bastion_002',
        kind: 'system_access'
      },
      actions: ['login']
    }
  ]
});

console.log(results);
// {
//   results: [
//     {
//       resource: { id: 'bastion_002', kind: 'system_access' },
//       actions: { login: 'EFFECT_DENY' },
//       outputs: [
//         {
//           src: 'resource.system_access.vdefault#working-hours-only',
//           val: {
//             principal: 'john',
//             resource: 'bastion_002',
//             timestamp: '2023-06-02T20:53:58.319Z',
//             message: 'System can only be accessed between 0800 and 1800'
//           }
//         }
//       ]
//     }
//   ]
// }
```

## Output Function Syntax

Output functions are JavaScript functions that receive the request context and return any value:

```javascript
// Basic function syntax
({ P, R, V, C }) => {
  // Your logic here
  return {
    principal: P.id,
    resource: R.kind,
    timestamp: new Date().toISOString()
  };
}
```

Available context parameters:

- **P**: Principal object with `id`, `roles`, and `attr`
- **R**: Resource object with `id` and `kind`
- **V**: Variables (computed values)
- **C**: Constants (static values)

Output functions are called when:

- **ruleActivated**: The rule matches and its condition is satisfied
- **conditionNotMet**: The rule matches but its condition is not satisfied

The output `src` field reflects the policy type that produced it:

- Resource policy example: `resource.expense.vdefault#rule-name`
- Principal policy example: `principal.sally.vdefault#rule-name`
