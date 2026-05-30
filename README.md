# Kerberos.js

Kerberos.js is a JavaScript library for authorization solutions. It is a simple and lightweight Cerbos (Cerbos mini).

### Motivation:

- Cerbos is a powerful authorization engine, but it is written in Go and requires a separate server to run.
- We all know that gRPC is faster than REST API because it uses protobuf. But it can be even faster—by avoiding network requests altogether. Often, maintaining a separate service just for your permissions can be unnecessary, don’t you think?
- Kerberos.js is a lightweight alternative that can be used in the browser or server-side JavaScript applications (only up to 6 KB).
- Some features that are only available in the paid version of Cerbos(Cerbos Hub) are available here for free.
  - Embedded Cerbos features:
    - In-browser/serverless authorization;
    - isAllowed API;
- lack of some functionality in your Cerbos policies. With Kerberos.js you can use all the power of JavaScript to create your policies.
- if you are using Cerbos Hub and you want to test your policies locally, it can be a bit tricky. With Kerberos.js you can test your policies locally without any hassle.

### Features:

- [x] Derived roles;
- [x] Resource policies;
- [x] Principal policies;
- [x] Conditions;
- [x] Variables and constants;
- [x] Outputs;
- [x] Testing;
- [x] APIs:
  - [x] isAllowed API;
  - [x] CheckResourceSet API;
- [x] Audit logs;
- [x] Logger;
- [x] In-browser/serverless authorization;
- [x] Scopes;
- [x] Metadata;
- [x] Caching / storing dynamic policies (cache-agnostic, with a safe AST-based serialization codec);

---
**_P.S. We are tying to keep the API as close as possible to Cerbos. If you are familiar with Cerbos, you will feel at home with Kerberos.js._**

## Installation

```bash
npm install @alexify/kerberos
```

## Usage

```javascript
import { Kerberos, Effect } from '@alexify/kerberos';

const policies = [
  {
    resourcePolicy: {
      version: 'default',
      // Importing `common_roles` so they can be used in the resource policy.
      importDerivedRoles: ['common_roles'],
      // This resource file is reviewed for when checking permissions when a resource
      // is of `kind` "expense:object"
      resource: 'expense',
      rules: [
        // Rule 1: If the principal's role is 'ADMIN', then all actions are allowed.
        {
          actions: ['*'],
          effect: Effect.Allow,
          roles: ['ADMIN'],
        },
        // ...
      ],
    },
  },
  {
    principalPolicy: {
      principal: 'user1',
      version: 'default',
      variables: {
        isOpenExpense: ({ R }) => R.kind === 'expense' && R.attr.status === 'OPEN',
      },
      rules: [
        {
          resource: 'expense',
          actions: [
            {
              name: 'deny-sensitive-view',
              action: 'view',
              effect: Effect.Deny,
              condition: {
                match: ({ R }) => R.attr.amount > 10_000,
              },
            },
            {
              name: 'allow-own-delete-override',
              action: 'delete',
              effect: Effect.Allow,
              condition: {
                match: ({ V }) => V.isOpenExpense,
              },
            },
          ],
        },
      ],
    },
  },
];

const derivedRoles = {
  name: 'common_roles',
  description: 'Common dynamic roles used within the Finance Demo app',
  definitions: [
    {
      name: 'OWNER',
      parentRoles: ['USER'],
      condition: {
        match: ({ P, R }) => R.attr.ownerId === P.id,
      },
    },
    // ...
  ],
};

const kerberos = new Kerberos(policies, [derivedRoles], { logger: true });

const isAllowed = await kerberos.isAllowed({
  principal: {
    id: 'user1',
    roles: ['USER'],
    policyVersion: 'default',
  },
  action: 'view',
  resource: {
    id: 'expense1',
    kind: 'expense',
    attr: { amount: 5000, status: 'OPEN' },
  },
});

// checkResources API returns results with kerberosCallId for audit tracking
const results = await kerberos.checkResources({
  principal: { id: 'user1', roles: ['USER'] },
  resources: [
    {
      resource: { id: 'expense1', kind: 'expense' },
      actions: ['view', 'create'],
    },
  ],
});

console.log(results);
// {
//   kerberosCallId: 'b9c4362d-b92a-4c2b-9d49-845f00d7a372', // Generated UUID for audit tracking
//   results: [
//     {
//       resource: { id: 'expense1', kind: 'expense' },
//       actions: { view: 'EFFECT_ALLOW', create: 'EFFECT_DENY' },
//       outputs: []
//     }
//   ]
// }

console.log(isAllowed); // true
```

## Policy Types

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

### ResourcePolicy

`ResourcePolicy` keeps the existing Kerberos.js behavior. Rules are matched by action, then by `roles` or `derivedRoles`, and may also use `conditions`, `variables`, `constants`, `outputs`, versions, and scopes.

### PrincipalPolicy

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

### RolePolicy

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

### Mixed Policy Evaluation

When mixed policy types are present, Kerberos resolves each action in this order:

1. Find the matching `PrincipalPolicy` for the request principal.
2. If it returns an explicit `EFFECT_ALLOW` or `EFFECT_DENY`, use that result.
3. Otherwise, evaluate all matching `RolePolicy` entries for the principal roles.
4. If multiple role policies apply to the same action, `EFFECT_DENY` wins over `EFFECT_ALLOW`.
5. If the role layer is not applicable for that action, fall back to the matching `ResourcePolicy`.
6. If nothing matches, return `EFFECT_DENY`.

This keeps Kerberos.js aligned with the Cerbos-style principal override model described in the [Cerbos principal policies documentation](https://docs.cerbos.dev/cerbos/latest/policies/principal_policies) while extending the runtime with role-centric policy evaluation similar to [Cerbos role policies](https://docs.cerbos.dev/cerbos/latest/policies/role_policies).

## Configuration Options

The Kerberos constructor accepts an optional third parameter with configuration options:

```javascript
const kerberos = new Kerberos(policies, derivedRoles, {
  logger: true, // Legacy console audit logging with summary + table + debug(json)
  cache, // Optional: any cache solution exposing get(key) (keyv, cacheable, ...)
  codec, // Optional: custom (de)serialization codec for dynamic policies
  z, // Optional: validate with Zod
  ajv, // Optional: validate with Ajv
  typebox: Type, // Optional: switch Ajv validation to TypeBox builders
  getCallId: () => `custom-${Date.now()}`, // Custom call ID generator (optional)
});
```

### Options:

- **`logger`** (boolean | KerberosLogger): Enable audit logging.
  - `true` keeps the legacy console behavior with `group + summary + table + debug(json)`
  - `false` or omitted disables logging
  - a custom `console`-like logger keeps the legacy table/json flow
  - a structured logger such as `Pino` receives one structured audit entry per evaluated action
  - when logging is enabled, validation/runtime errors are logged and converted to fallback results instead of being rethrown:
    - `isAllowed(...)` returns `false`
    - `checkResources(...)` returns `{ results: [], kerberosCallId, reqId? }`
  - when logging is disabled, those errors continue to be thrown to the caller
- **`cache`** (CacheLike): An optional cache used as a fallback source for dynamic/stored policies. Any object exposing a `get(key)` method is accepted (keyv, cacheable, cache-manager, ...). See [Caching / Storing policies](#caching--storing-policies).
- **`codec`** (PolicyCodec): An optional `{ serialize, deserialize }` codec used to (de)serialize dynamic policy documents read from `cache`. Defaults to the built-in safe AST codec (`createSafeExprCodec`).
- **`z`**: Enables validation using the built-in Zod schema builders.
- **`ajv`**: Enables validation using the built-in JSON Schema builders compiled with Ajv.
- **`typebox`**: When used together with `ajv`, switches validation to the built-in TypeBox builders.
- **`getCallId`** (function): Custom function to generate call IDs for audit tracking. 
  - **Default behavior**: Uses `crypto.randomUUID()` in Node.js, `window.crypto.randomUUID()` in browsers, or falls back to a pseudo UUID generator
  - **Custom example**: `() => \`req-\${Date.now()}-\${Math.random()}\``

### Using Pino for Production Logging

If you want machine-readable audit logs in production, pass a `Pino` instance as the `logger` option:

```javascript
import pino from 'pino';
import { Kerberos } from '@alexify/kerberos';

const logger = pino({ level: 'info' });

const kerberos = new Kerberos(policies, derivedRoles, {
  logger,
});
```

With `Pino`, Kerberos emits structured audit entries that include `callId`, `reqId`, `reqKind`, `principalId`, `resourceId`, `action`, `effect`, `outputs`, and `meta`. This mode is better suited for production ingestion than the default console table output.

It also emits lifecycle logs such as `IsAllowed.start`, `IsAllowed.error`, `IsAllowed.finish`, `CheckResources.start`, and `CheckResources.finish`. When an error happens with logging enabled, Kerberos logs that error and returns a fallback response instead of throwing.

## Schema Validation

Kerberos.js supports multiple validation backends:

- **Zod** for consumers already using `zod`
- **JSON Schema + Ajv** for standards-based schema validation
- **TypeBox + Ajv** for typed schema builders backed by Ajv

Install only the validation stack you need:

```bash
npm install ajv
npm install @sinclair/typebox ajv
npm install zod
```

### Using Zod

```javascript
import { z } from 'zod';
import { Kerberos } from '@alexify/kerberos';

const kerberos = new Kerberos(policies, derivedRoles, { z });
```

### Using JSON Schema + Ajv

```javascript
import Ajv from 'ajv';
import { Kerberos, registerAjvKeywords } from '@alexify/kerberos';

const ajv = registerAjvKeywords(new Ajv({ strict: false }));
const kerberos = new Kerberos(policies, derivedRoles, { ajv });
```

### Using TypeBox + Ajv

```javascript
import Ajv from 'ajv';
import { Type } from '@sinclair/typebox';
import { Kerberos, registerAjvKeywords } from '@alexify/kerberos';

const ajv = registerAjvKeywords(new Ajv({ strict: false }));
const kerberos = new Kerberos(policies, derivedRoles, {
  ajv,
  typebox: Type,
});
```

### Using Explicit Builders

Kerberos.js also exports first-class schema builders and Ajv adapters if you want to compile validators yourself:

```javascript
import Ajv from 'ajv';
import {
  JsonSchemas,
  KerberosJsonSchemas,
  PrincipalPolicyJsonSchemas,
  ResourcePolicyJsonSchemas,
  createAjvAdapter,
  registerAjvKeywords,
} from '@alexify/kerberos';

const ajv = registerAjvKeywords(new Ajv({ strict: false }));

const requestValidator = createAjvAdapter(ajv, JsonSchemas.buildRequest());
const argsValidator = createAjvAdapter(ajv, KerberosJsonSchemas.buildCheckResourcesArgs());
const resourcePolicyValidator = createAjvAdapter(ajv, ResourcePolicyJsonSchemas.buildShape());
const principalPolicyValidator = createAjvAdapter(ajv, PrincipalPolicyJsonSchemas.buildShape());
```

### Notes About Function Fields

Kerberos policies can contain JavaScript functions in:

- conditions
- variables
- outputs

When using Ajv or TypeBox, Kerberos.js registers custom Ajv keywords so those function-bearing fields can still be validated at runtime. This keeps the DSL usable even though plain JSON Schema doesn't natively understand JavaScript functions.

### Call ID Generation

Every `checkResources` call automatically generates a unique `kerberosCallId` for audit tracking:

- **Node.js**: Uses `crypto.randomUUID()` 
- **Browser**: Uses `window.crypto.randomUUID()`
- **Fallback**: Pseudo UUID v4 generator if crypto APIs are unavailable
- **Custom**: Provide your own `getCallId` function for custom ID formats

This ID is included in both the response and audit logs for correlation.

## Outputs

Kerberos.js supports outputs functionality similar to Cerbos. You can define output expressions that are evaluated when policy rules are activated or when conditions are not met. These outputs are included in the API response and can be used to provide detailed information about policy decisions.

### Defining Outputs

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
          match: ({ }) => {
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

### Using checkResources with Outputs

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
//             timestamp: '2023-06-02T21:53:58.319506543+01:00',
//             message: 'System can only be accessed between 0800 and 1800'
//           }
//         }
//       ]
//     }
//   ]
// }
```

### Output Function Syntax

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

### Using Scopes and Policy Versions

Kerberos.js supports scoped policies and policy versions, allowing you to organize policies for different environments or versions.

Policy selection now depends on the policy type:

- **`ResourcePolicy`**
  - `resource.kind`
  - `resource.policyVersion` (defaults to `'default'` when omitted)
  - `resource.scope`
- **`PrincipalPolicy`**
  - `principal.id`
  - `principal.policyVersion` (defaults to `'default'` when omitted)
  - `principal.scope`

Current scope behavior matches the Cerbos-style model used by the library:

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

### Using Metadata

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
//   kerberosCallId: '01HHENANTHFD5DV3HZGDKB87PJ',
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
//           src: 'resource.leave_request.v20210210/acme#rule-001',
//           val: 'create_allowed:john'
//         }
//       ],
//       meta: {
//         actions: {
//           'view:public': {
//             matchedPolicy: 'resource.leave_request.v20210210/acme.corp',
//             matchedScope: 'acme.corp'
//           },
//           'approve': {
//             matchedPolicy: 'resource.leave_request.v20210210/acme.corp',
//             matchedScope: 'acme.corp'
//           }
//         },
//         effectiveDerivedRoles: [
//           'employee_that_owns_the_record',
//           'any_employee'
//         ]
//       }
//     }
//   ]
// }
```

The metadata includes:

- **matchedPolicy**: The name of the policy that produced the decision
- **matchedRule**: The exact rule that produced the decision for that action
- **matchedScope**: The full matched policy scope that produced the decision
- **effectiveDerivedRoles**: List of derived roles that were activated

`matchedPolicy` can now refer to either a resource policy source such as `resource.expense.vdefault/acme.corp` or a principal policy source such as `principal.sally.vdefault/acme.corp`.

## Caching / Storing policies

Kerberos.js can resolve policies dynamically from a remote store (Redis, MongoDB, PostgreSQL, in-memory, ...) instead of loading every policy up front. Following the same delegating philosophy as the `logger` option, Kerberos stays **agnostic**: it does not implement caching, TTL or invalidation logic itself. You pass a `cache`, and Kerberos simply calls `cache.get(key)` when it needs a policy. Everything else — storage, layering, expiry, and multi-host invalidation — is delegated to dedicated solutions such as [`keyv`](https://keyv.org), [`cacheable`](https://cacheable.org) (`CacheSync`) and [`qified`](https://qified.org).

### How it works (fallback layer)

Static policies passed to the constructor stay in memory and are always checked first. The `cache` is only consulted on a **miss**:

1. Resolve the policy by `kind` / `id` / `role` + `policyVersion` + scope chain in memory.
2. On a miss, and only if a `cache` is configured, call `await cache.get(key)` for each scope in the chain.
3. On a hit, the JSON document is passed through `codec.deserialize(...)` and rebuilt into a policy instance.
4. If nothing matches, the action falls back to `EFFECT_DENY` (unchanged behavior).

Cache keys follow this layout:

| Policy type     | Key format                                |
| --------------- | ----------------------------------------- |
| Resource policy | `resource:<kind>:<version>:<scope>`       |
| Principal policy| `principal:<id>:<version>:<scope>`        |
| Role policy     | `role:<role>:<version>:<scope>`           |
| Derived roles   | `derivedRoles:<name>`                     |

`<version>` defaults to `default`, and `<scope>` is empty for unscoped policies (e.g. `resource:expense:default:`).

### `CacheLike`

The only requirement is a single `get` method, so any cache backend works:

```typescript
type CacheLike = {
  get(key: string): unknown | Promise<unknown>;
};
```

### Dynamic policy format

Because a remote store can be Redis/Mongo/Postgres/etc., dynamic policies must be **JSON documents**. JSON has no concept of a JavaScript function, so `conditions`, `variables` and `outputs` are authored as **expression descriptors** `{ "$expr": "..." }` instead of JS functions:

```javascript
// In-memory policy (function form):
condition: { match: ({ R, P }) => R.attr.ownerId === P.id }

// Dynamic/stored policy (JSON, $expr form):
"condition": { "match": { "$expr": "R.attr.ownerId == P.id" } }
```

A full stored resource policy document looks like:

```json
{
  "resourcePolicy": {
    "version": "default",
    "resource": "document",
    "importDerivedRoles": ["doc_roles"],
    "variables": { "isOpen": { "$expr": "R.attr.status == 'OPEN'" } },
    "rules": [
      { "actions": ["*"], "effect": "EFFECT_ALLOW", "roles": ["ADMIN"] },
      { "actions": ["view"], "effect": "EFFECT_ALLOW", "derivedRoles": ["OWNER"] },
      {
        "name": "edit-when-open",
        "actions": ["edit"],
        "effect": "EFFECT_ALLOW",
        "derivedRoles": ["OWNER"],
        "condition": { "match": { "$expr": "V.isOpen" } },
        "output": { "when": { "ruleActivated": { "$expr": "({ owner: R.attr.ownerId, by: P.id })" } } }
      }
    ]
  }
}
```

Expressions are evaluated against the same request context as functions: `P` (principal), `R` (resource), `V` (variables), `C` (constants), plus a curated set of **safe language builtins** (see below).

### Allowed safe builtins

The default codec exposes a small, allowlisted subset of JavaScript that is useful in policy conditions without opening an `eval` trust boundary:

| Category | Supported constructs |
| -------- | -------------------- |
| **Math** | `Math.abs`, `Math.min`, `Math.max`, `Math.floor`, `Math.ceil`, `Math.round`, `Math.pow`, ... |
| **Date** | `new Date()`, `new Date(value)`, `Date.now()`, `Date.parse(...)`, `Date.UTC(...)`, and read-only instance methods such as `.getTime()`, `.getHours()`, `.toISOString()` |
| **Coercion / parsing** | `parseInt(...)`, `parseFloat(...)`, `Number(...)`, `String(...)`, `Boolean(...)`, `isNaN(...)`, `isFinite(...)` |
| **Value helpers** | Safe string/array methods such as `.includes()`, `.startsWith()`, `.slice()`, ... |

Anything outside this list — arbitrary constructors (`new Function`, `new Object`, ...), global roots like `process` / `require` / `globalThis`, or member keys such as `constructor` / `__proto__` — is rejected by the AST allowlist interpreter.

Example: a time-window condition (equivalent to the in-memory expense delete rule) in `{ $expr }` form:

```json
{
  "condition": {
    "match": {
      "$expr": "(Date.now() - new Date(R.attr.createdAt).getTime()) < 3600000 && R.attr.status == 'OPEN'"
    }
  }
}
```

### Example 1: a simple Keyv cache

```javascript
import { Keyv } from 'keyv';
import { Kerberos, serializePolicy } from '@alexify/kerberos';

const keyv = new Keyv();

// Store dynamic policies as JSON documents.
await keyv.set('derivedRoles:doc_roles', serializePolicy({
  name: 'doc_roles',
  definitions: [
    { name: 'OWNER', parentRoles: ['USER'], condition: { match: { $expr: 'R.attr.ownerId == P.id' } } },
  ],
}));

await keyv.set('resource:document:default:', serializePolicy({
  resourcePolicy: {
    version: 'default',
    resource: 'document',
    importDerivedRoles: ['doc_roles'],
    rules: [
      { actions: ['view'], effect: 'EFFECT_ALLOW', derivedRoles: ['OWNER'] },
    ],
  },
}));

// No static policies: everything is resolved from the cache on demand.
const kerberos = new Kerberos([], [], { cache: keyv });

const allowed = await kerberos.isAllowed({
  principal: { id: 'u1', roles: ['USER'] },
  action: 'view',
  resource: { id: 'doc1', kind: 'document', attr: { ownerId: 'u1' } },
});
// -> true
```

`serializePolicy(...)` validates every `{ $expr }` and returns a JSON-safe document. You can also store hand-written JSON directly.

### Example 2: Keyv + Cacheable + Qified (recommended for multi-host invalidation)

For production deployments running multiple Kerberos instances, the recommended setup combines:

- **`keyv`** — the storage engine (Redis, Mongo, Postgres, ...);
- **`cacheable`** — high-performance layer 1 / layer 2 caching with `CacheSync`;
- **`qified`** — the pub/sub transport that propagates `CacheSync` invalidation messages across hosts.

> **This is the recommended way to invalidate your policies across multiple hosts.** When a policy changes, update the store; `cacheable`'s `CacheSync` broadcasts the invalidation over `qified` pub/sub so every Kerberos instance drops its stale layer-1 copy. Kerberos itself only ever calls `cache.get` — it never has to know about invalidation.

```javascript
import { Cacheable } from 'cacheable';
import { createKeyv } from '@keyv/redis';
import { Qified } from 'qified';
import { createQified } from '@qified/redis';
import { Kerberos } from '@alexify/kerberos';

// Layer 2 (distributed) storage + layer 1 (in-process) cache.
const secondary = createKeyv('redis://localhost:6379');

// CacheSync over qified pub/sub keeps every host's layer-1 cache coherent.
const cacheSync = createQified({ uri: 'redis://localhost:6379' });

const cacheable = new Cacheable({
  secondary,
  cacheId: 'kerberos-policies',
  cacheSync, // distributed invalidation via qified pub/sub
});

const kerberos = new Kerberos([], [], { cache: cacheable });

// Reads transparently use layer 1 -> layer 2; writes/invalidations are handled
// by cacheable + qified, not by Kerberos.
const allowed = await kerberos.isAllowed({
  principal: { id: 'u1', roles: ['USER'] },
  action: 'view',
  resource: { id: 'doc1', kind: 'document', attr: { ownerId: 'u1' } },
});
```

### Serialization mechanism (security & performance)

Kerberos deliberately does **not** serialize raw JavaScript function bodies and **never uses `eval` / `new Function` / `fn.toString()`**. That classic "stringify a function, then eval it back" approach is unsafe and brittle:

- `new Function(body)` is equivalent to `eval(body)`. A denylist of dangerous tokens is weaker than an allowlist by design — it can be bypassed via bracket notation (`P['cons' + 'tructor']`), unicode escapes, `with`, `Reflect`, `Proxy` traps, and so on, with no end to the patches (see the `node-serialize` RCE, CVE-2017-5941).
- `fn.toString()` produces engine/bundler-specific output (V8 vs SpiderMonkey, Babel/esbuild/SWC, `[native code]`), which silently breaks serialization across environments.
- Re-`eval`ing on every cache hit pays a JIT-compilation cost exactly when load is highest.

Instead, the default codec (`createSafeExprCodec`) uses an **AST allowlist interpreter** built on the tiny, eval-free [`jsep`](https://ericsmekens.github.io/jsep/) parser:

1. Each `{ $expr }` string is parsed **once** into an AST, which is cached by expression string (`parse-once`).
2. Evaluation walks the AST per request with a strict allowlist — no `eval`, no `new Function`, no recompilation.
3. Identifiers resolve **only** against the `{ P, R, V, C }` context and curated safe builtins (`Math`, `Date`, `parseInt`, `parseFloat`, ... — so `constructor`, `process`, `require`, `globalThis` simply do not exist as roots). Member keys `__proto__` / `prototype` / `constructor` are blocked at the interpreter level regardless of how they are written. Method calls are limited to a whitelist of safe helpers on string/array/number/`Date` values, plus `Math.*` / `Date.*` static methods. Only `new Date(...)` is permitted as a constructor.
4. This keeps remote policies expressive (comparisons, logic, ternaries, member access, object/array literals, time windows via `Date`, numeric helpers via `Math`, parsing via `parseInt`/`parseFloat`) while remaining non-Turing-complete and safe to load from a shared store.

### Using a custom codec

The codec is pluggable. If you need different semantics you can supply your own `{ serialize, deserialize }`:

```javascript
const kerberos = new Kerberos([], [], { cache, codec: myCodec });
```

Other eval-free options such as [`jexl`](https://github.com/TomFrost/jexl) or [`cel-js`](https://www.npmjs.com/package/cel-js) (CEL, the same expression language Cerbos uses) are good fits. Function-serializing libraries like `serialize-javascript` can also be wrapped, but only if you fully trust the store and accept the `eval`-based trust boundary they require.

## Testing

```javascript
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { Kerberos, Tests } from '@alexify/kerberos';

describe('KerberosTests', () => {
  describe('Expense Policy (raw mode)', () => {
    const expenseTestPolicy = {
      name: 'Expenses test suite',
      principals: {
        sally: {
          id: 'sally',
          roles: ['USER'],
          attr: {
            department: 'SALES',
            region: 'EMEA',
          },
        },
        // ...
      },
      resources: {
        expense1: {
          id: 'expense1',
          kind: 'expense',
          attr: {
            ownerId: 'sally',
            createdAt: '2022-07-21T14:47:51.063Z',
            vendor: 'Flux Water Gear',
            region: 'EMEA',
            amount: 500,
            status: 'OPEN',
          },
        },
        // ...
      },
      tests: [
        {
          name: 'Sales Roles',
          input: {
            principals: ['sally', 'sydney'],
            resources: ['expense1', 'expense2'],
            actions: ['view', 'view:approver', 'update', 'delete', 'approve'],
          },
          expected: [
            {
              principal: 'sally',
              resource: 'expense1',
              actions: {
                view: 'EFFECT_ALLOW',
                'view:approver': 'EFFECT_DENY',
                delete: 'EFFECT_DENY',
                update: 'EFFECT_ALLOW',
                approve: 'EFFECT_DENY',
              },
            },
            // ...
          ],
        },
      ],
    };

    const kerberos = new Kerberos(policies, derivedRoles, { logger: true });
    const tests = new Tests.KerberosTests(kerberos, [expenseTestPolicy]);

    tests.run({}, { describe, it, assert });
    // or -> tests.run({ effectAsBoolean: true }, { describe, it, assert });
  });
});
```

### Testing with Outputs

You can also test policies with outputs functionality:

```javascript
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { Kerberos, Effect } from '@alexify/kerberos';

describe('Outputs functionality', () => {
  const outputsPolicy = {
    resourcePolicy: {
      version: "default",
      resource: "system_access",
      rules: [
        {
          name: "admin-access",
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

  it('should return outputs when rules are activated', async () => {
    const kerberos = new Kerberos([outputsPolicy]);
    
    const results = await kerberos.checkResources({ 
      principal: { id: "alice", roles: ["admin"] }, 
      resources: [{ resource: { id: "system1", kind: "system_access" }, actions: ['login'] }]
    });

    // Check that we get outputs
    assert.ok(results.results[0].outputs);
    assert.strictEqual(results.results[0].outputs.length, 1);
    
    const output = results.results[0].outputs[0];
    assert.strictEqual(output.src, 'resource.system_access.vdefault#admin-access');
    assert.strictEqual(output.val.message, 'Admin access granted');
    assert.strictEqual(output.val.admin, 'alice');
  });
});
```

### Used by

<table style="text-align:center;">
<tr>
<td><a href="https://hirevel.com" target="_blank"><img src="https://cdn.hirevel.com/hirevel/logo.svg" width="200" valign="middle" /></a></td>
</tr>
</table>
