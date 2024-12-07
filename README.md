# Kerberos.js

Kerberos.js is a JavaScript library for authorization solutions. It is a simple and lightweight Cerbos (Cerbos mini).

Motivation:
- Cerbos is a powerful authorization engine, but it is written in Go and requires a separate server to run.
- We all know that gRPC is faster than REST API because it uses protobuf. But it can be even faster—by avoiding network requests altogether. Often, maintaining a separate service just for your permissions can be unnecessary, don’t you think?
- Kerberos.js is a lightweight alternative that can be used in the browser or server-side JavaScript applications (only up to 6 KB).
- Some features that are only available in the paid version of Cerbos(Cerbos Hub) are available here for free.
  - Embedded Cerbos features:
    - In-browser/serverless authorization;
    - isAllowed API;
- lack of some functionality in your Cerbos policies. With Kerberos.js you can use all the power of JavaScript to create your policies.
- if you are using Cerbos Hub and you want to test your policies locally, it can be a bit tricky. With Kerberos.js you can test your policies locally without any hassle.


Features:
- [x] Derived roles;
- [x] Resource policies;
- [x] Conditions;
- [x] Variables and constants;
- [x] Testing;
- [x] APIs:
  - [x] isAllowed API;
  - [x] CheckResourceSet API;
- [x] Audit logs;
- [x] Logger;
- [x] In-browser/serverless authorization;


- [ ] outputs (WIP); 
- [ ] scopes (WIP);
- [ ] metadata (WIP);

We are tying to keep the API as close as possible to Cerbos. If you are familiar with Cerbos, you will feel at home with Kerberos.js.

## Installation

```bash
npm install @alexify/kerberos
```

## Usage

```javascript
import { Kerberos } from '@alexify/kerberos';

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

const kerberos = new Kerberos(policies, derivedRoles, { logger: true });

const isAllowed = await kerberos.isAllowed({
  principal: {
    id: 'user1',
    roles: ['USER'],
  },
  action: 'view',
  resource: {
    id: 'expense1',
    kind: 'expense',
  },
});

console.log(isAllowed); // true
```

### Sponsors

[![Cerbos](https://cerbos.dev/img/logo.svg)](https://cerbos.dev)

