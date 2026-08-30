<script setup>
import Playground from './.vitepress/theme/components/Playground.vue';
</script>

# Playground

Edit the policies and the request, and the decision updates as you type. Nothing is sent anywhere — the whole engine is running in this tab, which is the point: Kerberos.js is the same library in your browser as it is on your server.

<ClientOnly>
  <Playground />
</ClientOnly>

## What is running

The playground constructs a real `Kerberos` instance on every change:

```javascript
import { Kerberos, createSafeExprCodec, deserializePolicy } from '@alexify/kerberos';
import jsep from 'jsep';

const codec = createSafeExprCodec({ jsep });
const kerberos = new Kerberos(policies.map((p) => deserializePolicy(p, codec)), derivedRoles);

await kerberos.checkResources(request);
```

Conditions here are written as `{ "$expr": "..." }` strings rather than JavaScript functions, so every example above is also a valid **stored** policy — the exact shape you would keep in Redis or Postgres. Those strings are parsed into an AST and walked against an allowlist; there is no `eval` and no `new Function` anywhere in that path. See [Serialization & security](/guide/serialization).

In your own code you can skip the codec entirely and write conditions as plain functions:

```javascript
condition: { match: ({ R, P }) => R.attr.ownerId === P.id }
```

## Where to go next

- [Quick Start](/guide/getting-started) — the same policy, written with JavaScript conditions
- [Policy Types](/guide/policy-types) — resource, principal and role policies, and how they combine
- [Query Plans](/guide/query-plans) — turning the `planResources` filter above into a SQL `WHERE` clause
- [Caching / dynamic policies](/guide/caching) — loading `$expr` policies from a store at runtime
