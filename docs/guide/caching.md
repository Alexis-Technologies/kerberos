# Caching / Storing policies

Kerberos.js can resolve policies dynamically from a remote store (Redis, MongoDB, PostgreSQL, in-memory, ...) instead of loading every policy up front. Following the same delegating philosophy as the `logger` option, Kerberos stays **agnostic**: it does not implement caching, TTL or invalidation logic itself. You pass a `cache`, and Kerberos simply calls `cache.get(key)` when it needs a policy. Everything else — storage, layering, expiry, and multi-host invalidation — is delegated to dedicated solutions such as [`keyv`](https://keyv.org), [`cacheable`](https://cacheable.org) (`CacheSync`) and [`qified`](https://qified.org).

## How it works (fallback layer)

Static policies passed to the constructor stay in memory and are always checked first. The `cache` is only consulted on a **miss**:

1. Resolve the policy by `kind` / `id` / `role` + `policyVersion` + scope chain in memory.
2. On a miss, and only if a `cache` is configured, call `await cache.get(key)` for each scope in the chain.
3. On a hit, the JSON document is handled according to the `codec` option (see below).
4. If nothing matches, the action falls back to `EFFECT_DENY` (unchanged behavior).

::: warning
The whole scope chain is walked **in memory first** — source precedence beats scope specificity. A static base-scope (`''`) policy therefore permanently shadows a *more specific* cached policy for the same `(kind/id/role, version)`: in a hybrid deployment (static org-wide defaults in code + per-tenant overrides in the store) the cached tenant override — including a tightening Deny — silently never loads. Don't combine a static policy and cached policies for the same id/version across scopes; keep each (id, version) fully static or fully cache-backed.
:::

Cache keys follow this layout:

| Policy type     | Key format                                |
| --------------- | ----------------------------------------- |
| Resource policy | `resource:<kind>:<version>:<scope>`       |
| Principal policy| `principal:<id>:<version>:<scope>`        |
| Role policy     | `role:<role>:<version>:<scope>`           |
| Derived roles   | `derivedRoles:<name>`                     |

`<version>` defaults to `default`, and `<scope>` is empty for unscoped policies (e.g. `resource:expense:default:`).

## `CacheLike`

The only requirement is a single `get` method, so any cache backend works:

```typescript
type CacheLike = {
  get(key: string): unknown | Promise<unknown>;
};
```

## `codec` option — three modes

The `codec` option controls how a value returned from the cache is transformed before being passed to the policy constructor:

| Provided option | Behaviour |
| --------------- | --------- |
| `codec: { jsep }` | Kerberos uses the **built-in AST allowlist evaluator** with the pre-configured `jsep` instance you supply. `{ $expr: "..." }` descriptors are resolved into runtime evaluator functions. |
| `codec: { deserialize }` | Your own **custom deserialization** function is called on the raw cached value. |
| *(omit `codec`)* | The cached value is **passed as-is** to the policy constructor — no `{ $expr }` transformation. Use this when your stored JSON documents don't contain expression descriptors (e.g. plain rules with static `effect` and `roles`). |

::: warning
**`jsep` is not a dependency of `@alexify/kerberos`.** It is deliberately kept out so you only pay for it when you need expression-based policies. Install it (and any plugins) separately and pass the instance to Kerberos.
:::

```bash
npm install jsep @jsep-plugin/object @jsep-plugin/ternary @jsep-plugin/new
```

## Dynamic policy format

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

## Allowed safe builtins

The default codec exposes a small, allowlisted subset of JavaScript that is useful in policy conditions without opening an `eval` trust boundary — `Math`, `Date`, coercion/parsing helpers and safe string/array methods. See [Safe builtins](/reference/safe-builtins) for the full list.

Anything outside that list — arbitrary constructors (`new Function`, `new Object`, ...), global roots like `process` / `require` / `globalThis`, or member keys such as `constructor` / `__proto__` — is rejected by the AST allowlist interpreter.

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

## Example 1: a simple Keyv cache

```javascript
import { Keyv } from 'keyv';
import jsep from 'jsep';
import jsepObject from '@jsep-plugin/object';
import jsepTernary from '@jsep-plugin/ternary';
import jsepNew from '@jsep-plugin/new';
import { Kerberos, serializePolicy } from '@alexify/kerberos';

// 1. Configure jsep once — register plugins and any extra unary operators.
jsep.plugins.register(jsepObject, jsepTernary, jsepNew);
jsep.addUnaryOp('typeof');

const keyv = new Keyv();

// 2. Serialize policies into JSON-safe documents (validates $expr ASTs via jsep).
await keyv.set('derivedRoles:doc_roles', serializePolicy({
  name: 'doc_roles',
  definitions: [
    { name: 'OWNER', parentRoles: ['USER'], condition: { match: { $expr: 'R.attr.ownerId == P.id' } } },
  ],
}, { jsep }));

await keyv.set('resource:document:default:', serializePolicy({
  resourcePolicy: {
    version: 'default',
    resource: 'document',
    importDerivedRoles: ['doc_roles'],
    rules: [
      { actions: ['view'], effect: 'EFFECT_ALLOW', derivedRoles: ['OWNER'] },
    ],
  },
}, { jsep }));

// 3. Pass the same jsep instance so Kerberos can evaluate $expr at runtime.
const kerberos = new Kerberos([], [], { cache: keyv, codec: { jsep } });

const allowed = await kerberos.isAllowed({
  principal: { id: 'u1', roles: ['USER'] },
  action: 'view',
  resource: { id: 'doc1', kind: 'document', attr: { ownerId: 'u1' } },
});
// -> true
```

`serializePolicy(shape, { jsep })` validates every `{ $expr }` string via full AST parse and returns a JSON-safe document. Passing `{ jsep }` is optional — without it the function still rejects raw JS functions but skips AST validation (expressions are validated at deserialize time instead). You can also store hand-written JSON directly.

## Example 2: Keyv + Cacheable + Qified (recommended for multi-host invalidation)

For production deployments running multiple Kerberos instances, the recommended setup combines:

- **`keyv`** — the storage engine (Redis, Mongo, Postgres, ...);
- **`cacheable`** — high-performance layer 1 / layer 2 caching with `CacheSync`;
- **`qified`** — the pub/sub transport that propagates `CacheSync` invalidation messages across hosts.

::: tip
**This is the recommended way to invalidate your policies across multiple hosts.** When a policy changes, update the store; `cacheable`'s `CacheSync` broadcasts the invalidation over `qified` pub/sub so every Kerberos instance drops its stale layer-1 copy. Kerberos itself only ever calls `cache.get` — it never has to know about invalidation.
:::

```javascript
import { Cacheable } from 'cacheable';
import { createKeyv } from '@keyv/redis';
import { Qified } from 'qified';
import { createQified } from '@qified/redis';
import jsep from 'jsep';
import jsepObject from '@jsep-plugin/object';
import jsepTernary from '@jsep-plugin/ternary';
import jsepNew from '@jsep-plugin/new';
import { Kerberos } from '@alexify/kerberos';

// Configure jsep once per process.
jsep.plugins.register(jsepObject, jsepTernary, jsepNew);
jsep.addUnaryOp('typeof');

// Layer 2 (distributed) storage + layer 1 (in-process) cache.
const secondary = createKeyv('redis://localhost:6379');

// CacheSync over qified pub/sub keeps every host's layer-1 cache coherent.
const cacheSync = createQified({ uri: 'redis://localhost:6379' });

const cacheable = new Cacheable({
  secondary,
  cacheId: 'kerberos-policies',
  cacheSync, // distributed invalidation via qified pub/sub
});

const kerberos = new Kerberos([], [], { cache: cacheable, codec: { jsep } });

// Reads transparently use layer 1 -> layer 2; writes/invalidations are handled
// by cacheable + qified, not by Kerberos.
const allowed = await kerberos.isAllowed({
  principal: { id: 'u1', roles: ['USER'] },
  action: 'view',
  resource: { id: 'doc1', kind: 'document', attr: { ownerId: 'u1' } },
});
```
