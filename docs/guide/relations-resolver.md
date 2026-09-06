# The built-in Zanzibar-lite resolver

```javascript
import { RelationResolver } from '@alexify/kerberos/relations';

const relations = new RelationResolver({
  schema: {
    relationSchema: {
      caveats: {
        // ABAC-on-ReBAC: a named condition evaluated against { P, ctx }.
        valid_ip: { match: ({ P, ctx }) => ctx.allowed_ips.includes(P.attr.ip) },
      },
      definitions: {
        user: {},
        group: { relations: { member: ['user', 'group#member'] } }, // nested groups
        folder: {
          relations: { parent: ['folder'], viewer: ['user', 'group#member'] },
          permissions: { view: { anyOf: ['viewer', { via: 'parent', permission: 'view' }] } }, // recursive!
        },
        document: {
          relations: {
            parent: ['folder'],
            owner: ['user'],
            editor: ['user', { type: 'user', caveat: 'valid_ip' }], // caveated subjects
            viewer: ['user', 'user:*', 'group#member'],             // incl. the wildcard
            auditor: ['user'],
          },
          permissions: {
            edit: { anyOf: ['owner', 'editor'] },                                  // union (+)
            view: { anyOf: ['edit', 'viewer', { via: 'parent', permission: 'view' }] }, // arrow (->)
            audit: { allOf: ['viewer', 'auditor'] },                               // intersection (&)
            read_only: { exclude: { base: 'viewer', subtract: ['editor'] } },      // exclusion (-)
            review_all: { via: 'parent', permission: 'view', all: true },          // intersection arrow (.all)
          },
        },
      },
    },
  },
  // Static tuples: canonical SpiceDB strings or objects (with caveat context).
  tuples: [
    'document:readme#owner@user:olga',
    'document:readme#viewer@group:eng#member',
    'group:eng#member@user:sara',
    'document:readme#parent@folder:docs',
    'document:readme#auditor@user:vera',
    { resource: 'document:readme', relation: 'editor', subject: 'user:cara', caveat: { name: 'valid_ip', context: { allowed_ips: ['10.0.0.1'] } } },
  ],
});

// Standalone SpiceDB-flavoured API:
await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:sara' }); // true
await relations.lookupSubjects({ resource: 'document:readme', permission: 'view' }); // who can view?
await relations.lookupResources({ subject: 'user:sara', permission: 'view', resourceType: 'document' }); // what can sara view?

// And it IS a `relations` resolver:
const kerberos = new Kerberos([policy], [derivedRoles], { relations });
```

What it borrows from SpiceDB (see [`src/Relations/`](https://github.com/Alexis-Technologies/kerberos/blob/main/src/Relations)):

- the **userset-rewrite algebra** (`union` / `intersection` / `exclusion` / arrows incl. `.all`, wildcard subjects `user:*`, subject relations `group#member`) with fail-fast schema compilation (unknown references, relation↔permission collisions and invalid arrows throw at construction);
- the **recursive check** with short-circuiting (union stops at the first ALLOW, intersection at the first DENY, exclusion is base-first and order-sensitive);
- **per-request memoization** of subproblems (`(resource#relation@subject)`), shared across a whole `checkResources` batch; concurrent identical document reads coalesce (the in-process analog of SpiceDB's singleflight);
- **depth limiting instead of cycle tracking** (`maxDepth`, default 50) — visited-sets are semantically unsound under exclusions, so cyclic relationship data throws a typed `KerberosRelationsError`;
- **caveats** (ABAC-on-ReBAC): named conditions bound to tuples with write-time context; at check time the written context takes precedence over the check-time `context` argument, and the condition sees `{ P, ctx }`. Caveats are ordinary Kerberos `Conditions` — for JSON/cache-stored schemas author them as `{ match: { $expr: '...' } }` and pass a codec built with `createSafeExprCodec({ jsep, roots: ['P', 'ctx'] })` (same eval-free guarantees as dynamic policies). A throwing or false caveat fails closed. There is deliberately no CEL and no partial evaluation of caveats (`CONDITIONAL` results) — in-process, the full context is available at check time (engine-level query planning is a separate, explicit API: [`planResources`](/guide/query-plans));
- **reverse lookups**: `lookupSubjects` walks the permission tree forward and expands groups (wildcards come back as `'user:*'`, or `{ subject: 'user:*', exclusions: [...] }` under exclusions; caveated tuples are treated as present — an upper bound); `lookupResources` uses compile-time reachability entrypoints plus candidate verification for intersection/exclusion/caveat paths (the LookupResources2 pattern). Both APIs cap their result at `maxResults` (default 1000). **The cap truncates**: by default the first `maxResults` sorted entries come back with no error, so `1000` results is indistinguishable from `1000 of 80 000`. Set `onTruncated: 'throw'` to get a typed `KerberosRelationsError` instead — recommended whenever lookup results feed a query-plan filter (`expandRelationOperands`), where a silently narrowed id list would drop authorized rows from the translated query; alternatively pass an `{ ids, truncated: true }` envelope to `expandRelationOperands`, which then degrades that branch to the sound `opaque` post-filter operator. Truncation is always recorded on the call's telemetry span as `kerberos.result.truncated`.

## Resolver telemetry

The resolver takes the same `telemetry` option as the engine (`{ api }` or `{ tracer, meter }`, see [OpenTelemetry](/guide/telemetry)): one span per public call (`Kerberos.relations.check` / `.list` / `.lookupSubjects` / `.lookupResources`, with resource/relation attributes and identity attributes gated by `includeIdentity`), a `kerberos.relations.checks` counter (`kerberos.relations.result: allow|deny`), the shared `kerberos.request.duration` histogram, and tuple-document cache reads counted in `kerberos.cache.requests` with `kerberos.cache.kind: relation`. When the resolver runs inside a Kerberos engine that also has telemetry, resolver spans nest under the `isAllowed`/`checkResources` span automatically (active span context). As everywhere else, telemetry failures are swallowed and can never affect resolution.

```javascript
const relations = new RelationResolver({ schema, tuples, telemetry: { api: require('@opentelemetry/api') } });
```

## Resolver hooks & events

The resolver accepts a `hooks` option with the request-level subset of the engine's lifecycle hooks — `beforeRequest(ctx)`, `afterRequest(ctx, summary)`, `onError(error, ctx)`, where `ctx = { kind: 'check' | 'list' | 'lookupSubjects' | 'lookupResources', callId, args, enriched }` (frozen; `beforeRequest` may return a replacement arguments object, re-validated and resolved instead of the original) — plus `hooksTimeoutMs` and `maxListeners`, and emits `request:start` / `request:end` / `request:error`, `relation:checked` (one per relation or permission checked: `{ callId, kind, resource, relation, subject, allowed, enriched? }`) and `cache:hit` / `cache:miss` / `cache:error` for tuple-document reads (`kind: 'relation'`). There is no `onError` option here, so a throwing `beforeRequest` (or an invalid replacement, or a hook past `hooksTimeoutMs`) always propagates as `KerberosHookError` (the engine converts it under its own `onError` when the resolver serves a relation-backed decision). Through the `relations` seam `callId` is the engine's `kerberosCallId`, so resolver events line up with engine events; standalone calls get a generated id. Unknown event names throw a `TypeError`. See [Hooks & events](/guide/hooks) for the full contract.

## Dynamic tuples (cache-backed)

Exactly like dynamic policies, tuples can live in your cache/store — Kerberos **only reads**; storage, TTL, invalidation and multi-host sync are the backend's job (keyv → cacheable → qified works here too):

- **Forward documents** (required): key **`rel:<resourceType>:<id>:<relation>`** → JSON array of subject entries:

  ```json
  ["user:emilia", "group:eng#member", { "subject": "user:bob", "caveat": { "name": "valid_ip", "context": { "allowed_ips": ["10.0.0.1"] } } }]
  ```

- **Reverse documents** (opt-in, only needed for `lookupResources` over cache-backed tuples): key **`rel:rev:<subjectKey>`** (e.g. `rel:rev:user:emilia`, `rel:rev:group:eng#member`) → JSON array of `{ "resource": "document:readme", "relation": "viewer" }` entries. Enable with `reverseIndex: true`; without it `lookupResources` throws a typed error when a cache is configured (`check`/`list`/`lookupSubjects` never need reverse documents).

Static tuples always win per `(resource, relation)` key — the cache is only consulted on a static miss, and sources for the same key are never merged. **A corrupt document throws a typed `KerberosCodecError`** (propagating per the engine's `onError` semantics) instead of resolving as empty — an "empty" read would silently *widen* access in exclusion positions (`read_only = viewer − editor`: a real editor whose editor document fails to parse would gain `read_only`). The same rule applies to a caveat whose condition **throws** (→ `KerberosRelationsError`): an evaluation error is never read as an answer; a caveat that cleanly evaluates to `false` simply does not match. Genuine absence (cache miss) still resolves as an empty set, and entries the schema does not admit are skipped with an operator log. Transient cache failures retry per `cacheRetry` and then surface as `KerberosCacheError`.

**Session memo contract** (`opts.memo` on `check`/`list`/`lookupSubjects`/`lookupResources`): pass one `Map` to share work across calls — document reads are shared whenever the same resolver instance is used, and decision entries are automatically scoped by resolver instance plus the *identity* of the `principal`/`context` objects, so reusing a memo across different principals, contexts or resolver instances is safe by construction (reuse the same object references to maximize sharing — that is exactly what the Kerberos engine does across a `checkResources` batch). A read that fails (rejects) is evicted from the memo automatically, so a transient backend failure never poisons a long-lived memo — the next call retries; successfully resolved reads stay memoized for the memo's lifetime, so treat the memo as request/batch-scoped when document freshness matters.

## Consistency (honest limitations)

This is deliberately **not** full Zanzibar. The hard part of Zanzibar is distributed consistency — ZedTokens/zookies, snapshot reads, the [New Enemy Problem](https://authzed.com/docs/spicedb/concepts/consistency) — and an in-process engine sidesteps it rather than solving it:

- checks always read the **current** in-memory state plus whatever your cache returns *right now*;
- the staleness window for dynamic tuples equals your cache-invalidation window (e.g. qified pub/sub propagation). Until an invalidation propagates, a just-revoked subject may still pass on another host — if that window matters for your threat model, put revocation-sensitive checks behind static tuples, shorten TTLs, or use a centralized authorization service (SpiceDB) instead;
- there are no per-request consistency levels and no revision tokens.
