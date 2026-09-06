# Changelog

All notable changes to **`@alexify/kerberos`** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.1.0] - 2026-09-06

Lifecycle hooks and events: run your own logic inside the request flow (veto
it, or enrich it), or subscribe to decisions without parsing audit logs — on
both the engine and the built-in relations resolver.

### Added

- **Lifecycle hooks (`hooks` option).** `beforeRequest(ctx)`, `afterRequest(ctx, summary)`, `beforeResource(ctx, info)`, `afterResource(ctx, info, result)` and `onError(error, ctx)` — awaited user callbacks around every `isAllowed` / `checkResources` / `planResources` call. `ctx` (one frozen object per request) carries the request kind, the `kerberosCallId`, the validated arguments and `enriched`; `info` and `result` are frozen views; `summary` reports `success`/`durationMs`/`error`/`failClosed`/`enriched`. Error contract: a throwing `beforeRequest`/`beforeResource`/`afterResource` (or a successful request's `afterRequest`) vetoes as `KerberosHookError` and follows `onError` (`'deny'` fails closed; inside a batch a per-resource hook only fails that resource); `onError`, a failed request's `afterRequest` and a failed resource's `afterResource` are swallowed so they never mask the cause. A failed resource still reaches `afterResource` with its fail-closed result (`reason: 'evaluation-error'`, `errorName`). Malformed arguments fire no hook. Per-resource hooks are the only ones that leave the synchronous evaluation driver (`test/SyncAsyncParity.test.js` pins byte-identical responses either way). Pinned by `test/Hooks.test.js`.
- **Request enrichment.** `beforeRequest` may return a replacement arguments object: it is re-validated with the method's own validator (plus the method's invariants — a `checkResources` replacement must keep the batch's resource count), evaluated instead of the original, and marked `enriched: true` on the audit entry, the span (`kerberos.request.enriched`), the `decision` / `plan` / `request:end` events and `afterRequest`'s summary. An invalid replacement is the hook's failure (`KerberosHookError`, `cause` = the `KerberosValidationError`). The caller's objects are never modified; any non-object return value keeps the request.
- **`hooksTimeoutMs`** (engine + resolver, off by default): bounds every awaited hook invocation; on expiry the hook fails as `KerberosHookError { timedOut: true }` and follows that hook's throwing/swallowing rule instead of hanging authorization — the hook counterpart of `relationsTimeoutMs`.
- **Events.** `kerberos.on/once/off/removeAllListeners/listenerCount` (chainable, no public `emit`): `request:start` / `request:end` / `request:error`, `decision` (one per resource, fail-closed ones marked `reason: 'evaluation-error'`), `plan`, `relations:resolved`, `cache:hit` / `cache:miss` / `cache:error`. Synchronous, fire-and-forget; payloads are fresh identity-only objects (never attribute bags or `Error` instances) stamped with the request's `callId`. A throwing or rejecting listener is contained and can never affect a decision. Unknown event names throw a `TypeError` (a typo cannot register a listener that never fires). The emitter is the package's own platform-neutral class (`src/events.js`) — synchronous listeners cost no promise; the same class on Node.js and in the browser, no `node:events`. Pinned by `test/Events.test.js` and `test/Emitter.test.js`.
- **`maxListeners`** (engine + resolver, default 10, `0` disables): listener-leak detection — the first subscription past the threshold on one event name logs a warning; never a limit.
- **Resolver hooks & events.** `RelationResolver` accepts the request-level hooks (`beforeRequest`/`afterRequest`/`onError`, with enrichment and `hooksTimeoutMs`; `KerberosHookError` always propagates — no `onError` option there) and emits `request:*`, `relation:checked` and `cache:*` (`kind: 'relation'`, correlated by the engine's `callId` through the `relations` seam).
- **`KerberosHookError`** (main entry): `hook` names the failing hook, `cause` carries the original error, `timedOut` flags a `hooksTimeoutMs` expiry.
- **Observability.** `kerberos.observability.failures` now also counts swallowed `hooks` and `events` failures under `kerberos.observability.sink`; the new `kerberos.hooks.duration` histogram (by `kerberos.hook`) records every awaited hook invocation, so a slow hook is attributable instead of looking like an engine regression.
- **Types.** `KerberosHooks`, `KerberosHookContext` (discriminated on `reqKind`), `KerberosRequestArgs`, `KerberosRequestSummary`, `KerberosResourceHookInfo`, `KerberosResourceHookResult`, `KerberosEvents` and the typed `on/once/off` overloads (a typo'd event name is a type error); `RelationResolverHooks` / `RelationResolverEvents` on the `/relations` subpath; `IsAllowedArgs` is now a named type.
- **Bench.** `pnpm bench` gains hooks/events scenarios (a sync `decision` listener, request-level hooks, per-resource hooks).

### Changed

- The swallowed-sink `console.warn` names the sink (`audit logger` / `lifecycle hook` / `event listener`) and warns once **per sink** instead of once per instance; the engine and the resolver share one implementation of the request lifecycle (`src/lifecycle.js`).
- `RelationResolver`: standalone calls without `opts.callId` get a generated correlation id on their span, hooks and events when telemetry, hooks or listeners are active; diagnostics-logger failures are now counted under the `logger` sink and warned once (previously silent).
- Bundle size (`pnpm size`): main entry 31.9 → 35.8 KB min+gzip, `/relations` 16.3 → 19.8 KB.

## [4.0.0] - 2026-08-30

Code-review hardening waves (0–4): the Conditions inherited-key fail-open fix,
restored Node-ESM named exports, scope-depth caps, cache-reader
backoff/timeout/degraded-mode options (`cacheRetry`, `cacheKeyPrefix`,
`relationsTimeoutMs`, `maxConcurrency`), per-batch policy-resolution memo and
cross-request instance memo, audit-stream completeness (fail-closed denials,
`principalRoles`, the `audit` option, info-level plan results,
`kerberos.observability.failures`), the synchronous evaluation driver
(~2.5× simple `isAllowed`), reverse-lookup truncation signaling
(`onTruncated`), frozen policy shapes/tokens, and d.ts/export-parity guards.

### Added

- **Verified Cerbos ORM-adapter compatibility.** New `toCerbosQueryPlan`
  export converts `planResources` output (HTTP-API operand encoding) into
  the flattened `@cerbos/core` SDK encoding, and the claim that Cerbos's
  official adapters "accept the filter" is now CI-executable:
  `test/OrmAdapters.test.js` runs the real `@cerbos/orm-prisma` and
  `@cerbos/orm-drizzle` packages against Kerberos plans and pins the
  produced Prisma `where` objects / Drizzle SQL. The Kerberos-only
  operators are handled by contract — `relation` plans convert only after
  `expandRelationOperands` (the converter throws otherwise, naming it),
  `opaque` plans throw with a post-filtering directive. Recipes in the
  query-plans guide.
- **Fuzzing + published comparative benchmarks.** A deterministic seeded
  fuzz suite (`test/Fuzz.test.js`, part of `pnpm test`, crankable via
  `FUZZ_ITERATIONS`) covers the `$expr` codec, the CEL translator's output
  contract, the YAML parser and `RelationResolver` — it already caught and
  fixed a real contract bug: `@jsep-plugin/new` emits a malformed
  callee-less node for `new R.attr.x`, which the codec now rejects as
  `KerberosExprError` instead of crashing with a raw `TypeError`. New
  `pnpm bench:compare` (Kerberos vs `@casl/ability` vs `casbin` on a
  shared RBAC+ABAC scenario) and `pnpm size:compare` (browser min+gzip)
  publish honest cross-library numbers, with the caveats, in the
  Benchmarks docs.
- **Policy-testing CLI.** The package now ships a `kerberos` binary:
  `kerberos test <policiesDir> <testsDir>` runs Cerbos-`TestSuite`-format
  suites (`*_test.yaml`/`*_test.json`, named fixtures + expected effects)
  against a policy directory — policies load through the `/loader` subpath
  (Kerberos JSON + Cerbos YAML/JSON), `{ $expr }` conditions resolve jsep
  from the caller's project, `--schemas reject|warn` wires `_schemas/` into
  attribute-schema enforcement, `--json` emits a machine-readable report,
  and unsupported expectation features fail the run instead of silently
  passing. `kerberos bundle <dir> --out <file> [--reproducible]` bakes a
  hash-stamped policy bundle.
- **File/directory policy loader + versioned bundles** — the new Node-only
  **`@alexify/kerberos/loader`** subpath: `loadPolicyDirectory` /
  `loadPolicyFile` read policy-as-code repositories (Kerberos serialized
  JSON and Cerbos YAML/JSON mix freely — `apiVersion` documents route
  through the `/cerbos` importer; `_schemas/**.json` come back keyed for
  `schemas.definitions`; deterministic sorted order; `_`-prefixed and
  hidden entries skipped), and `createPolicyBundle` / `writePolicyBundle` /
  `loadPolicyBundle` implement hash-stamped GitOps artifacts: `version` is
  the SHA-256 of the canonical sorted-key JSON, recomputed and verified on
  load so tampered or truncated bundles throw. Both a synchronous driver
  (top-level functions) and an asynchronous one (the `promises` namespace,
  Node's `fs.promises` idiom) share one decision core, so results are
  byte-identical; `promises.loadPolicyDirectory` reads files concurrently
  (bounded by the `concurrency` option, default 64) to keep cold starts
  fast over large policy repositories — the `kerberos` CLI uses it
  internally. Browser bundlers substitute throwing/rejecting stubs via the
  package `browser` map. Typed `KerberosLoaderError`.
- **Attribute schema enforcement** (Cerbos `schemas` parity). Resource
  policies now accept a `schemas:` block (`principalSchema` /
  `resourceSchema` refs with `ignoreWhen.actions` globs), enforced through
  the new `schemas` engine option: `definitions` maps refs to validators
  (JSON Schema via `ajv`, Zod, or plain functions), `enforcement` picks
  `reject` (deny + Cerbos-shaped `validationErrors` on the result) / `warn`
  (report only) / `none`. Unset ⇒ schema refs stay inert, matching Cerbos's
  default. Failures always reach `checkResources` results and the audit log;
  denied actions carry `reason: 'invalid-attributes'` under `includeMeta`.
  The Cerbos importer now translates `schemas:` blocks verbatim instead of
  requiring `drop: ['schemas']`.
- **Cerbos policy importer** — the new **`@alexify/kerberos/cerbos`** subpath
  turns an existing Cerbos policy repository into Kerberos policies, with zero
  dependencies: `importCerbosPolicies` (YAML/JSON documents → serialized
  `{ $expr }` documents for `deserializePolicy`), `celToExpr` (a real CEL
  parser + translator to the safe-interpreter subset), `parseYamlDocuments`
  (a YAML-subset parser verified differentially against the reference `yaml`
  package), and `KerberosImportError`. The importer refuses to guess:
  unsupported Cerbos constructs (macros, `matches()`, extension functions,
  `exportVariables`, `REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS`, unknown keys, …)
  throw named errors instead of being dropped — the only opt-out is
  `drop: ['schemas']`. Verified end-to-end by running the whole conformance
  corpus through the importer (`conformance/importer.test.js`): every
  PDP-pinned decision and query-plan expectation holds for importer-loaded
  policies. See the new "Importing Cerbos Policies" guide.
- **Typed authoring.** `Kerberos` and every policy/request/response type are
  now generic over an optional application schema naming resource kinds, their
  actions and attribute bags, and the principal's roles and attributes. The
  resource kind narrows the action, the attribute shapes and the `{ P, R, V, C }`
  envelope handed to conditions; policy documents become discriminated unions
  over `resource:`, so a rule naming another kind's action or an undeclared role
  is a compile error. Purely type-level — every parameter defaults to the new
  `AnySchema`, which reproduces the previous untyped surface exactly. New
  helper types: `KerberosSchema`, `AnySchema`, `ResourceKindOf`, `ActionOf`,
  `ResourceAttrOf`, `PrincipalRoleOf`, `PrincipalAttrOf`, `PolicyEvalRequest`,
  `CheckResourcesArgs`/`Entry`/`Result`/`Response`. See the new "TypeScript"
  guide.
- **Cerbos conformance suite** (`conformance/`, not published to npm). One
  corpus in Cerbos's own policy and `TestSuite` formats runs against Kerberos
  always, and against a real Cerbos PDP in CI. Known semantic gaps are recorded
  in `conformance/DIVERGENCES.md`. New `pnpm test:conformance`.
- **In-browser playground** on the docs site — the real engine running
  client-side, with no backend.

### Changed

- **BREAKING (semantics): resource-policy conflicts now resolve per principal
  role, matching Cerbos.** `EFFECT_DENY` overrides `EFFECT_ALLOW` *within* a
  role, but an `EFFECT_ALLOW` from *any* role wins *across* roles. Kerberos was
  previously deny-overrides unconditionally, which returned `EFFECT_DENY` where
  Cerbos ≥ 0.41 returns `EFFECT_ALLOW` — verified against a live Cerbos PDP and
  now covered by the conformance suite.

  **This is more permissive than before.** A `DENY` scoped to one role no longer
  vetoes an `ALLOW` carried by a different role the principal also holds. Audit
  any policy that relies on a role-scoped deny to revoke access: to keep the old
  outcome the deny must cover the allowing role, either with `roles: ['*']` or
  by naming it explicitly. Denies that already do are unaffected, as are
  single-role principals and same-role conflicts.

  Rules reached through `derivedRoles` count for the principal roles listed in
  that definition's `parentRoles` — derived roles collapse into the role
  dimension rather than forming one of their own. `planResources` follows the
  same rule; `test/PlanParity.test.js` gained multi-role principals, which is
  the shape that made the old behaviour invisible.
- **BREAKING (semantics): the full Cerbos rule-table evaluation model.** A
  differential sweep (2000+ decisions) against a live Cerbos 0.55.0 PDP,
  cross-checked against Cerbos's documentation and v0.55.0 source, surfaced
  and closed the remaining semantic gaps. All are pinned by the conformance
  suites (57 cases, offline and against the live PDP — zero divergences):

  - **Wildcards**: name matching now globs exactly like Cerbos — bare `*`
    matches anything, any other `*` stays within a `:`-delimited segment
    (`view:*` matches `view:public`, not `view` or `view:a:b`), `**` crosses
    segments. Applies to resource-policy `actions` and `roles`,
    principal-policy `resource` and `action`, role-policy `resource` and
    `allowActions`, and derived-role `parentRoles` (`parentRoles: ['*']`
    works now). Previously only a bare `*` in `actions`/`roles` matched — a
    `DENY` on `view:*` silently failed to deny (fail-open, fixed).
  - **Scoped policies evaluate per action, per role** (Cerbos
    `SCOPE_PERMISSIONS_OVERRIDE_PARENT`): the first scope that decides an
    (action, role) seals it, a failed condition falls through to the parent
    scope, and an action undecided at the specific scope is decided by a less
    specific policy. Previously the first policy found decided ALL actions.
    Applies to principal, resource and role policies alike.
  - **Role policies are synthetic deny rows in the per-role walk**, at their
    own scope: an allow must come from a resource rule reaching the SAME
    principal role — another role's allowlist cannot revive it (the
    cross-bucket case). Role policies also follow the RESOURCE scope chain
    and resource `policyVersion` (Cerbos's docs say principal scope; its
    engine and a live PDP say resource — recorded in DIVERGENCES.md).
  - **Cache-backed scope resolution is per scope** (memory first, then cache,
    at each scope): a static base-scope policy no longer shadows a more
    specific cached policy — the documented hybrid-deployment caveat is
    retired.

  Internals: the resource/role layers collapsed into one shared decision walk
  (`src/decision.js`) used by `ResourcePolicy.check`, both engine drivers and
  (symbolically) the query planner; glob matchers (`src/matching.js`) are
  precompiled per rule.
- **BREAKING (semantics): role policies are now a narrowing filter over the
  resource policy, not a ranked layer that can grant.** Matching Cerbos, and
  verified against a live PDP:

  - a role policy **cannot allow what the resource policy withholds** — with no
    matching `ResourcePolicy`, a `RolePolicy` alone now grants nothing;
  - multiple role policies **union** instead of intersecting: a principal may do
    what *any* of its roles allowlists, so holding an extra role can widen
    access but never narrow it;
  - a role with **no role policy at all is unrestricted** (that role's bucket
    passes the resource-layer result through unfiltered) — but holding a role
    that *has* a role policy constrains it everywhere, including resource
    kinds its rules never mention (where it permits nothing);
  - a `PrincipalPolicy` override is never narrowed by the role layer.

  `parentRoles` are unchanged — the child still keeps only what each locally
  defined parent role policy allows (intersection *along the chain*, union
  *across* roles). Deployments that relied on a `RolePolicy` to grant access on
  its own must add the corresponding `ResourcePolicy` rules.

- **BREAKING (types): `Effect` and `PlanKind` are const objects, not `enum`s.**
  The runtime has always been a frozen plain object, so the `enum` declaration
  mis-described it and made `effect: 'EFFECT_ALLOW'` in a plain JSON policy
  literal a type error — exactly the form stored policies carry. `Effect.Allow`
  and `PlanKind.Conditional` are unchanged; only `enum`-specific type usage
  (e.g. `PlanKind.Conditional` as a *type*) needs updating.
- **`checkResources` is now overloaded on `effectAsBoolean`**: the response's
  effects are typed `Effect`, or `boolean` when the flag is passed, instead of
  the `Effect | boolean` union in both cases.
- `{ $expr }` descriptors are accepted by the types in `condition.match` and
  `output` — stored policies always used them, but the types rejected them.

## [3.1.0] - 2026-07-21

### Added

- **Resources Query Plan API — `kerberos.planResources(args)`**, Cerbos-compatible
  ([`/api/plan/resources`](https://docs.cerbos.dev/cerbos/latest/api/#resources-query-plan)):
  partially evaluates the policies against everything known at plan time (full
  principal, `resource.kind`, known `attr`) and returns a filter over the
  unknown resource fields — `KIND_ALWAYS_ALLOWED` / `KIND_ALWAYS_DENIED` /
  `KIND_CONDITIONAL` with a Cerbos-shaped `{ operator, operands }` condition
  tree (`request.resource.id` / `request.resource.attr.*` variables; operators
  `and/or/not/eq/ne/lt/le/gt/ge/in/add/sub/mult/div/mod/index/list`), ready for
  translation into database queries (compatible in shape with Cerbos ORM
  query-plan adapters).
  - **Full layer parity with `isAllowed`**: principal override (Deny wins,
    conditional principal rules compose residually), role-policy allowlist with
    implicit deny + `parentRoles` intersection (Deny-wins across roles, cycle
    detection), resource layer Deny-over-Allow with default deny, scope
    first-match-wins + `policyVersion` selection, cache-backed policies —
    guarded by a property-style parity suite (`test/PlanParity.test.js`) that
    grid-samples unknown attributes against real `isAllowed` results.
  - **Partial evaluator** for codec-compiled `{ $expr }` conditions
    (`src/planning/`): constant folding through the codec's own interpreter
    (including `&&`/`||`/`?:` laziness), `variables` inlined at `V.*` use
    sites, `C.*`/`P.*` folded to literals; plain JS-function conditions and
    non-translatable constructs degrade soundly to the Kerberos **`opaque`**
    operator (translator post-filters).
  - **ReBAC bridge**: relation-backed derived roles plan as the Kerberos
    **`relation`** operator; the new exported **`expandRelationOperands(plan,
    lookup)`** helper materializes them into
    `in(request.resource.id, [ids])` via any resolver (e.g.
    `RelationResolver.lookupResources`).
  - `action` (single) **or** `actions` (multi — the plan is the AND of the
    per-action plans, Cerbos semantics); `includeMeta` adds `filterDebug`
    (s-expression rendering), `matchedScopes` and the `resolution` trace;
    `onError: 'deny'` fail-closes to `KIND_ALWAYS_DENIED`; wildcard `'*'`
    actions are rejected at validation.
  - Policy sources resolve as one concurrent `Promise.allSettled` wave
    (principal / roles+parent-closure / resource+derived-roles) — with a
    cache-backed store, one round-trip wave instead of three sequential ones;
    the `meta.resolution` trace order stays deterministic.
  - `buildPlanResourcesArgs` schema builders across all three validation
    backends (Zod / JSON Schema / TypeBox), `Kerberos.parsePlanResourcesArgs`,
    the exported **`PlanKind` enum** (`AlwaysAllowed` / `AlwaysDenied` /
    `Conditional`, mirroring `Effect`), hand-maintained types (`PlanFilter`,
    `PlanExpressionOperand`, `PlanResourcesArgs`, `PlanResourcesResponse`), a
    `planResources` bench scenario and a README section with the planning
    flow diagram.
  - **Plan observability**: each `planResources` call records the outcome —
    span attributes (`kerberos.plan.kind`, `kerberos.plan.opaque_count`,
    `kerberos.plan.relation_count`, `kerberos.plan.actions_count`), a new
    **`kerberos.plans`** counter (by filter kind and resource kind) and a
    structured `PlanResources.result` audit entry — so an `ALWAYS_ALLOWED`
    filter (a fail-open query) is distinguishable from an `ALWAYS_DENIED` one
    in traces, metrics and logs.
  - Bundle-size tooling: `pnpm size` (esbuild browser bundle, minified +
    gzipped, per entry) with the measured numbers in the README; CI smoke-runs
    it, and lint/format now also cover `scripts/` and `bench/`.

### Fixed

- **Wire safety of query-plan filters**: folded constants that JSON transport
  would silently corrupt (`undefined` vanishes, `NaN`/`Infinity` become
  `null`, `Date` instances become ISO strings, `BigInt` throws) are no longer
  emitted into filter operands — such conditions degrade to the sound `opaque`
  operator instead, and the parity suite now verifies filters **after** a JSON
  round-trip.
- Plan construction no longer throws on principals whose attributes contain
  circular structures (node deduplication survives unserializable values).
- Compiled `{ $expr }` ASTs are now **deeply frozen** at parse time: the
  cached AST shared by every closure of the same expression (and exposed to
  the query planner) can no longer be mutated to alter other consumers'
  evaluation.

## [3.0.0] - 2026-07-20

### Added

- **ReBAC (relationship-based access control)**, inspired by SpiceDB/Zanzibar:
  - **`relations` engine option** — a delegation contract
    (`{ check, list? }`) like `logger`/`cache`/`codec`; any resolver works,
    including one backed by your own SQL join tables. Derived-role definitions
    gain an optional **`relation:`** field: the role activates when the
    resolver grants that relation/permission on the request's resource
    (`parentRoles`/`condition` become optional synchronous gates). Resolution
    happens on the engine's existing async derived-roles phase — list-first,
    parallel `check` fallback, one shared request memo across a whole
    `checkResources` batch, `onError` semantics and per-resource isolation
    apply, and `includeMeta` traces every resolution as
    `{ source: 'relations', name, relation, matched }`.
  - **Built-in in-process "Zanzibar-lite" resolver** — the `RelationResolver`
    class on the new **`@alexify/kerberos/relations` subpath** (kept out of
    the main entry so non-ReBAC bundles do not grow): a JSON relation-schema
    DSL compiled to SpiceDB's userset-rewrite algebra (union `anyOf` /
    intersection `allOf` / exclusion `exclude` / arrows `{ via, permission }`
    incl. `.all`, wildcard subjects `user:*`, subject relations
    `group#member`, fail-fast compile checks + a precomputed O(1)
    admission-key Set per relation), static tuples indexed in both directions
    (zero IO) plus dynamic tuples via the same read-only cache fallback as
    policies (`rel:<type>:<id>:<relation>` documents; opt-in
    `rel:rev:<subject>` reverse documents with `reverseIndex: true`),
    **caveats** (ABAC-on-ReBAC: named conditions with write-time context
    precedence, `{ $expr }` support through the eval-free codec), recursive
    `check` with short-circuiting, per-request memoization and a SpiceDB-style
    `maxDepth` guard (default 50), and **reverse APIs** — `lookupSubjects`
    (group-expanding, with wildcard-exclusion entries) and `lookupResources`
    (reachability entrypoints + candidate verification). Engineered
    performance-first: O(1) strategy tables over rewrite-node kinds instead of
    switch dispatch, constructor-precompiled argument validators, per-type
    Map/Set subject-set algebra, cursor/level-based BFS (no `shift()`), and
    `Promise.allSettled` waves for lookup paths that need every branch
    (candidate verification, closure levels, collect expansions) while check
    paths stay sequential to preserve short-circuit cache-read savings.
    Optional **resolver telemetry** via the same `telemetry` option shapes:
    spans per public call (`Kerberos.relations.*`), a
    `kerberos.relations.checks` counter and tuple-document cache reads tagged
    `kerberos.cache.kind: relation`. New typed `KerberosRelationsError`.
  - Deliberately **not** implemented (documented in README/SECURITY.md):
    ZedTokens/consistency levels (freshness is delegated to the cache
    invalidation layer), CEL, partial caveat evaluation, cursors/streaming.
  - **Code-review hardening** (second-pass review of the unreleased module):
    session-memo entries are scoped by resolver instance + principal/context
    object identity (sharing one memo across principals, contexts or resolver
    instances is safe by construction); **data errors are never read as
    answers** — corrupt tuple/reverse documents throw `KerberosCodecError`
    and a caveat whose condition throws raises `KerberosRelationsError`
    (silently treating them as empty/not-matched would widen access in
    exclusion subtract positions); exclusion in `lookupSubjects` no longer
    mutates the memoized base set; subject-relation refs must reference
    relations (permissions rejected at compile — keeps `check` and
    `lookupResources` consistent); `|` is a reserved name character
    (admission-key delimiter); compiled refs/rewrite nodes are frozen and
    schema introspection getters return copies; `list()` validates its
    arguments through the configured backend; object-form resource/principal
    ids are sanitized (no `:`/`#`, no literal `*` principal id); caveats
    always receive a copied context; argument errors are recorded on
    telemetry spans; `lookupSubjects` omits concrete subjects covered by an
    unexcluded wildcard.
- **`onError: 'throw' | 'deny'` option** (default `'throw'`) — error semantics
  are no longer coupled to logger presence. Malformed arguments always throw
  the new typed `KerberosValidationError` regardless of this option.
- **Typed errors**: `KerberosCacheError`, `KerberosCodecError`,
  `KerberosValidationError` exported from the main entry.
- **`cacheRetry: { attempts }` option** (default 3 attempts) — transient
  `cache.get` failures are retried; exhausted retries surface as
  `KerberosCacheError`. Corrupt cache entries (deserialize/constructor
  failures) are logged and treated as a cache miss instead of failing the
  request.
- **Configurable safe-codec limits**: `codec: { jsep, maxCachedExprs?,
  maxExprLength?, maxDepth? }` (defaults: 1000 cached ASTs with FIFO eviction,
  4 KB expressions, depth 32) — a compromised policy store can no longer grow
  the AST cache without bound or overflow the stack with deep nesting.
- CI (GitHub Actions): lint + format check + tests with c8 coverage + type
  tests on Node 18/20/22.
- **Decision tracing** (`includeMeta: true`): denied actions now carry a
  `reason` (`'policy-miss'` / `'rule-miss'` / `'condition-not-met'`) and `meta`
  gains a `resolution` array recording every policy lookup (scopes searched,
  where the policy matched, memory vs cache origin) — "why was this denied" is
  now answerable from the response.
- **Cache observability**: debug log events + `kerberos.cache.requests` OTel
  counter with `result: hit|miss|error`.
- **Benchmarks**: zero-dependency `pnpm bench` harness; results documented in
  the README "Benchmarks" section.
- `SECURITY.md` with the threat model and the opt-in safety-layers philosophy.
- Test DSL: expected entries now support an optional `outputs` array asserted
  against the `checkResources` response.
- New exported constants: `ALL_ROLES`, `ALL_RESOURCES`, `DEFAULT_VERSION`,
  `BASE_SCOPE` (plus `ALL_ACTIONS` and `createCacheReader` are now typed).

- **Native OpenTelemetry support (traces + metrics)** via the new `telemetry`
  constructor option, following the same zero-dependency delegation philosophy
  as `logger`/`cache`: pass `{ api }` (the `@opentelemetry/api` module — Kerberos
  derives its own tracer/meter with the `@alexify/kerberos` instrumentation
  scope) or pre-created `{ tracer, meter }` instances. One span per
  `isAllowed`/`checkResources` call (started **active**, so auto-instrumented
  cache spans nest under it), per-decision `kerberos.decision` events, `ERROR`
  span status + exception events on failures, plus two metrics:
  `kerberos.decisions` counter and `kerberos.request.duration` histogram.
  Identity attributes (`kerberos.principal.id`, `kerberos.resource.id`) are on
  by default and can be stripped with `telemetry.includeIdentity: false`.
  Telemetry failures never affect authorization results, and the
  logger-controlled error contract (fallback vs rethrow) is unchanged. New
  structural types (`KerberosTelemetryOptions`, `KerberosTracer`,
  `KerberosMeter`, …) are exported from `index.d.ts`.

- **Browser/server entrypoint split** (pino-style). New root `browser.js` entry
  plus a package.json `browser` field (object map) and a `browser` condition in
  `exports`: browser bundlers (webpack, Vite, esbuild `platform: browser`,
  Rollup node-resolve with `browser: true`, Parcel, Bun) now automatically pick
  a build with **zero Node.js builtins**.
- New `src/runtime/node.js` / `src/runtime/browser.js` platform modules holding
  the only platform-specific code (`generateCallId`, `getNow`). The Node
  runtime uses `node:crypto` / `node:perf_hooks` directly; the browser runtime
  uses `globalThis.crypto.randomUUID` (with a pseudo-UUID fallback for insecure
  contexts) and `globalThis.performance` (falling back to `Date.now`).
- `engines.node >= 18` — documents the already-implicit runtime floor.

### Performance

- **`checkResources` evaluates resources concurrently** via
  `Promise.allSettled`: N cache-backed resources cost one parallel wave of
  lookups instead of N sequential round-trips (~8x faster with a 2ms-latency
  store and 10 resources). A rejected resource fail-closes (all its actions
  `EFFECT_DENY`) without failing the batch.
- Scope search chains are memoized per instance (bounded); role-policy memo
  keys are computed once per evaluation instead of per inheritance node; the
  rule `actions`/`allowActions` are precompiled into non-enumerable Sets at
  policy construction (O(1) hot-path membership instead of repeated
  `includes` scans, invisible in serialized shapes); the
  response effect map is built directly instead of double-allocating via
  `Object.fromEntries`.
- Internal evaluation now always works with canonical effect strings —
  `effectAsBoolean` is applied once at the response boundary instead of being
  threaded through every policy class (audit logs now always contain canonical
  `EFFECT_*` values).

### Changed

- **BREAKING (bug fix): logger no longer changes error semantics.** Previously
  errors were silently converted to DENY when a logger was enabled and thrown
  otherwise; a throwing logger could even flip a computed ALLOW to DENY. All
  logger calls are now internally guarded (a broken logger can never affect
  authorization results), and failure behavior is controlled solely by
  `onError`. To restore the old fail-closed behavior, pass `onError: 'deny'`.
- **BREAKING (security fix): duplicate policy keys now throw at construction.**
  Two policies with the same kind/principal/role + version + scope previously
  last-wins overwrote each other, which could silently drop a deny rule.
  Duplicate derived-roles definition names also throw.
- **Derived-role definitions without a `condition` (and without a `relation`)
  now throw at construction** instead of crashing later during evaluation —
  every definition must be either condition-backed or relation-backed.
- `pnpm-lock.yaml` is no longer published in the npm tarball.
- Removed the try/catch `require('crypto')` / `require('node:perf_hooks')`
  feature detection from `src/Kerberos.js` — each platform entry now targets
  its runtime directly. Node behavior is unchanged; browser bundles get
  smaller and webpack 5 browser builds no longer need `resolve.fallback`
  workarounds.
- **Tooling: migrated linting/formatting from ESLint (neostandard) + Prettier
  to [Oxlint](https://oxc.rs/docs/guide/usage/linter) + Oxfmt** (`.oxlintrc.json` / `.oxfmtrc.json`). `pnpm lint` now runs
  `oxlint src test` (test files are linted too, previously only `src/`), and new
  `pnpm format` / `pnpm format:check` scripts run Oxfmt. The whole codebase was
  reformatted to `printWidth: 120` with trailing commas; inline suppressions
  renamed to `oxlint-disable-*`. Dev-only change — no runtime impact.

## [2.0.1] - 2026-06-01

### Fixed

- Policy schema types now accept `as const` readonly literals (via `NonEmptyArray<T>`)
  without type assertions.
- `isAllowed` args type now includes optional `reqId` and `includeMeta`.

### Added

- Exported `KerberosPolicy`, `KerberosDerivedRoles`, and `NonEmptyArray` types for
  consumer-side policy definitions.
- Compile-time type tests (`test/types.test-d.ts` via `tsd`).

## [2.0.0] - 2026-05-31

Version 2 turns Kerberos.js from a resource-policy engine into a full,
Cerbos-style authorization runtime: three policy types, pluggable validation,
pluggable logging, and cache-agnostic dynamic policies backed by an eval-free,
security-first expression codec. The previously "WIP" features (outputs, scopes,
metadata) are now complete.

> **Breaking change:** the package is published as `2.0.0`. The core `isAllowed`
> / `checkResources` API is backward compatible, but the module layout,
> exports, and policy-resolution order have changed (see _Changed_ below).

### Added

#### Policy types
- **`PrincipalPolicy`** — Cerbos-style, principal-specific overrides bound to a
  single `principal` and targeting `resource + action` directly.
- **`RolePolicy`** — role-centric allowlist policies bound to a single `role`,
  targeting `resource + allowActions`, with `parentRoles` inheritance (a child
  role keeps only actions also allowed by every locally defined parent role).
- **Mixed policy evaluation** — when multiple policy types are loaded, each
  action is resolved in order: `PrincipalPolicy` → `RolePolicy` → `ResourcePolicy`
  → default `EFFECT_DENY` (with `EFFECT_DENY` winning ties within the role layer).

#### Authorization features
- **Outputs** — `output.when.ruleActivated` / `output.when.conditionNotMet`
  expressions surfaced in `checkResources` responses, with a `src` that reflects
  the producing policy (e.g. `resource.expense.vdefault#rule-name`).
- **Scopes** — hierarchical scope resolution with a most-specific-to-base search
  chain (e.g. `acme.corp → acme → ''`) and scope normalization (`'.'` ≡ base).
- **Metadata** — opt-in via `includeMeta: true`; exposes `matchedPolicy`,
  `matchedRule`, `matchedScope`, and `effectiveDerivedRoles`.
- **Constants** alongside variables, available in the request context as `C`.
- **`effectAsBoolean`** option for `checkResources` to return `true`/`false`
  instead of `EFFECT_ALLOW`/`EFFECT_DENY`.

#### Validation (pluggable backends)
- Optional validation via **Zod** (`z`), **JSON Schema + Ajv** (`ajv`), or
  **TypeBox + Ajv** (`ajv` + `typebox`).
- First-class schema builders (`JsonSchemas`, `TypeBoxSchemas`, `ZodSchemas`,
  `KerberosJsonSchemas`, `ResourcePolicyJsonSchemas`, `PrincipalPolicyJsonSchemas`,
  `RolePolicyJsonSchemas`, …) and helpers `createAjvAdapter` / `registerAjvKeywords`
  (custom Ajv keywords so function-bearing DSL fields validate at runtime).

#### Logging (pluggable)
- `logger: true` keeps the legacy `console` audit flow (group + summary + table
  + debug JSON); a `console`-like object behaves the same.
- A structured logger (e.g. **Pino**) receives one structured audit entry per
  evaluated action.
- Lifecycle logs: `*.start`, `*.error`, `*.finish` with timing/duration.
- When logging is enabled, validation/runtime errors are logged and converted to
  fallback results (`isAllowed → false`, `checkResources → { results: [], … }`)
  instead of being thrown.

#### Caching / storing dynamic policies
- Cache-agnostic **`CacheLike`** integration: pass any object with `get(key)`
  (keyv, cacheable, cache-manager, …); static policies stay in memory and are
  always checked first, the cache is only a fallback on a miss.
- Documented cache-key layout for resource/principal/role/derived-role policies.
- **Safe AST expression codec** (`createSafeExprCodec`, `serializePolicy`,
  `deserializePolicy`) built on a user-supplied, pre-configured `jsep` instance.
  Dynamic policies express `conditions`/`variables`/`outputs` as
  `{ "$expr": "..." }` descriptors evaluated by a strict allowlist interpreter —
  **no `eval` / `new Function` / `fn.toString()`**.
- Fully pluggable codec: `{ jsep }` (built-in evaluator), `{ deserialize }`
  (custom), or omitted (cached JSON used as-is).

#### Auditing & request correlation
- `kerberosCallId` generated per call (Node `crypto.randomUUID`, browser
  `crypto.randomUUID`, or a pseudo UUID v4 fallback) and included in responses
  and logs.
- Customizable via the **`getCallId`** option.
- `reqId` propagated through evaluation, responses, and audit entries.

### Changed
- **`@alexify/kerberos/tests` subpath** — Cerbos-style test harness
  (`KerberosTest`, `KerberosTests`, mocks, and schema builders) moved out of the
  main export so production bundles do not pull dev-only code. Import from
  `@alexify/kerberos/tests` in your test files instead of `Tests` from the root.
- **Module layout** reorganized: schema builders moved into per-module
  `schemas/` folders plus a shared `src/schemas/`, and validation logic into
  per-module `validation/` folders plus a shared `src/validation/`.
- **Public exports expanded**: the package root now also exposes `Constants`,
  `Conditions`, `Outputs`, `Variables`, `PrincipalPolicy`, `RolePolicy`, the
  caching codec helpers, and all schema/validation builders. The test harness
  lives on `@alexify/kerberos/tests`, not on the root entry.
- **`Conditions`** now evaluates multiple strategies (`all` / `any` / `none`) in
  a single match object via an O(1) strategy dispatch.
- **Policy selection** is now type-aware (resource by `kind`, principal by `id`,
  role by each `principal.roles[]`), each combined with `policyVersion`
  (default `'default'`) and the scope chain.

### Performance
- Safe-codec interpreter rewritten around **O(1) dispatch tables** for node
  types and binary/unary operators (replacing `switch` statements) on the hot
  expression-evaluation path; per-`jsep` AST cache via `WeakMap`.
- `typeof` validation keyword reduced to an O(1) strategy lookup.
- Policy `check` loops use **`Set`-based** role membership lookups and boolean
  effect flags instead of `Array.prototype.includes` scans; derived-role and
  role-policy resolution deduplicate via `Set`.

### Security
- Expression evaluation is **eval-free** and allowlist-based: identifiers
  resolve only against `{ P, R, V, C }` plus curated safe builtins (`Math`,
  `Date`, `parseInt`, `parseFloat`, `Number`, `String`, `Boolean`, `isNaN`,
  `isFinite`); `__proto__` / `prototype` / `constructor` access is blocked at the
  interpreter level regardless of how it is written.

## [1.0.0]

Initial release.

### Added
- `ResourcePolicy` evaluation with rules matched by action, then `roles` /
  `derivedRoles`.
- **Derived roles**, **conditions**, **variables and constants**.
- `isAllowed` and `checkResources` (CheckResourceSet) APIs.
- Console audit logging / logger support.
- In-browser / serverless authorization.
- Built-in test harness (`Tests`).

[4.0.0]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v4.0.0
[3.1.0]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v3.1.0
[3.0.0]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v3.0.0
[2.0.1]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v2.0.1
[2.0.0]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v2.0.0
[1.0.0]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v1.0.0
