# Changelog

All notable changes to **`@alexify/kerberos`** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[unreleased]: https://github.com/Alexis-Technologies/kerberos/compare/v3.1.0...HEAD
[3.1.0]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v3.1.0
[3.0.0]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v3.0.0
[2.0.1]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v2.0.1
[2.0.0]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v2.0.0
[1.0.0]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v1.0.0
