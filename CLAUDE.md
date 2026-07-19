# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Kerberos.js (`@alexify/kerberos`) is a zero-dependency (~6 KB), in-process authorization engine for JavaScript — a lightweight, embeddable alternative to Cerbos. It evaluates `resourcePolicy` / `principalPolicy` / `rolePolicy` documents against `(principal, resource, action)` requests and returns `EFFECT_ALLOW` / `EFFECT_DENY`, with optional derived roles, conditions, variables, constants, outputs, scopes, schema validation, audit logging, cache-backed dynamic policies, and ReBAC (relation-backed derived roles + a built-in SpiceDB-inspired Zanzibar-lite resolver on the `/relations` subpath). Runs in Node.js and the browser.

Package manager is **pnpm** (`packageManager: pnpm@11.5.0`). CommonJS throughout (`require`/`module.exports`), no build/transpile step — `src/` ships as-is.

## Commands

```bash
pnpm test              # run all tests: node --test test/*.test.js
node --test test/Kerberos.test.js          # run a single test file
node --test --test-name-pattern="scope"    # filter tests by name
pnpm test:types        # type-check test/types.test-d.ts against index.d.ts via tsd
pnpm test:coverage     # c8 coverage over src/
pnpm lint              # oxlint src test
pnpm format            # oxfmt src test (format:check for CI)
pnpm bench             # ops/sec benchmark harness (bench/bench.js)
```

Linting/formatting is **oxlint/oxfmt** (`.oxlintrc.json`, `.oxfmtrc.json`; the `correctness` category is intentionally off) — their native bindings require Node ≥20.19, so CI (`.github/workflows/ci.yml`) runs `lint`/`format:check` in a single job pinned to Node 22, separate from the `test` job, which runs `test:coverage` + `test:types` across the Node 18/20/22 matrix.

Style: 2-space indent, single quotes, semicolons, 120-char lines (see `.editorconfig`, `.oxfmtrc.json`).

## Architecture

### Module shape

Every DSL concept (`Conditions`, `Constants`, `DerivedRoles`, `Outputs`, `PrincipalPolicy`, `ResourcePolicy`, `RolePolicy`, `Variables`, `Tests`) lives in `src/<Name>/` with a consistent internal layout:

- `<Name>.js` — the class itself (parsing/normalizing a raw shape, evaluation logic)
- `schemas/index.js` — schema builders for the three validation backends (Zod / JSON Schema / TypeBox)
- `validation/index.js` — `parse<Name>Shape()` helper that resolves and applies whichever validation backend is configured
- `index.js` — re-exports the above

`src/index.js` merges every module's `index.js` into the single package export. When adding a new DSL concept or policy field, follow this same four-file pattern rather than inlining logic elsewhere.

### Platform runtime split (`src/runtime/`)

`src/runtime/node.js` and `src/runtime/browser.js` are the **only** platform-specific files in the package — both export the identical `{ generateCallId, getNow }` interface. The Node variant uses `node:crypto` / `node:perf_hooks` directly (no try/catch feature detection); the browser variant uses `globalThis.crypto?.randomUUID` (pseudo-UUID fallback for insecure contexts) and `globalThis.performance` (falling back to `Date.now`), reading globals at call time so fallback branches stay testable. `src/Kerberos.js` requires `./runtime/node.js`; browser bundlers swap it via the package.json `browser` field object map (`"./index.js" → "./browser.js"`, `"./src/runtime/node.js" → "./src/runtime/browser.js"`) plus the `browser` condition in `exports`. Invariants: everything else in `src/` must stay platform-neutral (no Node builtins); any new Node builtin usage goes into `src/runtime/node.js` with a matching browser counterpart; renaming runtime files requires updating the `browser` map keys in `package.json` (a mismatch fails loudly at bundle time thanks to the `node:` prefix). Root `browser.js` intentionally mirrors `index.js` — do not deduplicate them.

### Request evaluation flow (`src/Kerberos.js`)

`Kerberos` is the sole runtime engine. Policies passed to the constructor are parsed (via `Kerberos.parsePolicy`) and stored in four private `Map`s keyed by scope-aware cache keys: `#resourcePolicies`, `#principalPolicies`, `#rolePolicies`, `#derivedRoles`.

Policy/version/scope lookup (`#getResourcePolicy`, `#getPrincipalPolicy`, `#getRolePolicyByName`) walks the **scope search chain** (`Kerberos.getScopeSearchChain`, most-specific → base `''`) crossed with `policyVersion` (default `'default'`). In-memory `Map`s are checked first; on a miss, if a `cache` option was supplied, it falls back to `await cache.get(key)` (see Caching below).

Per-action resolution order (`#evaluatePolicySources`), computed independently for every action in a request:

1. `PrincipalPolicy` matching `principal.id` — explicit `Allow`/`Deny` wins immediately.
2. Otherwise, all `RolePolicy` entries matching `principal.roles[]` are evaluated (`#evaluateRolePolicies`); `Deny` wins over `Allow` across roles. `parentRoles` intersect the child's allowed actions with each locally-defined parent role policy.
3. Otherwise, fall back to `ResourcePolicy` matched by `resource.kind` (rules matched by `roles` / `derivedRoles`, evaluated via `Conditions`/`Variables`/`Constants`/`Outputs`).
4. No match → `EFFECT_DENY`.

Public API is just `isAllowed(args)` (single action → boolean) and `checkResources(args, effectAsBoolean?)` (batch, multiple resources/actions → structured response with `kerberosCallId`, `outputs`, optional `meta`). Both share the `#runRequest` lifecycle wrapper (telemetry span + audit events + `onError` semantics) and the `#evaluatePolicySources` core; the three per-source lookups go through the single `#resolvePolicy` resolver (scope-chain memoized per instance). Internals always use canonical `EFFECT_*` strings — `effectAsBoolean` converts once at the response boundary. `checkResources` evaluates resources concurrently (`Promise.allSettled`); a rejected resource fail-closes to DENY for its actions without failing the batch. Error semantics: all logger/telemetry calls are internally guarded (can never affect decisions); evaluation errors follow the `onError: 'throw' | 'deny'` option; malformed arguments always throw `KerberosValidationError`; transient `cache.get` failures retry per `cacheRetry` then surface as `KerberosCacheError`; corrupt cache entries log as `KerberosCodecError` and count as a miss. Duplicate policy keys (and derived-roles names) throw at construction. With `includeMeta`, denied actions carry a `reason` and `meta.resolution` records every policy lookup. Shared DSL parsers live in `src/policyParsers.js`; wildcard/default tokens (`ALL_ACTIONS`, `ALL_ROLES`, `ALL_RESOURCES`, `DEFAULT_VERSION`, `BASE_SCOPE`) in `src/schemas/index.js` — use the semantically-matching constant.

### Validation backends (`src/validation/`)

Kerberos never hard-depends on a validation library. `resolveValidationAdapter`/`parseWithValidation` (`src/validation/index.js`) picks, in priority order: an explicit schema/parser → Zod (`z` option) → TypeBox+Ajv (`typebox` + `ajv` options) → plain JSON Schema+Ajv (`ajv` option) → no-op passthrough. Every DSL module's `schemas/index.js` exports builders for all three backends so this dispatch works uniformly. Ajv needs custom keywords (`src/validation/keywords.js`, `registerAjvKeywords`) because policies can contain live JS functions (conditions/variables/outputs), which plain JSON Schema can't express.

### Caching / dynamic policies (`src/caching/`)

Kerberos is cache-**agnostic**: `cache.js` (`createCacheReader`) wraps anything exposing `get(key)` (keyv, cacheable, cache-manager…) as a read-only fallback layer — Kerberos never handles TTL, writes, or invalidation itself. It's a pure fallback: static/in-memory policies are always checked first; `cache.get` is only called on a miss, once per scope-chain entry.

Because remote-stored policies must be JSON (no live functions), `codec.js` (`createSafeExprCodec`) implements an **eval-free AST-allowlist interpreter** on top of `jsep`: conditions/variables/outputs are authored as `{ "$expr": "..." }` strings, parsed once per (jsep instance, expression) and cached, then walked against `{P, R, V, C}` plus a curated safe-builtins allowlist (`Math`, `Date`, `parseInt`/`parseFloat`/etc.). `__proto__`/`prototype`/`constructor` member access is blocked at the interpreter level regardless of how it's spelled, and there is deliberately no `eval`/`new Function`/`fn.toString()` anywhere in this path — see the "Serialization mechanism" section of `README.md` for the rationale before changing this file. The recommended production stack layered on top (documented in README, not part of this package) is `keyv` → `cacheable` (`CacheSync`) → `qified` (pub/sub invalidation across hosts).

### Logging (`src/logging.js`)

`logger` option accepts `true` (legacy `console.group`/`table`/`debug` output), a custom console-like object, or a structured logger (e.g. Pino, detected via `info`/`debug` methods) which receives one structured audit entry per evaluated action. When logging is enabled, runtime/validation errors are caught and converted to fallback results (`isAllowed` → `false`, `checkResources` → empty results) instead of being thrown; when disabled, errors propagate to the caller.

### OpenTelemetry (`src/telemetry.js`)

Same delegation pattern as logger/cache/codec: the `telemetry` option accepts `{ api }` (the `@opentelemetry/api` module — Kerberos derives tracer/meter with the `@alexify/kerberos` scope) or `{ tracer, meter }` instances; the package never depends on `@opentelemetry/api`. `createTelemetryWriter` mirrors `createLoggerWriter` (factory + no-op disabled writer); the writer contract is `{ enabled, withRequestSpan, recordDecisions, recordError, endRequest }`, hooked into `isAllowed`/`checkResources` alongside the existing `#log`/`#logMethod*` call sites. Invariants: `SPAN_STATUS_ERROR = 2` is hardcoded because OTel status codes are spec-frozen (avoids needing the api module for constants); every writer method swallows its own failures — telemetry must never affect authorization results or the logger-controlled swallow-vs-rethrow error contract; the module has zero imports and must stay platform-neutral. `@opentelemetry/*` packages are devDependencies only (test usage, like `pino`).

### ReBAC / Relations (`src/Relations/`)

Two layers, both SpiceDB-inspired (see the "borrow vs skip" notes in `README.md` "ReBAC (Relations)"):

1. **Engine seam** (`relations` constructor option, main entry): a delegation contract `{ check({principal, resource, relation}, {memo}), list?({...relations[]}, {memo}) }` — any resolver works. Derived-role definitions gain an optional `relation:` field (then `parentRoles`/`condition` become optional sync gates — `DerivedRoles.getRelationCandidates`); the engine resolves candidates on its only async phase (`#getImportedDerivedRoles` → `#resolveRelationCandidates`): list-first, `Promise.allSettled` check fallback (a rejection still surfaces per `onError` after all settle), one `relationsMemo` Map per public call shared across the whole `checkResources` batch, `{ source: 'relations', ... }` decision-trace entries under `includeMeta`.
2. **Built-in resolver** (the `RelationResolver` class, exported ONLY from the `@alexify/kerberos/relations` subpath — CJS doesn't tree-shake, keep it out of the main entry): `RelationSchema.js` compiles the JSON schema DSL into SpiceDB's userset-rewrite algebra (`{kind: 'ref'|'arrow'|'union'|'intersection'|'exclusion'}` nodes) with fail-fast reference checks and a precomputed O(1) admission-key Set per relation (`buildAdmissionKey`/`getRelationAdmission`); `RelationResolver.js` is a class in the Kerberos style (private fields, constructor-precompiled arg validators, prototype-less O(1) strategy tables over `node.kind` instead of switch — `#rewriteEvaluators`/`#subjectCollectors`/`#reachabilityCollectors`) holding the tuple indexes (static forward+reverse Maps; cache fallback docs `rel:<type>:<id>:<relation>`, opt-in reverse docs `rel:rev:<subjectKey>` behind `reverseIndex: true`), the recursive check (per-request memo of completed values + `maxDepth` guard, deliberately NO visited-set — SpiceDB semantics, unsound under exclusion; document reads memoize the *promise* as an in-process singleflight), caveat evaluation (`{ P, ctx }` only — no `R`, which is what keeps memoized subproblems batch-shareable; written context beats check-time context and is always passed as a copy; a caveat that THROWS raises `KerberosRelationsError` — errors are never read as answers, since "not matched" would widen access in exclusion subtract positions), and the reverse APIs (`lookupSubjects` collect-walk over a per-type Map/Set subject-set algebra with wildcard-exclusion sets; `lookupResources` via reachability analysis + candidate verification). Parallelism policy: check paths stay sequential (short-circuit saves cache reads); collect/lookup paths that need every branch run as `Promise.allSettled` waves via `settleAll` (all siblings settle, then the first rejection rethrows); BFS queues are cursor/level-based, never `shift()`. Optional `telemetry` option (spans per public call + `kerberos.relations.checks`; cache reads tagged `kerberos.cache.kind: relation`), guarded like the engine's. Static tuples are validated against the schema at construction (throw); cached doc entries the schema doesn't admit are skipped; corrupt docs THROW `KerberosCodecError` (misses stay empty). Memo keys are namespaced AND scoped: all entries carry the resolver-instance token, `check|`/`lr|` decision entries additionally carry principal/context identity tokens (WeakMap-assigned per object reference) — sharing a memo across principals/contexts/instances is safe by construction. Subject-relation refs must reference RELATIONS (permissions rejected at compile — the closure BFS cannot expand them); `|` is a reserved name char (admission-key delimiter); compiled refs/rewrite nodes are frozen and introspection getters return copies. Caveat `{ $expr }` conditions require a codec built with roots `['P', 'ctx']`. Typed error: `KerberosRelationsError`.

### Testing DSL (`src/Tests/`)

`KerberosTest`/`KerberosTests` (exported only from the `@alexify/kerberos/tests` subpath, not the main entry) implement a Cerbos-style declarative test runner: a JSON-ish fixture of `principals`/`resources`/`tests` is run against a live `Kerberos` instance and asserted with `node:test`. `Tests/Mocks/` provides named principal/resource fixture helpers. Use this pattern (see `README.md` "Testing" section) rather than hand-rolling policy assertions when adding policy-behavior tests.

### Public exports

The full package surface is assembled in `src/index.js` (main entry), `tests.js` (dev-only `/tests` subpath) and `relations.js` (`/relations` subpath) — check all three when adding a new export, and update `index.d.ts` / `tests.d.ts` / `relations.d.ts` in the repo root accordingly, since types are hand-maintained (not generated).

### Why the package doesn't ship a separate ESM build

CJS doesn't give property-level tree-shaking inside a single module, but the real size control for this package is the subpath exports (`/relations`, `/tests`), which drop entire files rather than individual exports. The main entry's DSL classes (Conditions, ResourcePolicy, RolePolicy, DerivedRoles, ...) are interdependent — Kerberos.js needs all of them at once — so there's no dead code to shake there regardless of module format.

A full ESM+CJS dual build is a deliberate non-goal: (1) it would contradict the "src/ ships as-is, no build step" philosophy; (2) heavy use of `instanceof` for self-classification (parsePolicy, schema builders, RelationResolver) creates a real dual package hazard risk if a CJS and an ESM copy ever load simultaneously in the same dependency tree.
