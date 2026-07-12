# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Kerberos.js (`@alexify/kerberos`) is a zero-dependency (~6 KB), in-process authorization engine for JavaScript — a lightweight, embeddable alternative to Cerbos. It evaluates `resourcePolicy` / `principalPolicy` / `rolePolicy` documents against `(principal, resource, action)` requests and returns `EFFECT_ALLOW` / `EFFECT_DENY`, with optional derived roles, conditions, variables, constants, outputs, scopes, schema validation, audit logging, and cache-backed dynamic policies. Runs in Node.js and the browser.

Package manager is **pnpm** (`packageManager: pnpm@11.5.0`). CommonJS throughout (`require`/`module.exports`), no build/transpile step — `src/` ships as-is.

## Commands

```bash
pnpm test              # run all tests: node --test test/*.test.js
node --test test/Kerberos.test.js          # run a single test file
node --test --test-name-pattern="scope"    # filter tests by name
pnpm test:types        # type-check test/types.test-d.ts against index.d.ts via tsd
pnpm lint              # eslint src -c eslint.config.js (neostandard config)
```

There is also `oxlint`/`oxfmt` config (`.oxlintrc.json`, `.oxfmtrc.json`) but no npm scripts wire them up yet — `pnpm lint` (ESLint/neostandard) is the enforced linter, and `pre-commit` (see `package.json`) runs `lint` then `test` on commit.

Style: 2-space indent, single quotes, semicolons, 120-char lines (see `.editorconfig`, `.oxfmtrc.json`).

## Architecture

### Module shape

Every DSL concept (`Conditions`, `Constants`, `DerivedRoles`, `Outputs`, `PrincipalPolicy`, `ResourcePolicy`, `RolePolicy`, `Variables`, `Tests`) lives in `src/<Name>/` with a consistent internal layout:

- `<Name>.js` — the class itself (parsing/normalizing a raw shape, evaluation logic)
- `schemas/index.js` — schema builders for the three validation backends (Zod / JSON Schema / TypeBox)
- `validation/index.js` — `parse<Name>Shape()` helper that resolves and applies whichever validation backend is configured
- `index.js` — re-exports the above

`src/index.js` merges every module's `index.js` into the single package export. When adding a new DSL concept or policy field, follow this same four-file pattern rather than inlining logic elsewhere.

### Request evaluation flow (`src/Kerberos.js`)

`Kerberos` is the sole runtime engine. Policies passed to the constructor are parsed (via `Kerberos.parsePolicy`) and stored in four private `Map`s keyed by scope-aware cache keys: `#resourcePolicies`, `#principalPolicies`, `#rolePolicies`, `#derivedRoles`.

Policy/version/scope lookup (`#getResourcePolicy`, `#getPrincipalPolicy`, `#getRolePolicyByName`) walks the **scope search chain** (`Kerberos.getScopeSearchChain`, most-specific → base `''`) crossed with `policyVersion` (default `'default'`). In-memory `Map`s are checked first; on a miss, if a `cache` option was supplied, it falls back to `await cache.get(key)` (see Caching below).

Per-action resolution order (`#evaluatePolicySources`), computed independently for every action in a request:

1. `PrincipalPolicy` matching `principal.id` — explicit `Allow`/`Deny` wins immediately.
2. Otherwise, all `RolePolicy` entries matching `principal.roles[]` are evaluated (`#evaluateRolePolicies`); `Deny` wins over `Allow` across roles. `parentRoles` intersect the child's allowed actions with each locally-defined parent role policy.
3. Otherwise, fall back to `ResourcePolicy` matched by `resource.kind` (rules matched by `roles` / `derivedRoles`, evaluated via `Conditions`/`Variables`/`Constants`/`Outputs`).
4. No match → `EFFECT_DENY`.

Public API is just `isAllowed(args)` (single action → boolean) and `checkResources(args, effectAsBoolean?)` (batch, multiple resources/actions → structured response with `kerberosCallId`, `outputs`, optional `meta`). Both are implemented on top of the same `#evaluatePolicySources` core.

### Validation backends (`src/validation/`)

Kerberos never hard-depends on a validation library. `resolveValidationAdapter`/`parseWithValidation` (`src/validation/index.js`) picks, in priority order: an explicit schema/parser → Zod (`z` option) → TypeBox+Ajv (`typebox` + `ajv` options) → plain JSON Schema+Ajv (`ajv` option) → no-op passthrough. Every DSL module's `schemas/index.js` exports builders for all three backends so this dispatch works uniformly. Ajv needs custom keywords (`src/validation/keywords.js`, `registerAjvKeywords`) because policies can contain live JS functions (conditions/variables/outputs), which plain JSON Schema can't express.

### Caching / dynamic policies (`src/caching/`)

Kerberos is cache-**agnostic**: `cache.js` (`createCacheReader`) wraps anything exposing `get(key)` (keyv, cacheable, cache-manager…) as a read-only fallback layer — Kerberos never handles TTL, writes, or invalidation itself. It's a pure fallback: static/in-memory policies are always checked first; `cache.get` is only called on a miss, once per scope-chain entry.

Because remote-stored policies must be JSON (no live functions), `codec.js` (`createSafeExprCodec`) implements an **eval-free AST-allowlist interpreter** on top of `jsep`: conditions/variables/outputs are authored as `{ "$expr": "..." }` strings, parsed once per (jsep instance, expression) and cached, then walked against `{P, R, V, C}` plus a curated safe-builtins allowlist (`Math`, `Date`, `parseInt`/`parseFloat`/etc.). `__proto__`/`prototype`/`constructor` member access is blocked at the interpreter level regardless of how it's spelled, and there is deliberately no `eval`/`new Function`/`fn.toString()` anywhere in this path — see the "Serialization mechanism" section of `README.md` for the rationale before changing this file. The recommended production stack layered on top (documented in README, not part of this package) is `keyv` → `cacheable` (`CacheSync`) → `qified` (pub/sub invalidation across hosts).

### Logging (`src/logging.js`)

`logger` option accepts `true` (legacy `console.group`/`table`/`debug` output), a custom console-like object, or a structured logger (e.g. Pino, detected via `info`/`debug` methods) which receives one structured audit entry per evaluated action. When logging is enabled, runtime/validation errors are caught and converted to fallback results (`isAllowed` → `false`, `checkResources` → empty results) instead of being thrown; when disabled, errors propagate to the caller.

### Testing DSL (`src/Tests/`)

`KerberosTest`/`KerberosTests` (exported only from the `@alexify/kerberos/tests` subpath, not the main entry) implement a Cerbos-style declarative test runner: a JSON-ish fixture of `principals`/`resources`/`tests` is run against a live `Kerberos` instance and asserted with `node:test`. `Tests/Mocks/` provides named principal/resource fixture helpers. Use this pattern (see `README.md` "Testing" section) rather than hand-rolling policy assertions when adding policy-behavior tests.

### Public exports

The full package surface is assembled in `src/index.js` (main entry) and `tests.js` (dev-only `/tests` subpath) — check both when adding a new export, and update `index.d.ts` / `tests.d.ts` in the repo root accordingly, since types are hand-maintained (not generated).
