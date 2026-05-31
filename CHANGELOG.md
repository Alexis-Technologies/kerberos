# Changelog

All notable changes to **`@alexify/kerberos`** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[2.0.0]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v2.0.0
[1.0.0]: https://github.com/Alexis-Technologies/kerberos/releases/tag/v1.0.0
