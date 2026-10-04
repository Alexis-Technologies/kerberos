# Why Kerberos.js?

An **embedded, zero-dependency authorization engine** for Node.js and the browser: Cerbos-style policies (RBAC + ABAC), a SpiceDB-inspired "Zanzibar-lite" resolver (ReBAC) and Cerbos-compatible query plans — all in-process, no server to deploy, [~38 KB min+gzip](/guide/installation#bundle-size). The API deliberately stays as close to Cerbos as possible: if you know Cerbos, you already know Kerberos.js.

## Why in-process?

**Authorization as a library, not a service.** Cerbos and SpiceDB are excellent engines, but each runs as a separate Go server: another deployment, another network hop on every check, another thing that can be down. In a JavaScript stack, Kerberos.js gives you the same policy models with zero infrastructure — decisions are a function call, policies ship (and roll back) atomically with your code, and there is no PDP to keep in sync. A centralized service remains the right choice for polyglot stacks — see [When NOT to use it](#when-not-to-use-kerberos-js).

**Policies are data plus the full power of JavaScript.** In-process policies use plain JS functions for conditions, variables and outputs — no expression-language ceiling. Policies stored in a cache/database use the same shapes with safe, eval-free [`$expr` expressions](/guide/caching). Local testing needs no emulator: the [`/tests` subpath](/guide/testing) runs Cerbos-style declarative test suites against the real engine.

**One engine everywhere.** The [browser build](/guide/installation#browser-usage) contains zero Node builtins, so the same policies that guard your API also gate your UI (hide buttons, filter menus) — without maintaining a second source of truth. Serverless and edge runtimes get the same benefit: no cold-start dependency on an external PDP.

## Compared with the alternatives

How Kerberos.js compares with the policy engines (Cerbos, SpiceDB, OPA) and the JavaScript authorization libraries it is [benchmarked against](/guide/benchmarks). ✅ built in · ⚠️ partial or with a caveat · ❌ not built in · — does not apply. A ❌ means the feature is not built in; most of them can still be written by hand on top.

<div class="kb-matrix">

| Architecture | **Kerberos.js** | Cerbos | SpiceDB | OPA | CASL | casbin | AccessControl | easy-rbac | @rbac/rbac |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Runs as | library | service (PDP) | service + database | service, Go library or WASM | library | library | library | library | library |
| Languages | JS / TS | 8 SDKs | 6 SDKs + HTTP | any (REST), Go | JS / TS | 10+ ports | JS / TS | JS / TS | JS / TS |
| In the browser | ✅ | ⚠️ WASM, Hub-built bundles | ❌ | ⚠️ WASM SDK + compiled `.wasm` | ✅ | ⚠️ needs Node polyfills¹ | ⚠️ bundles, not documented | ⚠️ bundles, not documented | ⚠️ default logger needs `process` |
| Runtime dependencies | 0 | — (server) | — (server) | 2 (WASM SDK) | 4 | 10 | 2 | 0 | 1 (`zod`)² |
| Check API | async | async (network) | async (network) | async (REST) · sync (WASM) | sync | async + `enforceSync` | sync + async | async | async |
| License | MIT | Apache-2.0 | Apache-2.0 | Apache-2.0 | MIT | Apache-2.0 | MIT | MIT | MIT |

| Policy model | **Kerberos.js** | Cerbos | SpiceDB | OPA | CASL | casbin | AccessControl | easy-rbac | @rbac/rbac |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Policy format | Cerbos-style documents | YAML / JSON documents | schema DSL + relationship tuples | Rego | JS builder / JSON rules | model `.conf` + policy rows | builder / grants JSON | role map | role map |
| Roles with inheritance | ✅ `parentRoles` | ✅ `parentRoles` | ✅ modeled as relations | ⚠️ written in Rego | ⚠️ no roles: map them to rules | ✅ role hierarchy | ✅ `extend` | ✅ `inherits` | ✅ `inherits` |
| Attribute conditions | ✅ JS functions / `$expr` | ✅ CEL | ✅ CEL caveats | ✅ Rego | ✅ MongoDB-style, resource only | ✅ matcher expressions | ✅ `.where()` expressions | ✅ JS `when` | ✅ JS `when` |
| Relationships (ReBAC) | ✅ built-in resolver | ❌ pass them as attributes | ✅ the core model | ⚠️ `graph.reachable`, model it yourself | ❌ | ⚠️ via role links | ❌ | ❌ | ❌ |
| Derived roles | ✅ | ✅ | ⚠️ computed permissions | ❌ plain Rego rules | ❌ | ❌ | ❌ `own` ownership only | ❌ | ❌ |
| Explicit deny | ✅ deny beats allow | ✅ deny beats allow | ⚠️ exclusion operator | ⚠️ precedence written in Rego | ⚠️ `cannot`, rule order decides | ✅ configurable effect | ✅ within a role chain³ | ❌ allow-only | ❌ allow-only |
| Field-level permissions | ⚠️ per-field actions or outputs | ⚠️ per-field actions or outputs | ❌ | ⚠️ column masks (server) | ✅ `fields` | ❌ | ✅ attribute filtering | ❌ | ❌ |
| Scopes / tenants | ✅ scope chain⁴ | ✅ scope chain | ❌ model tenants as objects | ❌ structure packages yourself | ❌ | ✅ domains | ⚠️ groups and categories | ❌ | ⚠️ one role map per tenant |
| Policy versions | ✅ | ✅ | ❌ | ⚠️ bundle revisions | ❌ | ❌ | ❌ | ❌ | ❌ |
| Outputs with the decision | ✅ | ✅ | ❌ | ✅ any JSON | ❌ reason string only | ❌ | ❌ | ❌ | ❌ |

| Queries and data | **Kerberos.js** | Cerbos | SpiceDB | OPA | CASL | casbin | AccessControl | easy-rbac | @rbac/rbac |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Policies as data, changed at runtime | ✅ any cache, eval-free `$expr` | ✅ disk, git, blob, DB, Hub | ✅ schema + relationships via API | ✅ bundles, policy API (WASM: rebuild) | ✅ JSON rules | ✅ DB adapters + watchers | ✅ grants from DB rows | ⚠️ loaded once at start | ⚠️ `updateRoles`; `when` stays code |
| Batch checks | ✅ `checkResources` | ✅ `CheckResources` | ✅ `CheckBulkPermissions` | ⚠️ design it into the policy | ❌ | ✅ `batchEnforce` | ❌ | ❌ | ❌ |
| Database filtering | ✅ `planResources` + Cerbos ORM adapters | ✅ `PlanResources` + ORM adapters | ⚠️ `LookupResources` returns ids | ✅ Compile API → SQL (server) | ✅ `rulesToCondition`, Prisma, Mongoose | ❌ | ❌ | ❌ | ❌ |
| "Who can access this?" | ⚠️ relations only (`lookupSubjects`) | ❌ | ✅ `LookupSubjects` | ⚠️ via partial evaluation | ⚠️ one user's rules | ✅ implicit-permission APIs | ⚠️ a role's actions | ❌ | ❌ |
| Explains a decision | ✅ `includeMeta` | ✅ `includeMeta` | ✅ debug trace | ✅ explain / trace (server) | ✅ `relevantRuleFor` | ✅ `enforceEx` | ⚠️ deny reason code | ❌ | ❌ |
| Consistency tokens | ❌ | — (stateless) | ✅ ZedTokens | — | — | — | — | — | — |

| Tooling and operations | **Kerberos.js** | Cerbos | SpiceDB | OPA | CASL | casbin | AccessControl | easy-rbac | @rbac/rbac |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Policy test runner | ✅ test DSL + CLI (Cerbos suite format) | ✅ `cerbos compile` | ✅ `zed validate` | ✅ `opa test` | ❌ | ❌ | ❌ | ❌ | ❌ |
| Attribute schema validation | ✅ JSON Schema / Zod | ✅ JSON Schema | ⚠️ typed relations and caveats | ⚠️ static type checks | ❌ | ❌ | ❌ | ❌ | ❌ |
| Audit / decision logs | ✅ structured logger + events | ✅ | ⚠️ paid tiers only | ✅ decision logs (server) | ❌ | ⚠️ console logger | ✅ `access` events | ❌ | ⚠️ logger callback |
| OpenTelemetry | ✅ traces + metrics | ✅ | ✅ traces | ✅ (server) | ❌ | ❌ | ❌ | ❌ | ❌ |
| Integrations | ⚠️ Cerbos ORM adapters, no middleware | ✅ React, ORM adapters | — (clients) | ⚠️ REST client SDK | ✅ React, Vue, Angular, Prisma, Mongoose | ✅ server middlewares, Casbin.js | ⚠️ NestJS (separate package) | ⚠️ Express middleware | ✅ Express, NestJS, Fastify |
| Managed control plane | — | ✅ Cerbos Hub (free tier + paid) | ✅ AuthZed Cloud (paid) | ⚠️ OPA Control Plane (no UI) | — | — | — | — | — |
| Reads Cerbos policies | ✅ YAML + CEL importer | ✅ native | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

</div>

1. casbin's README shows a browser import, but its main entry does not bundle for the browser without Node polyfills ([`pnpm size:compare`](/guide/benchmarks#bundle-size)). Casbin.js is its separate frontend package.
2. @rbac/rbac describes itself as zero-dependency but depends on `zod`.
3. AccessControl's deny wins within a role and the roles it inherits. When a check names several roles, a grant from one of them beats a deny from another.
4. Kerberos.js implements Cerbos's `OVERRIDE_PARENT` scope behaviour. The parental-consent mode and the other gaps are listed in [DIVERGENCES.md](https://github.com/Alexis-Technologies/kerberos/blob/main/conformance/DIVERGENCES.md).

"OPA" covers both the server and the WebAssembly SDK (`@open-policy-agent/opa-wasm`): rows marked "(server)" are not available in the SDK. Cerbos runs in the browser through `@cerbos/embedded-client`, whose WebAssembly bundles are built by Cerbos Hub. Compared versions: Kerberos.js 4.3, Cerbos 0.55, SpiceDB 1.56, OPA 1.21 with opa-wasm 1.10, CASL 7.0, casbin 5.51 (Node), AccessControl 3.1, easy-rbac 4.0 and @rbac/rbac 2.2, checked in October 2026 against each project's documentation and installed package. Throughput, cold start and bundle size of the same libraries are on the [benchmarks](/guide/benchmarks) page.

Where each one fits:

- **Kerberos.js** — a JS/TS stack with no authorization infrastructure, decisions in the browser or at the edge, Cerbos-style policies and query plans.
- **Cerbos** — polyglot backends and centrally governed policies, with Cerbos Hub as the control plane.
- **SpiceDB** — large relationship graphs that need Zanzibar-grade consistency.
- **OPA** — one general-purpose policy language across your stack, not only application authorization.
- **CASL** — permissions defined in code and shared with the UI, with field-level rules and ORM filtering.
- **casbin** — the same access model across many languages, with storage adapters.
- **AccessControl, easy-rbac, @rbac/rbac** — a role map with a few conditions, without policy documents.

## When NOT to use Kerberos.js

- **Polyglot backends** — if Go/Python/Java services need the same decisions, a central PDP (Cerbos) beats reimplementing policies per language.
- **Zanzibar-grade consistency** — the built-in ReBAC resolver reads current in-memory/cache state and deliberately has no revision tokens; if the [New Enemy Problem](https://authzed.com/docs/spicedb/concepts/consistency) matters for your threat model, use SpiceDB.
- **Non-engineering policy ownership** — policies here live in code/storage you control; if compliance teams need a managed policy workflow and UI, that is Cerbos Hub's territory.

## Features

| Area | What you get |
| ---- | ------------ |
| **Policy engine** | [Resource / principal / role policies](/guide/policy-types) (with `parentRoles` inheritance), [derived roles](/guide/getting-started), conditions, variables & constants, [outputs](/guide/outputs), [scopes & policy versions](/guide/scopes) |
| **APIs** | [`isAllowed`](/api/kerberos#kerberos-isallowed-args-promise-boolean), [`checkResources`](/api/kerberos#kerberos-checkresources-args-effectasboolean-false-promise-checkresourcesresponse), [`planResources`](/guide/query-plans) (Cerbos-compatible query plans) |
| **Dynamic policies** | [Cache-agnostic storage](/guide/caching) with a safe, eval-free `$expr` codec (jsep AST allowlist) |
| **ReBAC** | [Relation-backed derived roles](/guide/rebac) + a built-in Zanzibar-lite resolver (`@alexify/kerberos/relations`) |
| **Observability** | [Audit logs](/guide/configuration#options) (console / structured / Pino), [OpenTelemetry](/guide/telemetry) traces + metrics, [decision metadata](/guide/decision-metadata) |
| **DX** | [Pluggable validation](/guide/schema-validation) (Zod / JSON Schema + Ajv / TypeBox), [testing DSL](/guide/testing) (`/tests`), hand-maintained TypeScript types, [browser build](/guide/installation#browser-usage) |

::: tip Version 4.x
See the [CHANGELOG](https://github.com/Alexis-Technologies/kerberos/blob/main/CHANGELOG.md) for everything that changed since `3.1.0`: verified Cerbos compatibility (a conformance corpus replayed against a live PDP, plus the `/cerbos` YAML + CEL policy importer), attribute-schema enforcement, policy-as-code tooling (the `/loader` subpath and the `kerberos` CLI), typed policy authoring, and the code-review hardening waves — a `Conditions` fail-open fix, restored Node-ESM named exports, and a synchronous evaluation driver (~2.5× on simple `isAllowed`). `4.2.0` closes the parity gaps a differential campaign against a live PDP turned up — CEL-style strict comparisons and Cerbos's resource-kind sanitization — see its upgrade notes. `4.3.0` is a performance release: rules indexed by action and role, derived roles and the scope walk evaluated only as far as the decision needs (which also aligns unreached-scope behaviour with Cerbos), and ReBAC batches that share unfinished subproblems.
:::
