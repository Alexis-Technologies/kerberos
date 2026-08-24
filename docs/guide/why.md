# Why Kerberos.js?

An **embedded, zero-dependency authorization engine** for Node.js and the browser: Cerbos-style policies (RBAC + ABAC), a SpiceDB-inspired "Zanzibar-lite" resolver (ReBAC) and Cerbos-compatible query plans — all in-process, no server to deploy, [~29 KB min+gzip](/guide/installation#bundle-size). The API deliberately stays as close to Cerbos as possible: if you know Cerbos, you already know Kerberos.js.

## Why in-process?

**Authorization as a library, not a service.** Cerbos and SpiceDB are excellent engines, but each runs as a separate Go server: another deployment, another network hop on every check, another thing that can be down. In a JavaScript stack, Kerberos.js gives you the same policy models with zero infrastructure — decisions are a function call, policies ship (and roll back) atomically with your code, and there is no PDP to keep in sync. A centralized service remains the right choice for polyglot stacks — see [When NOT to use it](#when-not-to-use-kerberos-js).

**Policies are data plus the full power of JavaScript.** In-process policies use plain JS functions for conditions, variables and outputs — no expression-language ceiling. Policies stored in a cache/database use the same shapes with safe, eval-free [`$expr` expressions](/guide/caching). Local testing needs no emulator: the [`/tests` subpath](/guide/testing) runs Cerbos-style declarative test suites against the real engine.

**One engine everywhere.** The [browser build](/guide/installation#browser-usage) contains zero Node builtins, so the same policies that guard your API also gate your UI (hide buttons, filter menus) — without maintaining a second source of truth. Serverless and edge runtimes get the same benefit: no cold-start dependency on an external PDP.

## Positioning

| | **Kerberos.js**                                                                       | **Cerbos**                         | **SpiceDB** |
| --- |---------------------------------------------------------------------------------------|------------------------------------| --- |
| Deployment | in-process library (JS)                                                               | PDP service (sidecar/central)      | central service |
| Policy model | Cerbos-style RBAC+ABAC + ReBAC + query plans                                          | RBAC+ABAC (policies style)         | ReBAC (Zanzibar) |
| Conditions | JS functions / safe `$expr`                                                           | CEL                                | caveats (CEL) |
| Query plans | `planResources` (Cerbos-compatible shape)                                             | `PlanResources`                    | `LookupResources` |
| Consistency | in-process state + your cache ([honest limitations](/guide/relations-resolver#consistency-honest-limitations)) | per-PDP policy sync                | Zanzibar consistency (zookies) |
| Best when | JS/TS stack, zero-infra, browser/edge                                                 | polyglot stack, central governance | relationship graphs at scale, strict consistency |

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

::: tip Version 3.x
See the [CHANGELOG](https://github.com/Alexis-Technologies/kerberos/blob/main/CHANGELOG.md) for everything that changed since `2.0.0`: ReBAC with the built-in Zanzibar-lite resolver (`3.0.0`), OpenTelemetry, the Node/browser runtime split, and Cerbos-compatible query plans via `planResources` (`3.1.0`).
:::
