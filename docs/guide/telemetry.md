# OpenTelemetry

Kerberos.js ships native OpenTelemetry support (traces + metrics) following the same delegating philosophy as `logger` and `cache`: **the package never depends on `@opentelemetry/api`** (not even as a peer dependency). You pass either the api module or pre-created instances:

```javascript
import * as api from '@opentelemetry/api';
import { Kerberos } from '@alexify/kerberos';

// Preferred: pass the api module — Kerberos derives its own tracer/meter with
// the correct instrumentation scope ('@alexify/kerberos').
const kerberos = new Kerberos(policies, derivedRoles, { telemetry: { api } });

// Escape hatch: pre-created instances (either may be omitted).
const kerberos2 = new Kerberos(policies, derivedRoles, {
  telemetry: { tracer: myTracer, meter: myMeter },
});
```

Works out of the box with any registered SDK (e.g. `NodeSDK` from `@opentelemetry/sdk-node`); with no SDK registered, everything no-ops.

**Spans** — one per public call: `Kerberos.isAllowed` (decision attributes on the span) and `Kerberos.checkResources` (one `kerberos.decision` event per resource × action); the built-in ReBAC resolver adds `Kerberos.relations.check` / `.list` / `.lookupSubjects` / `.lookupResources` when given its own `telemetry` option (see [Resolver telemetry](/guide/relations-resolver#resolver-telemetry)). The span is started **active**, so spans created inside — e.g. an auto-instrumented Redis cache behind the `cache` option, or resolver spans under an engine span — nest correctly. Attributes include `kerberos.call_id`, `kerberos.req_id`, `kerberos.resource.kind`, `kerberos.action`, `kerberos.allowed` / `kerberos.effect`, `kerberos.matched_policy` / `kerberos.matched_rule` / `kerberos.matched_scope`, and identity attributes `kerberos.principal.id` / `kerberos.resource.id`. On errors the span gets `ERROR` status plus an exception event — error-handling behavior itself is controlled solely by the [`onError`](/guide/configuration) option, never by telemetry or logging.

**Metrics** — four instruments:

| Instrument | Type | Unit | Attributes |
| ---------- | ---- | ---- | ---------- |
| `kerberos.decisions` | Counter | `{decision}` | `kerberos.effect`, `kerberos.resource.kind` |
| `kerberos.plans` | Counter | `{plan}` | `kerberos.plan.kind`, `kerberos.resource.kind` |
| `kerberos.request.duration` | Histogram | `ms` | `kerberos.req_kind`, `error` |
| `kerberos.cache.requests` | Counter | `{request}` | `kerberos.cache.result` (`hit`/`miss`/`error`), `kerberos.cache.kind` (only for ReBAC tuple reads: `relation`) |
| `kerberos.relations.checks` | Counter | `{check}` | `kerberos.relations.result` (`allow`/`deny`) |

::: info
Metric attributes deliberately exclude actions and principals to keep cardinality bounded — they assume a bounded set of resource kinds.
:::

Notes:

- **Identity attributes are on by default** (parity with audit logs). Set `telemetry: { includeIdentity: false }` to strip `kerberos.principal.id` / `kerberos.resource.id` from spans and events when traces are exported to backends where identity data is unwanted.
- Telemetry failures (a broken tracer, exporter bugs) are swallowed internally — they can never affect authorization results.
- `@opentelemetry/api` is browser-compatible, so telemetry works in browser builds too.
