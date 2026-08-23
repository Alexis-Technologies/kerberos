# Configuration Options

The Kerberos constructor accepts an optional third parameter with configuration options:

```javascript
const kerberos = new Kerberos(policies, derivedRoles, {
  logger: true, // Legacy console audit logging with summary + table + debug(json)
  onError: 'deny', // 'throw' (default) or 'deny' — fail-closed evaluation errors
  telemetry, // Optional: OpenTelemetry traces + metrics ({ api } or { tracer, meter })
  cache, // Optional: any cache solution exposing get(key) (keyv, cacheable, ...)
  cacheRetry: { attempts: 3 }, // Optional: retry policy for transient cache.get failures
  codec, // Optional: (de)serialization codec for dynamic policies ({ jsep } or { deserialize })
  relations, // Optional: ReBAC resolver for relation-backed derived roles
  z, // Optional: validate with Zod
  ajv, // Optional: validate with Ajv
  typebox: Type, // Optional: switch Ajv validation to TypeBox builders
  getCallId: () => `custom-${Date.now()}`, // Custom call ID generator (optional)
});
```

## Options

- **`logger`** (boolean | KerberosLogger): Enable audit logging.
  - `true` keeps the legacy console behavior with `group + summary + table + debug(json)`
  - `false` or omitted disables logging
  - a custom `console`-like logger keeps the legacy table/json flow
  - a structured logger such as `Pino` receives one structured audit entry per evaluated action
  - Logging is pure observability: it never changes decisions or error behavior (that is [`onError`](#options)'s job), and a throwing logger is swallowed — it can never affect authorization.
- **`onError`** (`'throw' | 'deny'`, default `'throw'`): What happens when policy **evaluation** fails at runtime (a throwing condition function, a failing cache backend, a ReBAC resolver error).
  - `'throw'` propagates the error to the caller;
  - `'deny'` fails closed: `isAllowed` resolves to `false`, `checkResources` to `{ results: [], kerberosCallId, reqId? }`, `planResources` to a `KIND_ALWAYS_DENIED` filter.
  - Malformed **arguments** are programming errors and always throw `KerberosValidationError`, regardless of this option.

  ```javascript
  // Fail-closed setup: evaluation errors deny instead of throwing.
  const kerberos = new Kerberos(policies, derivedRoles, { onError: 'deny' });
  ```

- **`telemetry`** (KerberosTelemetryOptions): Enable OpenTelemetry traces and metrics. Pass `{ api }` (the `@opentelemetry/api` module) or `{ tracer, meter }` instances — see [OpenTelemetry](/guide/telemetry).
- **`cache`** (CacheLike): An optional cache used as a fallback source for dynamic/stored policies. Any object exposing a `get(key)` method is accepted (keyv, cacheable, cache-manager, ...). See [Caching / Storing policies](/guide/caching).
- **`cacheRetry`** (`{ attempts?, delayMs?, jitter?, timeoutMs?, onExhausted? }`, default `{ attempts: 3, delayMs: 25, jitter: true }`): Retry policy for `cache.get` failures. Attempts are spaced by full-jitter exponential backoff (`delayMs` base, doubling per attempt; `delayMs: 0` restores immediate retries); deterministic adapter errors (`TypeError`/`SyntaxError`) are never retried. `timeoutMs` (off by default) bounds each read attempt so a *hung* backend fails instead of hanging authorization. After the attempts are exhausted the failure surfaces as `KerberosCacheError` (and then follows `onError`) — unless `onExhausted: 'miss'` opts into **degraded mode**: the read counts as a cache miss and evaluation falls through to the remaining static sources, so a cache outage no longer disables statically-resolvable decisions (the degradation stays visible via the `kerberos.cache.requests` `error` metric and a guarded error log entry). `attempts: 1` disables retrying.
- **`cacheKeyPrefix`** (`string`, default `''`): Prefix prepended to **every** cache key (policies *and* derived roles). Use it to namespace tenants or environments sharing one store — derived-roles documents are otherwise a single global `derivedRoles:<name>` namespace, so two tenants publishing the same definition name on a shared store would silently overwrite each other.
- **`relationsTimeoutMs`** (`number`, off by default): Bounds each `relations.check` / `relations.list` call; a resolver that neither resolves nor rejects fails as `KerberosRelationsError` (following `onError`) instead of hanging the request.
- **`audit`** (`{ includeMeta?: boolean }`): Engine-level audit enrichment. With `{ includeMeta: true }` and a logger attached, decision tracing runs for **every** request, so audit entries always carry `meta.resolution` and the `policy-miss` reason — audit completeness stops depending on each call site remembering the per-request `includeMeta` flag. The response stays gated on the request flag.
- **`maxConcurrency`** (`number`, unbounded by default): Caps how many resources of a `checkResources` batch evaluate at once. Without it a 10k-resource batch launches 10k concurrent evaluation chains (each issuing its own cache reads) — memory spikes, event-loop saturation and a thundering herd on the cache backend. The built-in `RelationResolver` accepts the same option for its `lookupResources` candidate-verification fan-out.
- **`codec`** (PolicyCodec): How cached policy documents are transformed before construction: `{ jsep }` enables the built-in safe `$expr` evaluator, `{ deserialize }` plugs in your own logic, and when omitted cached values are passed to policy constructors **as-is** — see [`codec` option — three modes](/guide/caching#codec-option-three-modes).
- **`relations`** (KerberosRelationsResolver): ReBAC resolver used by relation-backed derived roles — any object with a `check(args, opts)` method (and an optional batched `list`). See [ReBAC (Relations)](/guide/rebac).
- **`z`**: Enables validation using the built-in Zod schema builders.
- **`ajv`**: Enables validation using the built-in JSON Schema builders compiled with Ajv.
- **`typebox`**: When used together with `ajv`, switches validation to the built-in TypeBox builders.
- **`getCallId`** (function): Custom function to generate call IDs for audit tracking. 
  - **Default behavior**: Uses `crypto.randomUUID()` in Node.js, `window.crypto.randomUUID()` in browsers, or falls back to a pseudo UUID generator
  - **Custom example**: `() => \`req-\${Date.now()}-\${Math.random()}\``

## Using Pino for Production Logging

If you want machine-readable audit logs in production, pass a `Pino` instance as the `logger` option:

```javascript
import pino from 'pino';
import { Kerberos } from '@alexify/kerberos';

const logger = pino({ level: 'info' });

const kerberos = new Kerberos(policies, derivedRoles, {
  logger,
});
```

With `Pino`, Kerberos emits structured audit entries that include `callId`, `reqId`, `reqKind`, `principalId`, `principalRoles` (the role set the decision was based on — roles change over time, so past entries stay explainable), `resourceId`, `action`, `effect`, `outputs`, and `meta`. Fail-closed denials are part of the stream too: a resource whose evaluation failed inside a `checkResources` batch (and the `onError: 'deny'` fallback of `isAllowed`) logs its DENY decisions marked `reason: 'evaluation-error'`, and `planResources` results (`PlanResources.result`, with the filter kind) go out at **info** level like other decision entries — only lifecycle `*.start`/`*.finish` events sit at debug. This mode is better suited for production ingestion than the default console table output.

It also emits lifecycle logs such as `IsAllowed.start`, `IsAllowed.error`, `IsAllowed.finish`, `CheckResources.start`, `CheckResources.finish` and `PlanResources.*`. Errors are always logged, but whether they are rethrown or converted into a fail-closed response is decided solely by the [`onError`](#options) option — never by the logger.

## Call ID Generation

Every request (`isAllowed` / `checkResources` / `planResources`) automatically generates a unique `kerberosCallId` for audit tracking:

- **Node.js**: Uses `crypto.randomUUID()` 
- **Browser**: Uses `window.crypto.randomUUID()`
- **Fallback**: Pseudo UUID v4 generator if crypto APIs are unavailable
- **Custom**: Provide your own `getCallId` function for custom ID formats

This ID is included in both the response and audit logs for correlation.
