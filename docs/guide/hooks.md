# Hooks & events

Two complementary ways to plug into the engine's lifecycle:

- **Hooks** are configured up front (the `hooks` option), run **inside** the request flow and are **awaited** — use them to run your own logic around a decision (tenant guards, rate limits, request enrichment, an audit sink that must complete before the response) and to **veto** a request by throwing.
- **Events** are subscribed from outside (`kerberos.on(name, listener)`), fire **synchronously** after the fact and can never affect a decision — use them to feed metrics, alerting or dashboards without parsing audit logs.

Both live on `Kerberos` and on the built-in [`RelationResolver`](/guide/relations-resolver#resolver-hooks-events).

## Hooks

```javascript
const kerberos = new Kerberos(policies, derivedRoles, {
  onError: 'deny',
  hooks: {
    // Once per request, after the arguments validated. Throw to veto.
    async beforeRequest(ctx) {
      if (ctx.args.principal.attr?.suspended) throw new Error('suspended principal');
    },
    // Once per request — on success, on failure and on the fail-closed path.
    async afterRequest(ctx, summary) {
      await audit.write({ callId: ctx.callId, kind: ctx.reqKind, ...summary });
    },
    // Around each resource evaluation (isAllowed, checkResources).
    beforeResource(ctx, info) {
      metrics.increment('authz.resource', { kind: info.resource.kind });
    },
    afterResource(ctx, info, result) {
      if (result.actions.delete === 'EFFECT_ALLOW') alerts.notify(ctx, info);
    },
    // When a request fails — receives the error before afterRequest.
    onError(error, ctx) {
      sentry.captureException(error, { extra: { callId: ctx.callId } });
    },
  },
});
```

| Hook | Signature | When it runs |
| ---- | --------- | ------------ |
| `beforeRequest` | `(ctx)` | Once per `isAllowed` / `checkResources` / `planResources` call, **after** argument validation and before any evaluation. |
| `beforeResource` | `(ctx, info)` | Before each resource evaluation — once for `isAllowed`, once per entry of a `checkResources` batch (never for `planResources`). |
| `afterResource` | `(ctx, info, result)` | After each **successful** resource evaluation. |
| `afterRequest` | `(ctx, summary)` | Once per request — on success, on failure, **and** on the `onError: 'deny'` fail-closed path. |
| `onError` | `(error, ctx)` | When the request fails, before `afterRequest`. |

Hooks may be sync or async; they are awaited and their return value is ignored. A hook changes the outcome only by **throwing**.

### What a hook receives

- `ctx` — one object shared by every hook of the request: `{ reqKind: 'IsAllowed' | 'CheckResources' | 'PlanResources', callId, reqId?, args }`. `callId` is the request's `kerberosCallId` (the same one audit logs, telemetry spans and events carry); `args` are the **validated** arguments of the method — the same principal/resource objects the engine evaluates (under Zod, the parsed output). They are neither cloned nor frozen: treat them as read-only.
- `info` — `{ index, total, resource, actions }`: the resource's position in the request (`0` of `1` for `isAllowed`), the resource object and the requested actions.
- `result` — `{ actions: { [action]: 'EFFECT_ALLOW' | 'EFFECT_DENY' }, outputs, validationErrors?, meta? }`, always with canonical `EFFECT_*` strings (never the `effectAsBoolean` view).
- `summary` — `{ success, durationMs, error?, failClosed? }`. `success` is `false` whenever the request failed, **including** when `onError: 'deny'` converted the failure into a fail-closed result — `failClosed: true` tells the two apart.

### Execution order

```
request:start (event)
  validate arguments                      ← KerberosValidationError: no hook fires
  beforeRequest(ctx)                      ← throw = veto
    beforeResource(ctx, info[0]) → evaluate → afterResource(ctx, info[0], result)
    beforeResource(ctx, info[1]) → evaluate → afterResource(ctx, info[1], result)
  decision (event, one per resource)
  afterRequest(ctx, { success: true })
request:end (event)
```

A `checkResources` batch evaluates its resources concurrently (bounded by `maxConcurrency`), so the per-resource hooks of different resources interleave; each resource's `beforeResource`/`afterResource` pair is ordered, and `info.index` is the resource's position, not the invocation order.

The failure path:

```
  beforeRequest(ctx)
    beforeResource(ctx, info) → evaluate ✖
  request:error (event)
  onError(error, ctx)                                ← always swallowed
  afterRequest(ctx, { success: false, error })       ← always swallowed
request:end (event, success: false)
→ onError: 'throw' rethrows; onError: 'deny' returns the fail-closed result (summary.failClosed = true)
```

### Error contract

| Hook that throws | What happens |
| ---------------- | ------------ |
| `beforeRequest`, `afterRequest` **after a successful request** | Wrapped in `KerberosHookError` (`hook` names it, `cause` is your error) and handled like any evaluation error: [`onError: 'throw'`](/guide/configuration#options) propagates it, `'deny'` returns the fail-closed result. |
| `beforeResource`, `afterResource` inside a `checkResources` batch | Isolated to **that resource**, exactly like an evaluation error: all its actions come back `EFFECT_DENY` with `reason: 'evaluation-error', errorName: 'KerberosHookError'` under `includeMeta`; the other resources are unaffected and the batch resolves (so `afterRequest` sees `success: true`). |
| `beforeResource`, `afterResource` in `isAllowed` | The single resource *is* the request — follows `onError`. |
| `afterRequest` **after a failed request**, `onError` | Swallowed: the original error is what surfaces. The failure is counted on `kerberos.observability.failures{kerberos.observability.sink: 'hooks'}` and `console.warn`ed once per instance. |

Hooks never run for malformed arguments (`KerberosValidationError`), and the pairing invariant always holds: once `beforeRequest` ran, `onError` (on failure) and `afterRequest` run exactly once — even when the success-path `afterRequest` was itself the failure, it is not re-invoked. Unknown hook names and non-function values are rejected at construction with a `TypeError`.

### Performance notes

- Request-level hooks add one awaited call per request; the fully-synchronous evaluation driver (no cache, no relations) stays in use.
- `beforeResource` / `afterResource` wrap each evaluation in an async frame, so they are the only hooks with a per-resource cost.
- With no hooks configured the runner is a no-op object and every call site short-circuits on one boolean.

## Events

```javascript
kerberos
  .on('decision', ({ callId, principal, resource, actions }) => {
    for (const [action, effect] of Object.entries(actions)) {
      metrics.increment('authz.decisions', { kind: resource.kind, action, effect });
    }
  })
  .on('request:end', ({ reqKind, durationMs, success }) => {
    metrics.timing('authz.request', durationMs, { reqKind, success });
  })
  .on('cache:error', ({ key, errorName }) => alerts.notify(`policy cache read failed: ${key} (${errorName})`));
```

`on` / `once` / `off` / `removeAllListeners` are chainable; `listenerCount(name)` reports subscriptions. Unknown event names are a type error in TypeScript. There is deliberately **no public `emit`** (events are the engine's outbound signal — a consumer must not be able to forge `decision` entries into an audit pipeline) and no bare `'error'` event.

| Event | Payload | When |
| ----- | ------- | ---- |
| `request:start` | `{ callId, reqKind, reqId? }` | Before argument validation, once per public call. |
| `request:end` | `{ callId, reqKind, reqId?, durationMs, success, error?, errorName? }` | Always, last. `success: false` on failure — also on the `onError: 'deny'` path. |
| `request:error` | `{ callId, reqKind, reqId?, error, errorName }` | When the request failed (validation errors included). |
| `decision` | `{ callId, reqKind, reqId?, index, principal, resource, actions, reason?, errorName? }` | One per evaluated resource of `isAllowed` / `checkResources`; fail-closed decisions carry `reason: 'evaluation-error'`. |
| `plan` | `{ callId, reqKind, reqId?, principal, resource, actions, filterKind, opaqueCount, relationCount }` | After `planResources` built its filter. |
| `relations:resolved` | `{ callId, principal, resource, relations, granted, mode: 'list' \| 'check', durationMs }` | After the `relations` resolver answered for one resource. |
| `cache:hit` / `cache:miss` / `cache:error` | `{ key, error?, errorName? }` | Per policy-cache read. No `callId`: the lookup path has no request context (parity with the `Cache.*` log entries). |

Rules every payload follows:

- **Correlation** — every request-scoped payload carries the request's `callId` (the `kerberosCallId` of the response, the audit entries and the telemetry span), so a `decision` can be joined to its `request:end` and to the resolver's events (see below).
- **Identity only** — `principal` is `{ id, roles }` and `resource` is `{ kind, id, scope?, policyVersion? }`; attribute bags are never included (they may hold secrets). Hooks get the full context; events get correlation data.
- **No `Error` objects** — failures are a message string (`error`) plus `errorName`, safe to ship to metrics or alerting as-is.
- **Fresh objects** — each payload is built for that emission (only when someone listens); mutating it affects nothing.
- **Contained listeners** — emission is synchronous and fire-and-forget. A listener that throws, or returns a rejecting promise, never affects the decision: the failure is counted on `kerberos.observability.failures{kerberos.observability.sink: 'events'}` and `console.warn`ed once per instance.

The emitter is a small built-in class (a copy of [metautil](https://github.com/metarhia/metautil)'s `Emitter`), the same on Node.js and in the browser — `Kerberos` is **not** a `node:events` `EventEmitter` (`instanceof EventEmitter`, `events.once(kerberos, …)` or `addListener` do not apply; wrap `on`/`off` if you need them).

### Resolver events

The built-in `RelationResolver` emits `request:start` / `request:end` / `request:error` (`{ callId, kind: 'check' | 'list' | 'lookupSubjects' | 'lookupResources', … }`), `relation:checked` (`{ callId, kind, resource: { kind, id }, relation, subject, allowed }` — one per relation or permission checked) and `cache:hit` / `cache:miss` / `cache:error` for tuple-document reads (`{ key, kind: 'relation', callId, error?, errorName? }`). When the engine calls the resolver through the `relations` seam, `callId` is the engine's `kerberosCallId`, so resolver and engine events line up; standalone calls get a generated id.

## Hooks vs events

| | Hooks | Events |
| - | ----- | ------ |
| Registration | `hooks` constructor option, one function per name | `kerberos.on(name, fn)`, any number of listeners |
| Timing | Awaited inside the request | Synchronous, after the fact |
| Can veto / fail the request | Yes — by throwing (`KerberosHookError`, follows `onError`) | Never — failures are contained |
| Data | Full validated arguments and results | Identity-only payloads |
| Fires for malformed arguments | No | `request:start` / `request:error` / `request:end` |
| Typical use | Guards, enrichment, blocking audit | Metrics, alerting, dashboards |
