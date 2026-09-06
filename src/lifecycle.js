/**
 * Request-lifecycle plumbing shared by the engine (`src/Kerberos.js`) and the
 * relations resolver (`src/Relations/RelationResolver.js`): the run record
 * that enforces the hooks pairing invariant, the `request:*` event emitters,
 * identity-only payload projections and the swallowed-sink reporter. One
 * implementation of the contract on both classes — they must not drift.
 * Platform-neutral: no Node builtins (the callers pass their clock in).
 */

// Cache-result → event name, precomputed so the per-read hot path does no
// string building before the `wants()` gate.
const CACHE_EVENTS = Object.freeze({ hit: 'cache:hit', miss: 'cache:miss', error: 'cache:error' });

// Event payloads never carry Error objects (they may reach metrics/alerting
// pipelines): message string + name only.
function errorText(error) {
  return error instanceof Error ? error.message : String(error);
}

function withErrorFields(payload, error) {
  payload.error = errorText(error);
  payload.errorName = error?.name;
  return payload;
}

// Identity-only projections for event payloads: never the attribute bags —
// hooks get the full request context, events get correlation data.
function principalIdentity(principal) {
  return { id: principal.id, roles: Array.isArray(principal.roles) ? [...principal.roles] : principal.roles };
}

function resourceIdentity(resource) {
  const identity = { kind: resource.kind };
  // planResources resources carry no id — keep the payload key-minimal.
  if (resource.id !== undefined) identity.id = resource.id;
  if (resource.scope !== undefined) identity.scope = resource.scope;
  if (resource.policyVersion !== undefined) identity.policyVersion = resource.policyVersion;
  return identity;
}

/**
 * Per-request lifecycle record shared between a request wrapper and its
 * handler. `ctx` is set by `beginRun` once the arguments validated (hooks
 * enabled) and doubles as the "beforeRequest ran, so afterRequest is owed"
 * flag; `afterFired` guards the exactly-once invariant; `enriched` records
 * that `beforeRequest` replaced the arguments; `args` holds what the handler
 * must evaluate (the replacement after enrichment).
 */
function createRun(fields) {
  return { ...fields, ctx: null, args: null, enriched: false, afterFired: false, error: null };
}

/**
 * Builds the frozen context every hook of this run shares and runs
 * `beforeRequest`. `args`/`enriched` are live accessors over the run record so
 * the SAME frozen object reflects an enrichment to the later hooks, while
 * `ctx.args = …` throws in strict mode — mutation is not the contract.
 * Resolves to the hook's return value (a replacement, or undefined).
 */
function beginRun(run, hooks, fields) {
  run.ctx = Object.freeze({
    ...fields,
    get args() {
      return run.args;
    },
    get enriched() {
      return run.enriched;
    },
  });
  return hooks.beforeRequest(run.ctx);
}

/**
 * Runs `afterRequest` exactly once with the outcome summary. The runner
 * throws on the success path and swallows on the failure path.
 */
function finishRun(run, hooks, durationMs, error, failClosed) {
  run.afterFired = true;
  const summary = { success: error === null, durationMs };
  if (error !== null) {
    summary.error = error;
    if (failClosed) summary.failClosed = true;
  }
  if (run.enriched) summary.enriched = true;
  return hooks.afterRequest(run.ctx, summary);
}

// `request:*` emitters. `fieldsOf(run)` builds the correlation fields of the
// caller's payload shape (engine: callId/reqKind/reqId; resolver:
// callId/kind); payloads are built only behind the `wants()` gate.
function emitRequestStart(events, fieldsOf, run) {
  if (!events.wants('request:start')) return;
  events.emit('request:start', fieldsOf(run));
}

function emitRequestError(events, fieldsOf, run, error) {
  if (!events.wants('request:error')) return;
  events.emit('request:error', withErrorFields(fieldsOf(run), error));
}

function emitRequestEnd(events, fieldsOf, run, durationMs) {
  if (!events.wants('request:end')) return;
  const payload = fieldsOf(run);
  payload.durationMs = durationMs;
  payload.success = run.error === null;
  if (run.error !== null) withErrorFields(payload, run.error);
  if (run.enriched) payload.enriched = true;
  events.emit('request:end', payload);
}

// Observability sinks whose failures are swallowed + counted + warned once
// per sink (kerberos.observability.failures{kerberos.observability.sink}).
const SINK_LABELS = Object.freeze({ logger: 'audit logger', hooks: 'lifecycle hook', events: 'event listener' });

/**
 * Builds the `(sinkError, sink) => void` reporter behind every guarded
 * observability call: counts the failure on the telemetry channel and warns
 * once PER sink (a noisy event listener must not suppress the later, more
 * important audit-logger warning), so a permanently broken sink is
 * discoverable before someone needs its output.
 */
function createSinkFailureReporter({ telemetry, prefix, labels = SINK_LABELS, unaffected }) {
  const warned = new Set();
  return (sinkError, sink) => {
    telemetry.recordObservabilityFailure(sink);
    if (warned.has(sink)) return;
    warned.add(sink);
    try {
      console.warn(
        `${prefix}: the ${labels[sink] ?? sink} threw and was swallowed (${unaffected}; further warnings suppressed): ${sinkError?.message}`,
      );
    } catch {
      // Even the warning is best-effort.
    }
  };
}

/**
 * Builds the `onLeak` callback of an event hub: one console warning per event
 * name the first time its listener count passes `maxListeners`.
 */
function createLeakReporter(prefix) {
  return (eventName, count, max) => {
    try {
      console.warn(
        `${prefix}: possible listener leak — ${count} listeners on "${eventName}" (maxListeners: ${max}). Subscribe once at startup, not per request; raise maxListeners (0 disables) if this is intended. Further warnings for this event suppressed.`,
      );
    } catch {
      // Best-effort.
    }
  };
}

module.exports = {
  CACHE_EVENTS,
  SINK_LABELS,
  beginRun,
  createLeakReporter,
  createRun,
  createSinkFailureReporter,
  emitRequestEnd,
  emitRequestError,
  emitRequestStart,
  errorText,
  finishRun,
  principalIdentity,
  resourceIdentity,
  withErrorFields,
};
