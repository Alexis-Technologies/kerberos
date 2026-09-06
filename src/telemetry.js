// OpenTelemetry status code for errors. The numeric values are frozen by the
// OTel specification (0 = UNSET, 1 = OK, 2 = ERROR), so hardcoding avoids any
// dependency on the @opentelemetry/api module for constants.
const SPAN_STATUS_ERROR = 2;

// Instrumentation scope name. The version parameter of getTracer/getMeter is
// intentionally omitted: requiring package.json for it would drag the whole
// file into browser bundles.
const SCOPE_NAME = '@alexify/kerberos';

const SPAN_NAMES = {
  IsAllowed: 'Kerberos.isAllowed',
  CheckResources: 'Kerberos.checkResources',
  PlanResources: 'Kerberos.planResources',
  RelationsCheck: 'Kerberos.relations.check',
  RelationsList: 'Kerberos.relations.list',
  RelationsLookupSubjects: 'Kerberos.relations.lookupSubjects',
  RelationsLookupResources: 'Kerberos.relations.lookupResources',
};

function hasMethod(value, methodName) {
  return typeof value?.[methodName] === 'function';
}

/**
 * Normalizes an effect for telemetry attributes: `effectAsBoolean` responses
 * carry booleans, which are mapped back to the canonical effect strings so
 * metric series stay consistent regardless of the response format.
 */
function normalizeEffect(effect) {
  if (effect === true) return 'EFFECT_ALLOW';
  if (effect === false) return 'EFFECT_DENY';
  return effect;
}

/**
 * Resolves a tracer and meter from the `telemetry` option. Two modes are
 * supported, mirroring the `codec` option's multi-mode style:
 * - `{ api }` — the @opentelemetry/api module; Kerberos derives its own tracer
 *   and meter so spans/metrics get the correct instrumentation scope.
 * - `{ tracer, meter }` — pre-created instances (either may be absent).
 */
function resolveTracerAndMeter(telemetry) {
  if (telemetry.api) {
    const { api } = telemetry;
    return {
      tracer: hasMethod(api.trace, 'getTracer') ? api.trace.getTracer(SCOPE_NAME) : null,
      meter: hasMethod(api.metrics, 'getMeter') ? api.metrics.getMeter(SCOPE_NAME) : null,
    };
  }
  return { tracer: telemetry.tracer ?? null, meter: telemetry.meter ?? null };
}

function createDisabledTelemetryWriter() {
  return {
    enabled: false,
    withRequestSpan(reqKind, callId, reqId, fn) {
      return fn(null);
    },
    recordDecisions() {},
    recordPlan() {},
    recordError() {},
    recordCacheRequest() {},
    recordRelationCheck() {},
    recordRelationResolution() {},
    recordObservabilityFailure() {},
    recordHookDuration() {},
    endRequest() {},
  };
}

/**
 * Wraps user-supplied OpenTelemetry objects behind a writer used by the
 * Kerberos runtime. Following the same delegating philosophy as `logger` and
 * `cache`, the package never depends on @opentelemetry/api itself — the
 * consumer passes either the api module or tracer/meter instances.
 *
 * Every method swallows telemetry failures internally: a broken tracer,
 * exporter or meter must never affect authorization control flow.
 *
 * @param {{ api?: object, tracer?: object, meter?: object, includeIdentity?: boolean } | null | undefined} telemetry
 */
function createTelemetryWriter(telemetry) {
  if (!telemetry || typeof telemetry !== 'object') return createDisabledTelemetryWriter();

  let tracer = null;
  let meter = null;
  try {
    ({ tracer, meter } = resolveTracerAndMeter(telemetry));
  } catch {
    return createDisabledTelemetryWriter();
  }
  if (!tracer && !meter) return createDisabledTelemetryWriter();

  const includeIdentity = telemetry.includeIdentity !== false;

  let decisionsCounter = null;
  let plansCounter = null;
  let durationHistogram = null;
  let cacheRequestsCounter = null;
  let relationChecksCounter = null;
  let observabilityFailuresCounter = null;
  let hooksDurationHistogram = null;
  if (hasMethod(meter, 'createCounter') && hasMethod(meter, 'createHistogram')) {
    try {
      decisionsCounter = meter.createCounter('kerberos.decisions', {
        unit: '{decision}',
        description: 'Authorization decisions evaluated by Kerberos',
      });
      plansCounter = meter.createCounter('kerberos.plans', {
        unit: '{plan}',
        description: 'Resources query plans built by planResources, by filter kind',
      });
      durationHistogram = meter.createHistogram('kerberos.request.duration', {
        unit: 'ms',
        description: 'Duration of Kerberos engine and relations calls, by kerberos.req_kind',
      });
      cacheRequestsCounter = meter.createCounter('kerberos.cache.requests', {
        unit: '{request}',
        description: 'Dynamic-policy cache lookups by result (hit/miss/error)',
      });
      relationChecksCounter = meter.createCounter('kerberos.relations.checks', {
        unit: '{check}',
        description: 'ReBAC relation checks resolved by the built-in resolver',
      });
      observabilityFailuresCounter = meter.createCounter('kerberos.observability.failures', {
        unit: '{failure}',
        description:
          'Swallowed logger/telemetry/hooks/events sink failures, by kerberos.observability.sink — a non-zero rate means audit or telemetry output is being lost while authorization keeps working',
      });
      hooksDurationHistogram = meter.createHistogram('kerberos.hooks.duration', {
        unit: 'ms',
        description:
          'Wall time of each awaited lifecycle hook invocation, by kerberos.hook — hooks run inside the request, so this is their share of kerberos.request.duration',
      });
    } catch {
      decisionsCounter = null;
      plansCounter = null;
      durationHistogram = null;
      cacheRequestsCounter = null;
      relationChecksCounter = null;
      observabilityFailuresCounter = null;
      hooksDurationHistogram = null;
    }
  }

  // Best-effort self-count for the writer's own swallowed failures. Guarded so
  // a broken meter can never re-throw out of a catch block.
  function countSelfFailure() {
    try {
      observabilityFailuresCounter?.add(1, { 'kerberos.observability.sink': 'telemetry' });
    } catch {
      // Nothing left to do — the swallow contract still holds.
    }
  }

  function buildRequestAttributes(reqKind, callId, reqId) {
    const attributes = { 'kerberos.req_kind': reqKind };
    if (callId) attributes['kerberos.call_id'] = callId;
    if (reqId) attributes['kerberos.req_id'] = reqId;
    return attributes;
  }

  function setDecisionAttributesOnSpan(span, req, action, effect, actionMeta) {
    span.setAttribute?.('kerberos.resource.kind', req.R.kind);
    span.setAttribute?.('kerberos.action', action);
    span.setAttribute?.('kerberos.allowed', effect === 'EFFECT_ALLOW');
    if (actionMeta?.matchedPolicy) span.setAttribute?.('kerberos.matched_policy', actionMeta.matchedPolicy);
    if (actionMeta?.matchedRule) span.setAttribute?.('kerberos.matched_rule', actionMeta.matchedRule);
    if (actionMeta?.matchedScope) span.setAttribute?.('kerberos.matched_scope', actionMeta.matchedScope);
    if (includeIdentity && req.R.id) span.setAttribute?.('kerberos.resource.id', req.R.id);
  }

  function buildDecisionEventAttributes(req, action, effect, actionMeta) {
    const attributes = {
      'kerberos.resource.kind': req.R.kind,
      'kerberos.action': action,
      'kerberos.effect': effect,
    };
    if (actionMeta?.matchedPolicy) attributes['kerberos.matched_policy'] = actionMeta.matchedPolicy;
    if (actionMeta?.matchedRule) attributes['kerberos.matched_rule'] = actionMeta.matchedRule;
    if (actionMeta?.matchedScope) attributes['kerberos.matched_scope'] = actionMeta.matchedScope;
    if (includeIdentity && req.R.id) attributes['kerberos.resource.id'] = req.R.id;
    return attributes;
  }

  return {
    enabled: true,

    /**
     * Starts the request span (active when the tracer supports it, so spans
     * created inside — e.g. an auto-instrumented cache — nest correctly),
     * invokes `fn(handle)` exactly once and returns its result. The span is
     * ended by `endRequest`, not here.
     */
    withRequestSpan(reqKind, callId, reqId, fn) {
      const handle = { span: null, error: false };
      if (!tracer) return fn(handle);

      const name = SPAN_NAMES[reqKind] ?? `Kerberos.${reqKind}`;
      const attributes = buildRequestAttributes(reqKind, callId, reqId);

      if (hasMethod(tracer, 'startActiveSpan')) {
        let invoked = false;
        try {
          return tracer.startActiveSpan(name, { attributes }, (span) => {
            handle.span = span ?? null;
            invoked = true;
            return fn(handle);
          });
        } catch (error) {
          // Errors thrown by `fn` itself must propagate untouched; only a
          // tracer that broke before running the callback is swallowed.
          if (invoked) throw error;
          return fn(handle);
        }
      }

      try {
        handle.span = hasMethod(tracer, 'startSpan') ? tracer.startSpan(name, { attributes }) : null;
      } catch {
        handle.span = null;
      }
      return fn(handle);
    },

    /**
     * Records per-action decisions from the same `[{ req, result }]` input
     * shape the audit logger consumes. `IsAllowed` puts decision attributes on
     * the span itself; `CheckResources` emits one `kerberos.decision` event
     * per resource × action. The decisions counter fires even without a span
     * (meter-only configuration).
     */
    recordDecisions(handle, input, reqKind) {
      try {
        const span = handle?.span ?? null;
        let decisionCount = 0;

        if (span && includeIdentity && input[0]?.req.P.id) {
          span.setAttribute?.('kerberos.principal.id', input[0].req.P.id);
        }
        // A beforeRequest hook replaced the arguments: the span says the
        // decision was made on enriched input.
        if (span && input[0]?.req.enriched) span.setAttribute?.('kerberos.request.enriched', true);

        for (const { req, result } of input) {
          for (const action of req.actions) {
            const effect = normalizeEffect(result.effects.get(action));
            const actionMeta = result.meta?.actions?.[action];
            decisionCount += 1;

            decisionsCounter?.add(1, { 'kerberos.effect': effect, 'kerberos.resource.kind': req.R.kind });

            if (!span) continue;
            if (reqKind === 'IsAllowed') setDecisionAttributesOnSpan(span, req, action, effect, actionMeta);
            else span.addEvent?.('kerberos.decision', buildDecisionEventAttributes(req, action, effect, actionMeta));
          }
        }

        if (span && reqKind === 'CheckResources') {
          span.setAttribute?.('kerberos.resource.count', input.length);
          span.setAttribute?.('kerberos.decision.count', decisionCount);
        }
      } catch {
        // Telemetry must never break authorization.
        countSelfFailure();
      }
    },

    /**
     * Records the outcome of one `planResources` call: the plans counter (by
     * filter kind) plus span attributes describing the built filter — an
     * `ALWAYS_ALLOWED` plan (a fail-open query) must be distinguishable from
     * an `ALWAYS_DENIED` one in traces and metrics.
     */
    recordPlan(handle, plan) {
      try {
        plansCounter?.add(1, {
          'kerberos.plan.kind': plan.kind,
          'kerberos.resource.kind': plan.resourceKind,
        });
        const span = handle?.span ?? null;
        if (!span) return;
        span.setAttribute?.('kerberos.resource.kind', plan.resourceKind);
        span.setAttribute?.('kerberos.plan.kind', plan.kind);
        span.setAttribute?.('kerberos.plan.actions_count', plan.actionsCount);
        span.setAttribute?.('kerberos.plan.opaque_count', plan.opaqueCount);
        span.setAttribute?.('kerberos.plan.relation_count', plan.relationCount);
        if (plan.enriched) span.setAttribute?.('kerberos.request.enriched', true);
        if (includeIdentity && plan.principalId) span.setAttribute?.('kerberos.principal.id', plan.principalId);
      } catch {
        // Telemetry must never break authorization.
        countSelfFailure();
      }
    },

    /**
     * Marks the request as failed. Called from both catch branches — the
     * swallow-and-fallback path and the rethrow path — without altering the
     * logger-controlled error contract.
     */
    recordError(handle, error) {
      try {
        if (!handle) return;
        handle.error = true;
        handle.span?.recordException?.(error);
        handle.span?.setStatus?.({ code: SPAN_STATUS_ERROR, message: error?.message });
      } catch {
        // Telemetry must never break authorization.
        countSelfFailure();
      }
    },

    /**
     * Counts a cache lookup by outcome (`hit`/`miss`/`error`). The optional
     * `kind` (e.g. `'relation'` for ReBAC tuple documents) is added as an
     * attribute only when provided, so pre-existing policy series stay intact.
     * Not tied to a span — works in meter-only configurations too.
     */
    recordCacheRequest(result, kind) {
      try {
        const attributes = { 'kerberos.cache.result': result };
        if (kind) attributes['kerberos.cache.kind'] = kind;
        cacheRequestsCounter?.add(1, attributes);
      } catch {
        // Telemetry must never break authorization.
        countSelfFailure();
      }
    },

    /**
     * Counts one ReBAC relation resolution by outcome. Emitted at the public
     * boundary of the built-in resolver (`check` once, `list` once per name).
     */
    recordRelationCheck(allowed) {
      try {
        relationChecksCounter?.add(1, { 'kerberos.relations.result': allowed ? 'allow' : 'deny' });
      } catch {
        // Telemetry must never break authorization.
        countSelfFailure();
      }
    },

    /**
     * Annotates the request span with the engine-seam relation resolution
     * (count of distinct relations + duration). This is the seam-level
     * counterpart of the built-in resolver's own spans: it covers CUSTOM
     * resolvers too, so relation latency is attributable from the engine span
     * even when the resolver has no instrumentation of its own. Span
     * attributes only — the kerberos.relations.checks counter stays inside
     * the built-in resolver to avoid double counting.
     */
    recordRelationResolution(handle, resolution) {
      try {
        const span = handle?.span ?? null;
        if (!span) return;
        span.setAttribute?.('kerberos.relations.count', resolution.count);
        span.setAttribute?.('kerberos.relations.duration_ms', resolution.duration);
      } catch {
        // Telemetry must never break authorization.
        countSelfFailure();
      }
    },

    /**
     * Counts a swallowed observability-sink failure (`sink: 'logger'` from the
     * engine's guarded log helpers; the writer's own failures self-count as
     * `'telemetry'`). Keeps the swallow contract while making silent audit
     * loss visible on a dashboard.
     */
    recordObservabilityFailure(sink) {
      try {
        observabilityFailuresCounter?.add(1, { 'kerberos.observability.sink': sink });
      } catch {
        // Nothing left to do — the swallow contract still holds.
      }
    },

    /**
     * Records one awaited hook invocation on the kerberos.hooks.duration
     * histogram (by hook name). Hooks run INSIDE the request, so this is the
     * part of kerberos.request.duration a slow beforeRequest accounts for —
     * without it a hook regression looks like an engine regression.
     */
    recordHookDuration(hookName, duration) {
      try {
        hooksDurationHistogram?.record(duration, { 'kerberos.hook': hookName });
      } catch {
        // Telemetry must never break authorization.
        countSelfFailure();
      }
    },

    /**
     * Records the duration histogram and ends the span. Runs in the methods'
     * `finally` blocks, so spans are closed on success and failure alike.
     */
    endRequest(handle, reqKind, duration) {
      try {
        durationHistogram?.record(duration, { 'kerberos.req_kind': reqKind, error: handle?.error ?? false });
        handle?.span?.end?.();
      } catch {
        // Telemetry must never break authorization.
        countSelfFailure();
      }
    },
  };
}

module.exports = {
  createTelemetryWriter,
};
