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
    recordError() {},
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
  let durationHistogram = null;
  if (hasMethod(meter, 'createCounter') && hasMethod(meter, 'createHistogram')) {
    try {
      decisionsCounter = meter.createCounter('kerberos.decisions', {
        unit: '{decision}',
        description: 'Authorization decisions evaluated by Kerberos',
      });
      durationHistogram = meter.createHistogram('kerberos.request.duration', {
        unit: 'ms',
        description: 'Duration of Kerberos isAllowed/checkResources calls',
      });
    } catch {
      decisionsCounter = null;
      durationHistogram = null;
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
      }
    },
  };
}

module.exports = {
  createTelemetryWriter,
};
