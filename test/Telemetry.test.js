const { describe, it } = require('node:test');
const assert = require('node:assert').strict;
const api = require('@opentelemetry/api');
const { BasicTracerProvider, SimpleSpanProcessor, InMemorySpanExporter } = require('@opentelemetry/sdk-trace-base');
const {
  MeterProvider,
  PeriodicExportingMetricReader,
  InMemoryMetricExporter,
  AggregationTemporality,
} = require('@opentelemetry/sdk-metrics');
const { AsyncHooksContextManager } = require('@opentelemetry/context-async-hooks');

const { Kerberos, Effect } = require('../src/index.js');

// Global context manager so startActiveSpan propagation works; global api
// providers back the `{ api }` mode tests. Instance-mode tests use per-test
// providers for isolation.
api.context.setGlobalContextManager(new AsyncHooksContextManager().enable());

const globalSpanExporter = new InMemorySpanExporter();
api.trace.setGlobalTracerProvider(
  new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(globalSpanExporter)] }),
);

const globalMetricExporter = new InMemoryMetricExporter(AggregationTemporality.CUMULATIVE);
const globalMetricReader = new PeriodicExportingMetricReader({
  exporter: globalMetricExporter,
  exportIntervalMillis: 3_600_000,
});
api.metrics.setGlobalMeterProvider(new MeterProvider({ readers: [globalMetricReader] }));

const policies = [
  {
    resourcePolicy: {
      version: 'default',
      resource: 'expense',
      rules: [{ name: 'user-view', actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
    },
  },
];

const principal = { id: 'sally', roles: ['USER'] };
const resource = { id: 'expense1', kind: 'expense' };

const silentLogger = { info() {}, debug() {}, error() {} };

function createTraceSetup() {
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] });
  return { exporter, tracer: provider.getTracer('test') };
}

function createMetricSetup() {
  const exporter = new InMemoryMetricExporter(AggregationTemporality.CUMULATIVE);
  const reader = new PeriodicExportingMetricReader({ exporter, exportIntervalMillis: 3_600_000 });
  const provider = new MeterProvider({ readers: [reader] });
  return { exporter, reader, meter: provider.getMeter('test') };
}

async function collectMetrics(reader, exporter) {
  await reader.forceFlush();
  const all = exporter.getMetrics();
  const latest = all[all.length - 1];
  const metrics = {};
  for (const scope of latest.scopeMetrics) {
    for (const metric of scope.metrics) metrics[metric.descriptor.name] = metric;
  }
  return metrics;
}

describe('Telemetry', () => {
  describe('disabled path', () => {
    it('should behave identically without the telemetry option', async () => {
      const kerberos = new Kerberos(policies, []);
      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
      assert.equal(await kerberos.isAllowed({ principal, action: 'delete', resource }), false);
    });

    it('should ignore non-object telemetry values', async () => {
      const kerberos = new Kerberos(policies, [], { telemetry: true });
      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
    });

    it('should disable telemetry when neither tracer nor meter resolves', async () => {
      const kerberos = new Kerberos(policies, [], { telemetry: {} });
      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
    });
  });

  describe('isAllowed span (instance mode)', () => {
    it('should record a span with decision attributes', async () => {
      const { exporter, tracer } = createTraceSetup();
      const kerberos = new Kerberos(policies, [], { telemetry: { tracer } });

      const allowed = await kerberos.isAllowed({ reqId: 'req-1', principal, action: 'view', resource });
      assert.equal(allowed, true);

      const spans = exporter.getFinishedSpans();
      assert.equal(spans.length, 1);
      const [span] = spans;
      assert.equal(span.name, 'Kerberos.isAllowed');
      assert.equal(span.attributes['kerberos.req_kind'], 'IsAllowed');
      assert.equal(span.attributes['kerberos.req_id'], 'req-1');
      assert.ok(span.attributes['kerberos.call_id']);
      assert.equal(span.attributes['kerberos.resource.kind'], 'expense');
      assert.equal(span.attributes['kerberos.action'], 'view');
      assert.equal(span.attributes['kerberos.allowed'], true);
      assert.match(String(span.attributes['kerberos.matched_policy']), /resource\.expense/);
      assert.equal(span.attributes['kerberos.principal.id'], 'sally');
      assert.equal(span.attributes['kerberos.resource.id'], 'expense1');
      assert.equal(span.status.code, 0);
    });

    it('should mark denied decisions', async () => {
      const { exporter, tracer } = createTraceSetup();
      const kerberos = new Kerberos(policies, [], { telemetry: { tracer } });

      assert.equal(await kerberos.isAllowed({ principal, action: 'delete', resource }), false);

      const [span] = exporter.getFinishedSpans();
      assert.equal(span.attributes['kerberos.allowed'], false);
    });
  });

  describe('checkResources span (instance mode)', () => {
    it('should record one span with a decision event per resource × action', async () => {
      const { exporter, tracer } = createTraceSetup();
      const kerberos = new Kerberos(policies, [], { telemetry: { tracer } });

      await kerberos.checkResources({
        principal,
        resources: [
          { resource, actions: ['view', 'delete'] },
          { resource: { id: 'expense2', kind: 'expense' }, actions: ['view'] },
        ],
      });

      const spans = exporter.getFinishedSpans();
      assert.equal(spans.length, 1);
      const [span] = spans;
      assert.equal(span.name, 'Kerberos.checkResources');
      assert.equal(span.attributes['kerberos.resource.count'], 2);
      assert.equal(span.attributes['kerberos.decision.count'], 3);
      assert.equal(span.attributes['kerberos.principal.id'], 'sally');

      const events = span.events.filter((event) => event.name === 'kerberos.decision');
      assert.equal(events.length, 3);
      const viewEvent = events.find(
        (event) =>
          event.attributes['kerberos.action'] === 'view' && event.attributes['kerberos.resource.id'] === 'expense1',
      );
      assert.equal(viewEvent.attributes['kerberos.effect'], 'EFFECT_ALLOW');
      const deleteEvent = events.find((event) => event.attributes['kerberos.action'] === 'delete');
      assert.equal(deleteEvent.attributes['kerberos.effect'], 'EFFECT_DENY');
    });

    it('should normalize boolean effects when effectAsBoolean is set', async () => {
      const { exporter, tracer } = createTraceSetup();
      const kerberos = new Kerberos(policies, [], { telemetry: { tracer } });

      await kerberos.checkResources({ principal, resources: [{ resource, actions: ['view'] }] }, true);

      const [span] = exporter.getFinishedSpans();
      const [event] = span.events;
      assert.equal(event.attributes['kerberos.effect'], 'EFFECT_ALLOW');
    });
  });

  describe('error paths', () => {
    it("should set ERROR status and still return the fallback when onError is 'deny'", async () => {
      const { exporter, tracer } = createTraceSetup();
      const { reader, exporter: metricExporter, meter } = createMetricSetup();
      const kerberos = new Kerberos(policies, [], {
        logger: silentLogger,
        onError: 'deny',
        telemetry: { tracer, meter },
      });

      const result = await kerberos.isAllowed({});
      assert.equal(result, false);

      const [span] = exporter.getFinishedSpans();
      assert.equal(span.status.code, 2);
      assert.ok(span.events.some((event) => event.name === 'exception'));

      const metrics = await collectMetrics(reader, metricExporter);
      const durationPoint = metrics['kerberos.request.duration'].dataPoints.find(
        (point) => point.attributes.error === true,
      );
      assert.ok(durationPoint);
      assert.equal(durationPoint.attributes['kerberos.req_kind'], 'IsAllowed');
    });

    it("should set ERROR status and still end the span with the default onError: 'throw'", async () => {
      const { exporter, tracer } = createTraceSetup();
      const kerberos = new Kerberos(policies, [], { telemetry: { tracer } });

      await assert.rejects(() => kerberos.checkResources({}));

      const spans = exporter.getFinishedSpans();
      assert.equal(spans.length, 1);
      assert.equal(spans[0].status.code, 2);
    });
  });

  describe('context propagation', () => {
    it('should parent the Kerberos span under the active span and nest cache spans within', async () => {
      const { exporter, tracer } = createTraceSetup();
      const cache = {
        async get() {
          const span = tracer.startSpan('cache.get');
          span.end();
          return undefined;
        },
      };
      const kerberos = new Kerberos(policies, [], { telemetry: { tracer }, cache });

      await tracer.startActiveSpan('outer', async (outer) => {
        await kerberos.isAllowed({ principal, action: 'delete', resource: { id: 'r1', kind: 'unknown' } });
        outer.end();
      });

      const spans = exporter.getFinishedSpans();
      const outerSpan = spans.find((span) => span.name === 'outer');
      const kerberosSpan = spans.find((span) => span.name === 'Kerberos.isAllowed');
      const cacheSpan = spans.find((span) => span.name === 'cache.get');

      assert.equal(kerberosSpan.parentSpanContext?.spanId, outerSpan.spanContext().spanId);
      assert.equal(cacheSpan.parentSpanContext?.spanId, kerberosSpan.spanContext().spanId);
    });
  });

  describe('metrics', () => {
    it('should count decisions by effect and resource kind and record durations', async () => {
      const { reader, exporter, meter } = createMetricSetup();
      const kerberos = new Kerberos(policies, [], { telemetry: { meter } });

      await kerberos.isAllowed({ principal, action: 'view', resource });
      await kerberos.checkResources({ principal, resources: [{ resource, actions: ['view', 'delete'] }] });

      const metrics = await collectMetrics(reader, exporter);

      const decisionPoints = metrics['kerberos.decisions'].dataPoints;
      const allowPoint = decisionPoints.find((point) => point.attributes['kerberos.effect'] === 'EFFECT_ALLOW');
      const denyPoint = decisionPoints.find((point) => point.attributes['kerberos.effect'] === 'EFFECT_DENY');
      assert.equal(allowPoint.value, 2);
      assert.equal(denyPoint.value, 1);
      assert.equal(allowPoint.attributes['kerberos.resource.kind'], 'expense');

      const durationPoints = metrics['kerberos.request.duration'].dataPoints;
      const isAllowedPoint = durationPoints.find((point) => point.attributes['kerberos.req_kind'] === 'IsAllowed');
      const checkPoint = durationPoints.find((point) => point.attributes['kerberos.req_kind'] === 'CheckResources');
      assert.equal(isAllowedPoint.value.count, 1);
      assert.equal(checkPoint.value.count, 1);
      assert.equal(isAllowedPoint.attributes.error, false);
    });
  });

  describe('robustness', () => {
    it('should return correct results when every telemetry method throws', async () => {
      const telemetry = {
        tracer: {
          startActiveSpan() {
            throw new Error('broken tracer');
          },
          startSpan() {
            throw new Error('broken tracer');
          },
        },
        meter: {
          createCounter() {
            throw new Error('broken meter');
          },
          createHistogram() {
            throw new Error('broken meter');
          },
        },
      };
      const kerberos = new Kerberos(policies, [], { telemetry });

      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
      const response = await kerberos.checkResources({ principal, resources: [{ resource, actions: ['view'] }] });
      assert.equal(response.results[0].actions.view, 'EFFECT_ALLOW');
    });

    it('should propagate authorization errors through a working tracer untouched', async () => {
      const { tracer } = createTraceSetup();
      const kerberos = new Kerberos(policies, [], { telemetry: { tracer } });
      await assert.rejects(() => kerberos.isAllowed({}), TypeError);
    });

    it('should fall back to startSpan when the tracer lacks startActiveSpan', async () => {
      const ended = [];
      const tracer = {
        startSpan(name) {
          return {
            setAttribute() {},
            end() {
              ended.push(name);
            },
          };
        },
      };
      const kerberos = new Kerberos(policies, [], { telemetry: { tracer } });

      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
      assert.deepEqual(ended, ['Kerberos.isAllowed']);
    });
  });

  describe('identity attributes (PII)', () => {
    it('should omit principal and resource ids when includeIdentity is false', async () => {
      const { exporter, tracer } = createTraceSetup();
      const kerberos = new Kerberos(policies, [], { telemetry: { tracer, includeIdentity: false } });

      await kerberos.isAllowed({ principal, action: 'view', resource });
      await kerberos.checkResources({ principal, resources: [{ resource, actions: ['view'] }] });

      for (const span of exporter.getFinishedSpans()) {
        assert.equal('kerberos.principal.id' in span.attributes, false);
        assert.equal('kerberos.resource.id' in span.attributes, false);
        for (const event of span.events) {
          assert.equal('kerberos.resource.id' in (event.attributes ?? {}), false);
        }
      }
    });
  });

  describe('api mode', () => {
    it('should derive tracer and meter from the api module with the package instrumentation scope', async () => {
      globalSpanExporter.reset();
      const kerberos = new Kerberos(policies, [], { telemetry: { api } });

      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);

      const spans = globalSpanExporter.getFinishedSpans();
      assert.equal(spans.length, 1);
      assert.equal(spans[0].name, 'Kerberos.isAllowed');
      assert.equal(spans[0].instrumentationScope.name, '@alexify/kerberos');

      const metrics = await collectMetrics(globalMetricReader, globalMetricExporter);
      assert.ok(metrics['kerberos.decisions']);
      assert.ok(metrics['kerberos.request.duration']);
    });
  });

  describe('partial configurations', () => {
    it('should work tracer-only', async () => {
      const { exporter, tracer } = createTraceSetup();
      const kerberos = new Kerberos(policies, [], { telemetry: { tracer } });
      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
      assert.equal(exporter.getFinishedSpans().length, 1);
    });

    it('should work meter-only', async () => {
      const { reader, exporter, meter } = createMetricSetup();
      const kerberos = new Kerberos(policies, [], { telemetry: { meter } });
      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);

      const metrics = await collectMetrics(reader, exporter);
      assert.equal(metrics['kerberos.decisions'].dataPoints[0].value, 1);
    });
  });
});

describe('Telemetry writer-level contract', () => {
  const { createTelemetryWriter } = require('../src/telemetry.js');

  it('records cache requests with and without the kind attribute', async () => {
    const { exporter, reader, meter } = createMetricSetup();
    const writer = createTelemetryWriter({ meter });

    writer.recordCacheRequest('hit');
    writer.recordCacheRequest('miss', 'relation');
    writer.recordCacheRequest('error', 'relation');

    const metrics = await collectMetrics(reader, exporter);
    const points = metrics['kerberos.cache.requests'].dataPoints;
    const withoutKind = points.find((p) => p.attributes['kerberos.cache.result'] === 'hit');
    assert.equal(withoutKind.attributes['kerberos.cache.kind'], undefined);
    const withKind = points.find((p) => p.attributes['kerberos.cache.result'] === 'miss');
    assert.equal(withKind.attributes['kerberos.cache.kind'], 'relation');
  });

  it('records relation checks by outcome', async () => {
    const { exporter, reader, meter } = createMetricSetup();
    const writer = createTelemetryWriter({ meter });

    writer.recordRelationCheck(true);
    writer.recordRelationCheck(true);
    writer.recordRelationCheck(false);

    const metrics = await collectMetrics(reader, exporter);
    const points = metrics['kerberos.relations.checks'].dataPoints;
    const allow = points.find((p) => p.attributes['kerberos.relations.result'] === 'allow');
    const deny = points.find((p) => p.attributes['kerberos.relations.result'] === 'deny');
    assert.equal(allow.value, 2);
    assert.equal(deny.value, 1);
  });

  it('exposes no-op stubs on the disabled writer', () => {
    const disabled = createTelemetryWriter(null);
    assert.equal(disabled.enabled, false);
    assert.equal(disabled.recordCacheRequest('hit', 'relation'), undefined);
    assert.equal(disabled.recordRelationCheck(true), undefined);
  });

  it('emits kerberos.cache.requests from the engine cache path', async () => {
    const { exporter, reader, meter } = createMetricSetup();
    const store = new Map([
      [
        'resource:document:default:',
        {
          resourcePolicy: {
            version: 'default',
            resource: 'document',
            rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
          },
        },
      ],
    ]);
    const kerberos = new Kerberos([], [], { cache: store, telemetry: { meter } });

    assert.equal(
      await kerberos.isAllowed({ principal, action: 'view', resource: { id: 'doc1', kind: 'document' } }),
      true,
    );

    const metrics = await collectMetrics(reader, exporter);
    const points = metrics['kerberos.cache.requests'].dataPoints;
    const results = new Set();
    for (const point of points) {
      results.add(point.attributes['kerberos.cache.result']);
      // Engine (policy) reads carry NO kind attribute.
      assert.equal(point.attributes['kerberos.cache.kind'], undefined);
    }
    assert.ok(results.has('hit'));
    assert.ok(results.has('miss'));
  });
});

describe('Telemetry wave-2 observability', () => {
  it('counts swallowed logger failures on kerberos.observability.failures', async () => {
    const { exporter, reader, meter } = createMetricSetup();
    const throwingLogger = {
      info() {
        throw new Error('sink down');
      },
      debug() {
        throw new Error('sink down');
      },
      error() {
        throw new Error('sink down');
      },
    };

    const originalWarn = console.warn;
    console.warn = () => {};
    try {
      const kerberos = new Kerberos(policies, [], { logger: throwingLogger, telemetry: { meter } });
      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
    } finally {
      console.warn = originalWarn;
    }

    const metrics = await collectMetrics(reader, exporter);
    const points = metrics['kerberos.observability.failures'].dataPoints;
    assert.ok(points.length > 0);
    for (const point of points) {
      assert.equal(point.attributes['kerberos.observability.sink'], 'logger');
      assert.ok(point.value >= 1);
    }
  });

  it('counts swallowed hook and event-listener failures under their own sinks', async () => {
    const { exporter, reader, meter } = createMetricSetup();
    const originalWarn = console.warn;
    console.warn = () => {};
    try {
      const kerberos = new Kerberos(policies, [], {
        telemetry: { meter },
        hooks: {
          onError() {
            throw new Error('handler down');
          },
          beforeRequest() {
            throw new Error('veto');
          },
        },
        onError: 'deny',
      });
      kerberos.on('request:end', () => {
        throw new Error('listener down');
      });
      assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), false);
      await new Promise((resolve) => setImmediate(resolve));
    } finally {
      console.warn = originalWarn;
    }

    const metrics = await collectMetrics(reader, exporter);
    const sinks = metrics['kerberos.observability.failures'].dataPoints
      .map((point) => point.attributes['kerberos.observability.sink'])
      .sort();
    assert.deepEqual(sinks, ['events', 'hooks']);
  });

  it('records every awaited hook invocation on kerberos.hooks.duration (by hook name)', async () => {
    const { exporter, reader, meter } = createMetricSetup();
    const kerberos = new Kerberos(policies, [], {
      telemetry: { meter },
      hooks: {
        beforeRequest: async () => {
          await new Promise((resolve) => setTimeout(resolve, 2));
        },
        afterResource() {},
        onError() {},
      },
    });
    await kerberos.isAllowed({ principal, action: 'view', resource });
    await kerberos.checkResources({
      principal,
      resources: [
        { resource, actions: ['view'] },
        { resource, actions: ['edit'] },
      ],
    });

    const metrics = await collectMetrics(reader, exporter);
    const points = metrics['kerberos.hooks.duration'].dataPoints;
    const byHook = {};
    for (const point of points) byHook[point.attributes['kerberos.hook']] = point.value;
    assert.deepEqual(Object.keys(byHook).sort(), ['afterResource', 'beforeRequest']);
    assert.equal(byHook.beforeRequest.count, 2);
    assert.ok(byHook.beforeRequest.sum >= 2);
    assert.equal(byHook.afterResource.count, 3);
    // Hooks that were configured but never ran (onError) record nothing.
    assert.equal('onError' in byHook, false);
  });

  it('marks spans of enriched requests with kerberos.request.enriched', async () => {
    const { exporter, tracer } = createTraceSetup();
    const kerberos = new Kerberos(policies, [], {
      telemetry: { tracer },
      hooks: { beforeRequest: (ctx) => ({ ...ctx.args }) },
    });
    await kerberos.isAllowed({ principal, action: 'view', resource });
    await kerberos.planResources({ principal, resource: { kind: 'expense' }, action: 'view' });
    const spans = exporter.getFinishedSpans();
    assert.deepEqual(
      spans.map((span) => span.attributes['kerberos.request.enriched']),
      [true, true],
    );
  });

  it('keeps hooks and events working when every telemetry method throws', async () => {
    const telemetry = {
      tracer: {
        startActiveSpan() {
          throw new Error('broken tracer');
        },
      },
      meter: {
        createCounter() {
          throw new Error('broken meter');
        },
        createHistogram() {
          throw new Error('broken meter');
        },
      },
    };
    const seen = [];
    const kerberos = new Kerberos(policies, [], {
      telemetry,
      hooks: { beforeRequest: () => seen.push('hook') },
    });
    kerberos.on('decision', () => seen.push('event'));
    kerberos.on('request:end', () => {
      throw new Error('listener down');
    });
    assert.equal(await kerberos.isAllowed({ principal, action: 'view', resource }), true);
    assert.deepEqual(seen, ['hook', 'event']);
  });

  it('counts fail-closed batch denials on kerberos.decisions', async () => {
    const { exporter, reader, meter } = createMetricSetup();
    const throwingPolicy = {
      resourcePolicy: {
        version: 'default',
        resource: 'broken',
        rules: [
          {
            actions: ['view'],
            effect: Effect.Allow,
            roles: ['USER'],
            condition: {
              match: () => {
                throw new Error('boom');
              },
            },
          },
        ],
      },
    };
    const kerberos = new Kerberos([throwingPolicy], [], { telemetry: { meter } });

    const response = await kerberos.checkResources({
      principal,
      resources: [{ resource: { id: 'b1', kind: 'broken' }, actions: ['view'] }],
    });
    assert.equal(response.results[0].actions.view, Effect.Deny);

    const metrics = await collectMetrics(reader, exporter);
    const denyPoint = metrics['kerberos.decisions'].dataPoints.find(
      (point) => point.attributes['kerberos.effect'] === 'EFFECT_DENY',
    );
    // The error-shaped DENY is counted, not silently dropped from the stream.
    assert.ok(denyPoint);
    assert.ok(denyPoint.value >= 1);
  });

  it('annotates the request span with seam-level relation resolution (custom resolver)', async () => {
    const { exporter, tracer } = createTraceSetup();
    const relationPolicies = [
      {
        resourcePolicy: {
          version: 'default',
          resource: 'document',
          importDerivedRoles: ['doc_roles'],
          rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['VIEWER'] }],
        },
      },
    ];
    const derivedRoles = [{ name: 'doc_roles', definitions: [{ name: 'VIEWER', relation: 'viewer' }] }];
    // A custom resolver with zero instrumentation of its own.
    const kerberos = new Kerberos(relationPolicies, derivedRoles, {
      relations: { check: async () => true },
      telemetry: { tracer },
    });

    assert.equal(
      await kerberos.isAllowed({ principal, action: 'view', resource: { id: 'd1', kind: 'document' } }),
      true,
    );

    const spans = exporter.getFinishedSpans();
    const requestSpan = spans.find((span) => span.name === 'Kerberos.isAllowed');
    assert.equal(requestSpan.attributes['kerberos.relations.count'], 1);
    assert.ok(typeof requestSpan.attributes['kerberos.relations.duration_ms'] === 'number');
  });
});

describe('Relations span correlation (callId through the seam)', () => {
  it('stamps the engine kerberosCallId on resolver spans via opts.callId', async () => {
    const { RelationResolver } = require('../src/Relations/index.js');
    const { exporter, tracer } = createTraceSetup();
    const resolver = new RelationResolver({
      schema: {
        relationSchema: {
          definitions: {
            user: {},
            document: { relations: { viewer: ['user'] }, permissions: { view: { anyOf: ['viewer'] } } },
          },
        },
      },
      tuples: ['document:doc1#viewer@user:sally'],
      telemetry: { tracer },
    });

    // Standalone call with an explicit correlation id.
    await resolver.check(
      { resource: 'document:doc1', permission: 'view', subject: 'user:sally', context: null },
      {
        callId: 'call-corr-1',
      },
    );
    let spans = exporter.getFinishedSpans();
    assert.equal(spans[0].attributes['kerberos.call_id'], 'call-corr-1');
    exporter.reset();

    // Driven through the engine seam: the request's kerberosCallId arrives
    // in the resolver's span attributes automatically.
    const relationPolicies = [
      {
        resourcePolicy: {
          version: 'default',
          resource: 'document',
          importDerivedRoles: ['doc_roles'],
          rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['DOC_VIEWER'] }],
        },
      },
    ];
    const derivedRoles = [{ name: 'doc_roles', definitions: [{ name: 'DOC_VIEWER', relation: 'view' }] }];
    const kerberos = new Kerberos(relationPolicies, derivedRoles, {
      relations: resolver,
      getCallId: () => 'call-corr-2',
    });
    assert.equal(
      await kerberos.isAllowed({
        principal: { id: 'sally', roles: ['USER'] },
        action: 'view',
        resource: { id: 'doc1', kind: 'document' },
      }),
      true,
    );
    spans = exporter.getFinishedSpans();
    const resolverSpan = spans.find((span) => span.name.startsWith('Kerberos.relations.'));
    assert.equal(resolverSpan.attributes['kerberos.call_id'], 'call-corr-2');
  });
});
