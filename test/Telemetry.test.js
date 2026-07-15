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
    it('should set ERROR status and still return the fallback when logging is enabled', async () => {
      const { exporter, tracer } = createTraceSetup();
      const { reader, exporter: metricExporter, meter } = createMetricSetup();
      const kerberos = new Kerberos(policies, [], { logger: silentLogger, telemetry: { tracer, meter } });

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

    it('should set ERROR status and still end the span when logging is disabled (rethrow)', async () => {
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
