const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const { Writable } = require('node:stream');

const pino = require('pino');
const { z } = require('zod');

const { commonRolesPolicy, principalsPolicy, resourcesPolicy, expensePolicy } = require('./mocks/index.js');
const { Effect, Kerberos } = require('../src/index.js');

function createKerberosWithLogger(logger, options = {}) {
  return new Kerberos([expensePolicy], [commonRolesPolicy], {
    logger,
    getCallId: () => 'call-123',
    ...options,
  });
}

function withPatchedConsole(overrides, callback) {
  const originalConsole = {};

  for (const [methodName, replacement] of Object.entries(overrides)) {
    originalConsole[methodName] = console[methodName];
    console[methodName] = replacement;
  }

  return Promise.resolve()
    .then(callback)
    .finally(() => {
      for (const [methodName, originalMethod] of Object.entries(originalConsole)) {
        console[methodName] = originalMethod;
      }
    });
}

function createPinoCollector(level = 'info') {
  const lines = [];
  const destination = new Writable({
    write(chunk, _encoding, callback) {
      lines.push(chunk.toString());
      callback();
    },
  });

  const logger = pino({
    level,
    base: null,
    timestamp: false,
  }, destination);

  return {
    logger,
    async flush() {
      logger.flush?.();
      await new Promise((resolve) => setImmediate(resolve));
    },
    entries() {
      return lines
        .join('')
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line));
    },
  };
}

function splitLifecycleAndAuditEntries(entries) {
  return {
    lifecycleEntries: entries.filter((entry) => typeof entry.event === 'string'),
    auditEntries: entries.filter((entry) => typeof entry.event !== 'string'),
  };
}

describe('Kerberos logger support', () => {
  it('should preserve legacy table and json logging for logger: true', async () => {
    const events = {
      group: [],
      log: [],
      table: [],
      debug: [],
      groupEnd: 0,
    };

    const kerberos = createKerberosWithLogger(true);

    await withPatchedConsole({
      group: (...args) => events.group.push(args),
      log: (...args) => events.log.push(args),
      table: (...args) => events.table.push(args),
      debug: (...args) => events.debug.push(args),
      groupEnd: () => { events.groupEnd++; },
    }, async () => {
      const isAllowed = await kerberos.isAllowed({
        principal: principalsPolicy.sally,
        action: 'view',
        resource: resourcesPolicy.expense1,
      });

      assert.strictEqual(isAllowed, true);
    });

    assert.deepStrictEqual(events.group, [['Kerberos.js']]);
    assert.deepStrictEqual(events.log, [['Principal sally is ALLOWED to perform action view on resource expense1']]);
    assert.strictEqual(events.table.length, 1);
    assert.strictEqual(events.debug.length, 3);
    assert.strictEqual(events.groupEnd, 1);

    const [tableRows] = events.table[0];
    assert.strictEqual(Array.isArray(tableRows), true);
    assert.strictEqual(tableRows.length, 1);
    assert.strictEqual(tableRows[0]['Call ID'], 'call-123');
    assert.strictEqual(tableRows[0]['Request kind'], 'IsAllowed');
    assert.strictEqual(tableRows[0]['Principal ID'], 'sally');
    assert.strictEqual(tableRows[0]['Resource kind'], 'expense');
    assert.strictEqual(tableRows[0]['Resource ID'], 'expense1');
    assert.strictEqual(tableRows[0].Action, 'view');
    assert.strictEqual(tableRows[0].Effect, Effect.Allow);

    const [startEntry, startMessage] = events.debug[0];
    assert.strictEqual(startEntry.event, 'IsAllowed.start');
    assert.strictEqual(startEntry.callId, 'call-123');
    assert.strictEqual(startEntry.reqKind, 'IsAllowed');
    assert.strictEqual(startMessage, 'Kerberos.js IsAllowed start!');

    const [debugEntry, debugMessage] = events.debug[1];
    assert.strictEqual(debugMessage, 'Kerberos.js request log');
    assert.strictEqual(debugEntry.callId, 'call-123');
    assert.strictEqual(debugEntry.reqKind, 'IsAllowed');
    assert.strictEqual(debugEntry.principalId, 'sally');
    assert.strictEqual(debugEntry.resourceKind, 'expense');
    assert.strictEqual(debugEntry.resourceId, 'expense1');
    assert.strictEqual(debugEntry.action, 'view');
    assert.strictEqual(debugEntry.effect, Effect.Allow);
    assert.strictEqual(Array.isArray(debugEntry.outputs), true);
    assert.ok(typeof debugEntry.timestamp === 'string');

    const [finishEntry, finishMessage] = events.debug[2];
    assert.strictEqual(finishEntry.event, 'IsAllowed.finish');
    assert.strictEqual(finishEntry.callId, 'call-123');
    assert.strictEqual(finishEntry.reqKind, 'IsAllowed');
    assert.ok(typeof finishEntry.duration === 'number');
    assert.strictEqual(finishMessage, 'Kerberos.js IsAllowed finish!');
  });

  it('should support legacy custom console-like loggers', async () => {
    const events = {
      group: [],
      log: [],
      table: [],
      debug: [],
      error: [],
      groupEnd: 0,
    };

    const logger = {
      group: (...args) => events.group.push(args),
      log: (...args) => events.log.push(args),
      table: (...args) => events.table.push(args),
      debug: (...args) => events.debug.push(args),
      error: (...args) => events.error.push(args),
      groupEnd: () => { events.groupEnd++; },
    };

    const kerberos = createKerberosWithLogger(logger);

    const results = await kerberos.checkResources({
      reqId: 'req-42',
      principal: principalsPolicy.sally,
      resources: [
        {
          resource: resourcesPolicy.expense1,
          actions: ['view', 'delete'],
        },
      ],
      includeMeta: true,
    });

    assert.strictEqual(results.kerberosCallId, 'call-123');
    assert.strictEqual(events.group.length, 1);
    assert.strictEqual(events.log.length, 0);
    assert.strictEqual(events.table.length, 1);
    assert.strictEqual(events.debug.length, 4);
    assert.strictEqual(events.error.length, 0);
    assert.strictEqual(events.groupEnd, 1);

    const [firstDebugEntry] = events.debug[1];
    const [secondDebugEntry] = events.debug[2];
    const [tableRows] = events.table[0];
    assert.strictEqual(Array.isArray(tableRows), true);
    assert.strictEqual(tableRows.length, 2);
    assert.strictEqual(tableRows[0]['Request ID'], 'req-42');
    assert.strictEqual(Object.prototype.hasOwnProperty.call(tableRows[0], 'Call ID'), false);
    assert.strictEqual(tableRows[1]['Request ID'], 'req-42');
    assert.strictEqual(Object.prototype.hasOwnProperty.call(tableRows[1], 'Call ID'), false);
    assert.strictEqual(firstDebugEntry.reqId, 'req-42');
    assert.strictEqual(secondDebugEntry.reqId, 'req-42');
    assert.strictEqual(firstDebugEntry.action, 'view');
    assert.strictEqual(secondDebugEntry.action, 'delete');
    assert.strictEqual(events.debug[0][0].event, 'CheckResources.start');
    assert.strictEqual(events.debug[3][0].event, 'CheckResources.finish');
  });

  it('should emit structured audit entries with pino', async () => {
    const collector = createPinoCollector('debug');
    const kerberos = createKerberosWithLogger(collector.logger);

    const results = await kerberos.checkResources({
      reqId: 'req-42',
      principal: principalsPolicy.sally,
      resources: [
        {
          resource: resourcesPolicy.expense1,
          actions: ['view', 'delete'],
        },
      ],
      includeMeta: true,
    });

    assert.strictEqual(results.kerberosCallId, 'call-123');

    await collector.flush();

    const entries = collector.entries();
    const { lifecycleEntries, auditEntries } = splitLifecycleAndAuditEntries(entries);
    assert.strictEqual(lifecycleEntries.length, 2);
    assert.strictEqual(auditEntries.length, 2);

    assert.strictEqual(lifecycleEntries[0].level, 20);
    assert.strictEqual(lifecycleEntries[0].event, 'CheckResources.start');
    assert.strictEqual(lifecycleEntries[0].reqKind, 'CheckResources');
    assert.strictEqual(lifecycleEntries[0].msg, 'Kerberos.js CheckResources start!');
    assert.strictEqual(lifecycleEntries[1].level, 20);
    assert.strictEqual(lifecycleEntries[1].event, 'CheckResources.finish');
    assert.strictEqual(lifecycleEntries[1].reqKind, 'CheckResources');
    assert.ok(typeof lifecycleEntries[1].duration === 'number');
    assert.strictEqual(lifecycleEntries[1].msg, 'Kerberos.js CheckResources finish!');

    for (const entry of auditEntries) {
      assert.strictEqual(entry.level, 30);
      assert.strictEqual(entry.component, 'Kerberos.js');
      assert.strictEqual(entry.callId, 'call-123');
      assert.strictEqual(entry.reqId, 'req-42');
      assert.strictEqual(entry.reqKind, 'CheckResources');
      assert.strictEqual(entry.principalId, 'sally');
      assert.strictEqual(entry.resourceKind, 'expense');
      assert.strictEqual(entry.resourceId, 'expense1');
      assert.strictEqual(Array.isArray(entry.outputs), true);
      assert.ok(entry.meta);
      assert.strictEqual(entry.msg, 'Kerberos.js CheckResources audit log');
    }

    assert.strictEqual(auditEntries[0].action, 'view');
    assert.strictEqual(auditEntries[0].effect, Effect.Allow);
    assert.strictEqual(auditEntries[1].action, 'delete');
    assert.strictEqual(auditEntries[1].effect, Effect.Deny);
  });

  it('should use structured summaries for pino isAllowed logs', async () => {
    const collector = createPinoCollector('debug');
    const kerberos = createKerberosWithLogger(collector.logger);

    const isAllowed = await kerberos.isAllowed({
      principal: principalsPolicy.sally,
      action: 'view',
      resource: resourcesPolicy.expense1,
    });

    assert.strictEqual(isAllowed, true);

    await collector.flush();

    const entries = collector.entries();
    const { lifecycleEntries, auditEntries } = splitLifecycleAndAuditEntries(entries);
    assert.strictEqual(lifecycleEntries.length, 2);
    assert.strictEqual(auditEntries.length, 1);
    assert.strictEqual(lifecycleEntries[0].event, 'IsAllowed.start');
    assert.strictEqual(lifecycleEntries[0].reqKind, 'IsAllowed');
    assert.strictEqual(lifecycleEntries[0].msg, 'Kerberos.js IsAllowed start!');
    assert.strictEqual(lifecycleEntries[1].event, 'IsAllowed.finish');
    assert.strictEqual(lifecycleEntries[1].reqKind, 'IsAllowed');
    assert.ok(typeof lifecycleEntries[1].duration === 'number');
    assert.strictEqual(lifecycleEntries[1].msg, 'Kerberos.js IsAllowed finish!');
    assert.strictEqual(auditEntries[0].component, 'Kerberos.js');
    assert.strictEqual(auditEntries[0].callId, 'call-123');
    assert.strictEqual(auditEntries[0].reqKind, 'IsAllowed');
    assert.strictEqual(auditEntries[0].action, 'view');
    assert.strictEqual(auditEntries[0].effect, Effect.Allow);
    assert.strictEqual(auditEntries[0].msg, 'Kerberos.js authorization decision for sally on expense1');
  });

  it('should log structured method errors with pino and return fallback result', async () => {
    const collector = createPinoCollector('debug');
    const kerberos = createKerberosWithLogger(collector.logger, { z });

    const result = await kerberos.isAllowed({
      principal: principalsPolicy.sally,
      resource: resourcesPolicy.expense1,
    });

    assert.strictEqual(result, false);

    await collector.flush();

    const entries = collector.entries();
    const { lifecycleEntries, auditEntries } = splitLifecycleAndAuditEntries(entries);
    assert.strictEqual(auditEntries.length, 0);
    assert.strictEqual(lifecycleEntries.length, 3);

    assert.strictEqual(lifecycleEntries[0].event, 'IsAllowed.start');
    assert.strictEqual(lifecycleEntries[0].reqKind, 'IsAllowed');
    assert.strictEqual(lifecycleEntries[0].msg, 'Kerberos.js IsAllowed start!');

    assert.strictEqual(lifecycleEntries[1].level, 50);
    assert.strictEqual(lifecycleEntries[1].event, 'IsAllowed.error');
    assert.strictEqual(lifecycleEntries[1].reqKind, 'IsAllowed');
    assert.strictEqual(lifecycleEntries[1].callId, 'call-123');
    assert.ok(typeof lifecycleEntries[1].errorMessage === 'string');
    assert.ok(typeof lifecycleEntries[1].stack === 'string');
    assert.strictEqual(lifecycleEntries[1].msg, 'Kerberos.js IsAllowed error!');

    assert.strictEqual(lifecycleEntries[2].event, 'IsAllowed.finish');
    assert.strictEqual(lifecycleEntries[2].reqKind, 'IsAllowed');
    assert.ok(typeof lifecycleEntries[2].duration === 'number');
    assert.strictEqual(lifecycleEntries[2].msg, 'Kerberos.js IsAllowed finish!');
  });

  it('should rethrow method errors when logging is disabled', async () => {
    const kerberos = createKerberosWithLogger(false, { z });

    await assert.rejects(async () => {
      await kerberos.isAllowed({
        principal: principalsPolicy.sally,
        resource: resourcesPolicy.expense1,
      });
    });
  });
});
