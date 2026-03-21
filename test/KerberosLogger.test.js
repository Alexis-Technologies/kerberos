const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const { Writable } = require('node:stream');

const pino = require('pino');

const { commonRolesPolicy, principalsPolicy, resourcesPolicy, expensePolicy } = require('./mocks/index.js');
const { Effect, Kerberos } = require('../src/index.js');

function createKerberosWithLogger(logger) {
  return new Kerberos([expensePolicy], [commonRolesPolicy], {
    logger,
    getCallId: () => 'call-123',
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
    assert.strictEqual(events.debug.length, 1);
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

    const [debugEntry, debugMessage] = events.debug[0];
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
  });

  it('should support legacy custom console-like loggers', async () => {
    const events = {
      group: [],
      log: [],
      table: [],
      debug: [],
      groupEnd: 0,
    };

    const logger = {
      group: (...args) => events.group.push(args),
      log: (...args) => events.log.push(args),
      table: (...args) => events.table.push(args),
      debug: (...args) => events.debug.push(args),
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
    assert.strictEqual(events.debug.length, 2);
    assert.strictEqual(events.groupEnd, 1);

    const [firstDebugEntry] = events.debug[0];
    const [secondDebugEntry] = events.debug[1];
    assert.strictEqual(firstDebugEntry.reqId, 'req-42');
    assert.strictEqual(secondDebugEntry.reqId, 'req-42');
    assert.strictEqual(firstDebugEntry.action, 'view');
    assert.strictEqual(secondDebugEntry.action, 'delete');
  });

  it('should emit structured audit entries with pino', async () => {
    const collector = createPinoCollector();
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
    assert.strictEqual(entries.length, 2);

    for (const entry of entries) {
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

    assert.strictEqual(entries[0].action, 'view');
    assert.strictEqual(entries[0].effect, Effect.Allow);
    assert.strictEqual(entries[1].action, 'delete');
    assert.strictEqual(entries[1].effect, Effect.Deny);
  });

  it('should use structured summaries for pino isAllowed logs', async () => {
    const collector = createPinoCollector();
    const kerberos = createKerberosWithLogger(collector.logger);

    const isAllowed = await kerberos.isAllowed({
      principal: principalsPolicy.sally,
      action: 'view',
      resource: resourcesPolicy.expense1,
    });

    assert.strictEqual(isAllowed, true);

    await collector.flush();

    const entries = collector.entries();
    assert.strictEqual(entries.length, 1);
    assert.strictEqual(entries[0].component, 'Kerberos.js');
    assert.strictEqual(entries[0].callId, 'call-123');
    assert.strictEqual(entries[0].reqKind, 'IsAllowed');
    assert.strictEqual(entries[0].action, 'view');
    assert.strictEqual(entries[0].effect, Effect.Allow);
    assert.strictEqual(entries[0].msg, 'Kerberos.js authorization decision for sally on expense1');
  });
});
