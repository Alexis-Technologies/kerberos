const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const { DEFAULT_MAX_LISTENERS, ENGINE_EVENTS, Emitter, RESOLVER_EVENTS, createEventHub } = require('../src/events.js');

const tick = () => new Promise((resolve) => setImmediate(resolve));

describe('Emitter', () => {
  it('calls listeners synchronously, in registration order, with the payload', async () => {
    const emitter = new Emitter();
    const seen = [];
    emitter.on('x', (value) => seen.push(['a', value]));
    emitter.on('x', (value) => seen.push(['b', value]));
    const pending = emitter.emit('x', 42);
    // Synchronous: both ran before the returned promise was even awaited.
    assert.deepEqual(seen, [
      ['a', 42],
      ['b', 42],
    ]);
    assert.equal(await pending, undefined);
  });

  it('allocates no promise for synchronous listeners (the fast path)', () => {
    const emitter = new Emitter();
    emitter.on('x', () => {});
    emitter.on('x', () => 42);
    emitter.on('x', () => null);
    const first = emitter.emit('x');
    const second = emitter.emit('x');
    // The same shared, already-resolved promise comes back for every
    // all-sync emission — no per-emit allocation.
    assert.equal(first, second);
    assert.equal(emitter.emit('nobody'), first);
  });

  it('fires once-listeners exactly once, dropping them before they run (re-entrancy safe)', async () => {
    const emitter = new Emitter();
    let calls = 0;
    emitter.once('x', () => {
      calls += 1;
      // A re-entrant emission from inside the once-listener must not fire it again.
      emitter.emit('x');
    });
    emitter.on('x', () => {});
    await emitter.emit('x');
    await emitter.emit('x');
    assert.equal(calls, 1);
    assert.equal(emitter.listenerCount('x'), 1);
  });

  it('drops the event entirely when its only listener was a once-listener', async () => {
    const emitter = new Emitter();
    emitter.once('x', () => {});
    assert.equal(emitter.hasListeners(), true);
    await emitter.emit('x');
    assert.equal(emitter.hasListeners(), false);
    assert.equal(emitter.listenerCount('x'), 0);
  });

  it('snapshots the listener list per emit', async () => {
    const emitter = new Emitter();
    const seen = [];
    emitter.on('x', () => {
      seen.push('first');
      emitter.on('x', () => seen.push('added-during-emit'));
    });
    emitter.on('x', () => seen.push('second'));
    await emitter.emit('x');
    assert.deepEqual(seen, ['first', 'second']);
    await emitter.emit('x');
    assert.deepEqual(seen, ['first', 'second', 'first', 'second', 'added-during-emit']);
  });

  it('a single listener that unsubscribes itself during the emission still ran once', async () => {
    const emitter = new Emitter();
    let calls = 0;
    const listener = () => {
      calls += 1;
      emitter.off('x', listener);
    };
    emitter.on('x', listener);
    await emitter.emit('x');
    await emitter.emit('x');
    assert.equal(calls, 1);
  });

  it('allows duplicate registrations (Node parity — called once per registration)', async () => {
    const emitter = new Emitter();
    let calls = 0;
    const listener = () => {
      calls += 1;
    };
    emitter.on('x', listener);
    emitter.on('x', listener);
    await emitter.emit('x');
    assert.equal(calls, 2);
    emitter.off('x', listener);
    assert.equal(emitter.listenerCount('x'), 1);
  });

  it('collects sync throws without a microtask, and settles every async listener before rejecting', async () => {
    const emitter = new Emitter();
    emitter.on('x', () => {
      throw new Error('sync boom');
    });
    emitter.on('x', () => {
      throw new Error('sync boom 2');
    });
    await assert.rejects(
      () => emitter.emit('x'),
      (error) =>
        error instanceof AggregateError && error.errors.map((e) => e.message).join(',') === 'sync boom,sync boom 2',
    );

    const mixed = new Emitter();
    const seen = [];
    mixed.on('x', () => {
      throw new Error('sync boom');
    });
    mixed.on('x', async () => {
      await tick();
      throw new Error('async boom');
    });
    mixed.on('x', async () => {
      await tick();
      seen.push('third ran to completion');
    });
    await assert.rejects(
      () => mixed.emit('x'),
      (error) =>
        error instanceof AggregateError &&
        error.errors.map((reason) => reason.message).join(',') === 'sync boom,async boom' &&
        /2 listener\(s\) for "x" failed/.test(error.message),
    );
    assert.deepEqual(seen, ['third ran to completion']);
  });

  it('off removes one registration and ignores unknown listeners/events; clear() drops one or all', () => {
    const emitter = new Emitter();
    const listener = () => {};
    emitter.on('x', listener);
    emitter.off('x', () => {});
    emitter.off('unknown', listener);
    assert.equal(emitter.listenerCount('x'), 1);
    emitter.off('x', listener);
    assert.equal(emitter.listenerCount('x'), 0);
    assert.equal(emitter.hasListeners(), false);

    emitter.on('x', () => {});
    emitter.on('y', () => {});
    emitter.clear('x');
    assert.equal(emitter.listenerCount('x'), 0);
    assert.equal(emitter.listenerCount('y'), 1);
    emitter.clear();
    assert.equal(emitter.hasListeners(), false);
  });
});

describe('createEventHub', () => {
  it('wants() and active stay false (and cheap) until a listener is attached, and reset when it is removed', () => {
    const hub = createEventHub({ onSwallowed() {} });
    assert.equal(hub.active, false);
    assert.equal(hub.wants('decision'), false);
    const listener = () => {};
    hub.on('decision', listener);
    assert.equal(hub.active, true);
    assert.equal(hub.wants('decision'), true);
    assert.equal(hub.wants('plan'), false);
    assert.equal(hub.listenerCount('decision'), 1);
    hub.off('decision', listener);
    assert.equal(hub.active, false);
    hub.on('decision', listener);
    hub.removeAllListeners();
    assert.equal(hub.active, false);
  });

  it('rejects non-function listeners on on/once/off', () => {
    const hub = createEventHub();
    for (const method of ['on', 'once', 'off']) {
      assert.throws(() => hub[method]('decision', 'nope'), TypeError);
      assert.throws(() => hub[method]('decision'), TypeError);
    }
  });

  it('rejects unknown event names when an allowed list is configured (a typo must not register a dead listener)', () => {
    const hub = createEventHub({ allowed: ENGINE_EVENTS });
    const listener = () => {};
    for (const method of ['on', 'once', 'off']) {
      assert.throws(() => hub[method]('decison', listener), /unknown event "decison" \(expected one of request:start/);
    }
    assert.throws(() => hub.listenerCount('nope'), TypeError);
    assert.throws(() => hub.removeAllListeners('nope'), TypeError);
    hub.on('decision', listener);
    hub.removeAllListeners();
    // Without a list every name is accepted (the resolver passes its own).
    createEventHub().on('anything', listener);
    assert.deepEqual([...RESOLVER_EVENTS].includes('relation:checked'), true);
  });

  it('hands every listener failure (sync throw and async rejection) to onSwallowed', async () => {
    const swallowed = [];
    const hub = createEventHub({ onSwallowed: (error, name) => swallowed.push(`${name}:${error.message}`) });
    hub.on('decision', () => {
      throw new Error('sync');
    });
    hub.on('decision', async () => {
      throw new Error('async');
    });
    hub.on('decision', () => {});
    assert.equal(hub.emit('decision', {}), undefined);
    await tick();
    assert.deepEqual(swallowed, ['decision:sync', 'decision:async']);
  });

  it('survives a throwing onSwallowed and works without one', async () => {
    const hub = createEventHub({
      onSwallowed() {
        throw new Error('reporter down');
      },
    });
    hub.on('x', () => {
      throw new Error('boom');
    });
    hub.emit('x', {});
    await tick();

    const silent = createEventHub();
    silent.on('x', () => {
      throw new Error('boom');
    });
    silent.on('x', async () => {
      throw new Error('boom');
    });
    silent.emit('x', {});
    await tick();
  });

  it('once/off/removeAllListeners manage subscriptions', () => {
    const hub = createEventHub();
    const listener = () => {};
    hub.once('a', listener);
    hub.on('b', listener);
    hub.on('c', listener);
    hub.off('b', listener);
    assert.equal(hub.listenerCount('b'), 0);
    hub.removeAllListeners('a');
    assert.equal(hub.listenerCount('a'), 0);
    assert.equal(hub.listenerCount('c'), 1);
    hub.removeAllListeners();
    assert.equal(hub.listenerCount('c'), 0);
  });

  it('warns once per event name when the listener count passes maxListeners (default 10), never throws', () => {
    const leaks = [];
    const hub = createEventHub({ onLeak: (name, count, max) => leaks.push([name, count, max]) });
    assert.equal(DEFAULT_MAX_LISTENERS, 10);
    for (let i = 0; i < 12; i++) hub.on('decision', () => {});
    for (let i = 0; i < 12; i++) hub.once('plan', () => {});
    assert.deepEqual(leaks, [
      ['decision', 11, 10],
      ['plan', 11, 10],
    ]);
    assert.equal(hub.listenerCount('decision'), 12);

    const custom = createEventHub({ maxListeners: 2, onLeak: (name, count) => leaks.push([name, count]) });
    custom.on('x', () => {});
    custom.on('x', () => {});
    assert.equal(leaks.length, 2);
    custom.on('x', () => {});
    assert.deepEqual(leaks.at(-1), ['x', 3]);

    const off = createEventHub({ maxListeners: 0, onLeak: () => leaks.push('never') });
    for (let i = 0; i < 20; i++) off.on('x', () => {});
    assert.equal(leaks.length, 3);

    const broken = createEventHub({
      maxListeners: 1,
      onLeak() {
        throw new Error('reporter down');
      },
    });
    broken.on('x', () => {});
    broken.on('x', () => {});
    assert.equal(broken.listenerCount('x'), 2);
  });
});
