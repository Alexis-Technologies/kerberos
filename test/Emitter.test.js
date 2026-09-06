const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const { Emitter, createEventHub } = require('../src/events.js');

const tick = () => new Promise((resolve) => setImmediate(resolve));

describe('Emitter (metautil copy)', () => {
  it('calls listeners in registration order with the payload', async () => {
    const emitter = new Emitter();
    const seen = [];
    emitter.on('x', (value) => seen.push(['a', value]));
    emitter.on('x', (value) => seen.push(['b', value]));
    await emitter.emit('x', 42);
    assert.deepEqual(seen, [
      ['a', 42],
      ['b', 42],
    ]);
  });

  it('fires once-listeners exactly once and drops them', async () => {
    const emitter = new Emitter();
    let calls = 0;
    emitter.once('x', () => {
      calls += 1;
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
    await emitter.emit('x');
    assert.deepEqual(emitter.eventNames(), []);
  });

  it('snapshots the listener list per emit', async () => {
    const emitter = new Emitter();
    const seen = [];
    emitter.on('x', () => {
      seen.push('first');
      emitter.on('x', () => seen.push('added-during-emit'));
    });
    await emitter.emit('x');
    assert.deepEqual(seen, ['first']);
    await emitter.emit('x');
    assert.deepEqual(seen, ['first', 'first', 'added-during-emit']);
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

  it('resolves immediately when nothing listens', async () => {
    const emitter = new Emitter();
    assert.equal(await emitter.emit('nobody'), undefined);
  });

  it('keeps the original semantics for a bare "error" emit without listeners', () => {
    const emitter = new Emitter();
    assert.throws(() => emitter.emit('error', new Error('x')), /Unhandled error/);
  });

  it('settles every listener, then rejects with an AggregateError carrying each failure', async () => {
    const emitter = new Emitter();
    const seen = [];
    emitter.on('x', () => {
      throw new Error('sync boom');
    });
    emitter.on('x', async () => {
      await tick();
      throw new Error('async boom');
    });
    emitter.on('x', async () => {
      await tick();
      seen.push('third ran to completion');
    });
    await assert.rejects(
      () => emitter.emit('x'),
      (error) =>
        error instanceof AggregateError &&
        error.errors.map((reason) => reason.message).join(',') === 'sync boom,async boom' &&
        /2 listener\(s\) for "x" failed/.test(error.message),
    );
    assert.deepEqual(seen, ['third ran to completion']);
  });

  it('off removes one registration and ignores unknown listeners/events', () => {
    const emitter = new Emitter();
    const listener = () => {};
    emitter.on('x', listener);
    emitter.off('x', () => {});
    emitter.off('unknown', listener);
    assert.equal(emitter.listenerCount('x'), 1);
    emitter.off('x', listener);
    assert.equal(emitter.listenerCount('x'), 0);
    assert.deepEqual(emitter.eventNames(), []);
  });

  it('off without a listener drops the event; clear() drops everything', () => {
    const emitter = new Emitter();
    emitter.on('x', () => {});
    emitter.on('y', () => {});
    emitter.off('x');
    assert.deepEqual(emitter.eventNames(), ['y']);
    emitter.on('x', () => {});
    emitter.clear('x');
    assert.deepEqual(emitter.eventNames(), ['y']);
    emitter.clear();
    assert.deepEqual(emitter.eventNames(), []);
  });

  it('exposes listeners/listenerCount/eventNames/toPromise', async () => {
    const emitter = new Emitter();
    const listener = () => {};
    emitter.on('x', listener);
    assert.deepEqual(emitter.listeners('x'), [listener]);
    assert.deepEqual(emitter.listeners('nope'), []);
    assert.equal(emitter.listenerCount('nope'), 0);
    assert.deepEqual(emitter.eventNames(), ['x']);
    const pending = emitter.toPromise('ready');
    await emitter.emit('ready', 'go');
    assert.equal(await pending, 'go');
    assert.throws(() => emitter.listeners(), /Expected eventName/);
    assert.throws(() => emitter.listenerCount(), /Expected eventName/);
  });
});

describe('createEventHub', () => {
  it('wants() stays false (and cheap) until a listener is attached', () => {
    const hub = createEventHub({ onSwallowed() {} });
    assert.equal(hub.active, false);
    assert.equal(hub.wants('decision'), false);
    hub.on('decision', () => {});
    assert.equal(hub.active, true);
    assert.equal(hub.wants('decision'), true);
    assert.equal(hub.wants('plan'), false);
    assert.equal(hub.listenerCount('decision'), 1);
  });

  it('rejects non-function listeners on on/once/off', () => {
    const hub = createEventHub();
    for (const method of ['on', 'once', 'off']) {
      assert.throws(() => hub[method]('decision', 'nope'), TypeError);
      assert.throws(() => hub[method]('decision'), TypeError);
    }
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

  it('swallows a synchronous emit throw too', async () => {
    const swallowed = [];
    const hub = createEventHub({ onSwallowed: (error, name) => swallowed.push(`${name}:${error.message}`) });
    hub.emit('error', new Error('x'));
    assert.deepEqual(swallowed, ['error:Unhandled error']);
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
    hub.emit('error', new Error('x'));
    await tick();

    const silent = createEventHub();
    silent.on('x', () => {
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
});
