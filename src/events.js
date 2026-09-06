/**
 * Lifecycle events: a platform-neutral emitter plus the guarded hub the engine
 * and the relations resolver share.
 *
 * `Emitter` is a copy of metautil's `Emitter` (github.com/metarhia/metautil,
 * MIT) — deliberately NOT `node:events`: everything outside `src/runtime/`
 * must stay platform-neutral, and one class on both platforms means identical
 * listener semantics by construction. Deviations from the original, each with
 * its reason:
 *
 * - no duplicate-listener throw and no `maxListeners` throw — observability
 *   subscriptions must never blow up inside `on()` (Node only warns there);
 * - `emit` settles EVERY listener (`Promise.allSettled`) before rejecting, and
 *   rejects with an `AggregateError` carrying every failure — a synchronous
 *   throw becomes a rejection through the async wrapper, so each failing
 *   listener reaches the hub's swallow path, not just the first one;
 * - `EventIterator` / `EventIterable` / `toAsyncIterable` are not copied
 *   (bundle size; nothing in the package needs them).
 */
class Emitter {
  #events = new Map();

  emit(eventName, value) {
    const event = this.#events.get(eventName);
    if (!event) {
      if (eventName !== 'error') return Promise.resolve();
      throw new Error('Unhandled error');
    }
    const listeners = event.on.slice();
    const promises = listeners.map(async (fn) => fn(value));
    if (event.once.size > 0) {
      const len = event.on.length;
      const remaining = new Array(len);
      let index = 0;
      for (let i = 0; i < len; i++) {
        const listener = event.on[i];
        if (!event.once.has(listener)) remaining[index++] = listener;
      }
      if (index === 0) {
        this.#events.delete(eventName);
      } else {
        remaining.length = index;
        this.#events.set(eventName, { on: remaining, once: new Set() });
      }
    }
    return Promise.allSettled(promises).then((settled) => {
      const errors = [];
      for (const outcome of settled) {
        if (outcome.status === 'rejected') errors.push(outcome.reason);
      }
      if (errors.length) {
        throw new AggregateError(errors, `${errors.length} listener(s) for "${String(eventName)}" failed`);
      }
    });
  }

  #addListener(eventName, listener, once) {
    let event = this.#events.get(eventName);
    if (!event) {
      const on = [listener];
      event = { on, once: once ? new Set(on) : new Set() };
      this.#events.set(eventName, event);
    } else {
      event.on.push(listener);
      if (once) event.once.add(listener);
    }
  }

  on(eventName, listener) {
    this.#addListener(eventName, listener, false);
  }

  once(eventName, listener) {
    this.#addListener(eventName, listener, true);
  }

  off(eventName, listener) {
    if (!listener) {
      this.#events.delete(eventName);
      return;
    }
    const event = this.#events.get(eventName);
    if (!event) return;
    const index = event.on.indexOf(listener);
    if (index > -1) event.on.splice(index, 1);
    event.once.delete(listener);
    if (event.on.length === 0) this.#events.delete(eventName);
  }

  toPromise(eventName) {
    return new Promise((resolve) => {
      this.once(eventName, resolve);
    });
  }

  clear(eventName) {
    if (!eventName) {
      this.#events.clear();
      return;
    }
    this.#events.delete(eventName);
  }

  listeners(eventName) {
    if (!eventName) throw new Error('Expected eventName');
    const event = this.#events.get(eventName);
    return event ? event.on : [];
  }

  listenerCount(eventName) {
    if (!eventName) throw new Error('Expected eventName');
    const event = this.#events.get(eventName);
    return event ? event.on.length : 0;
  }

  eventNames() {
    return Array.from(this.#events.keys());
  }
}

function assertListener(listener) {
  if (typeof listener !== 'function') {
    throw new TypeError(`Invalid event listener — expected a function, got ${typeof listener}`);
  }
}

/**
 * Wraps an `Emitter` behind the contract the engine and the resolver rely on:
 *
 * - `wants(name)` is the hot-path gate — call sites build a payload ONLY when
 *   it returns true, so a request with no subscribers pays one boolean check;
 * - `emit(name, payload)` never throws and never leaves a rejection unhandled:
 *   every failing listener (sync throw or async rejection) is handed to
 *   `onSwallowed(error, eventName)` — events are observability, they can never
 *   affect a decision;
 * - `on`/`once`/`off` reject non-function listeners with a TypeError (Node
 *   parity), `removeAllListeners(name?)` maps to the emitter's `clear`.
 *
 * @param {{ onSwallowed?: (error: unknown, eventName: string) => void }} [options]
 */
function createEventHub({ onSwallowed } = {}) {
  const emitter = new Emitter();
  const swallow = typeof onSwallowed === 'function' ? onSwallowed : () => {};

  function report(error, eventName) {
    const reasons = error instanceof AggregateError ? error.errors : [error];
    for (const reason of reasons) {
      try {
        swallow(reason, eventName);
      } catch {
        // The swallow path is best-effort by definition.
      }
    }
  }

  const hub = {
    // Flipped by the first subscription and never reset: `wants()` short-
    // circuits on it before touching the emitter's Map.
    active: false,
    on(eventName, listener) {
      assertListener(listener);
      hub.active = true;
      emitter.on(eventName, listener);
    },
    once(eventName, listener) {
      assertListener(listener);
      hub.active = true;
      emitter.once(eventName, listener);
    },
    off(eventName, listener) {
      assertListener(listener);
      emitter.off(eventName, listener);
    },
    removeAllListeners(eventName) {
      emitter.clear(eventName);
    },
    listenerCount(eventName) {
      return emitter.listenerCount(eventName);
    },
    wants(eventName) {
      return hub.active && emitter.listenerCount(eventName) > 0;
    },
    emit(eventName, payload) {
      let pending;
      try {
        pending = emitter.emit(eventName, payload);
      } catch (error) {
        report(error, eventName);
        return;
      }
      pending.then(undefined, (error) => report(error, eventName));
    },
  };
  return hub;
}

module.exports = { Emitter, createEventHub };
