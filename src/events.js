/**
 * Lifecycle events: a platform-neutral emitter plus the guarded hub the engine
 * and the relations resolver share.
 *
 * `Emitter` is the package's own minimal emitter — deliberately NOT
 * `node:events`: everything outside `src/runtime/` must stay platform-neutral,
 * and one class on both platforms means identical listener semantics by
 * construction. What it guarantees:
 *
 * - listeners run synchronously, in registration order, against a snapshot of
 *   the list (subscriptions made during an emission fire from the next one);
 * - `emit` never throws for a listener failure: every listener runs, sync
 *   throws and async rejections are collected, and the returned promise
 *   rejects with an `AggregateError` carrying each failure — so the hub's
 *   swallow path sees all of them, not just the first;
 * - synchronous listeners cost no promise: `emit` allocates only when a
 *   listener returns a thenable or throws (the `decision` event fires once per
 *   resource — the fast path matters);
 * - no duplicate-listener or max-listeners throw (subscribing is never a
 *   failure; the hub warns about leaks instead).
 */

const RESOLVED = Promise.resolve();

function aggregate(errors, eventName) {
  return new AggregateError(errors, `${errors.length} listener(s) for "${String(eventName)}" failed`);
}

class Emitter {
  #events = new Map();

  hasListeners() {
    return this.#events.size > 0;
  }

  emit(eventName, value) {
    const event = this.#events.get(eventName);
    if (!event) return RESOLVED;
    const len = event.on.length;
    // Snapshot: a listener that subscribes/unsubscribes during the emission
    // must not affect this pass. A single listener needs no copy — the loop
    // bound is captured, and the live array cannot shrink below it mid-call
    // in a way that matters (index 0 is read before any listener runs).
    const listeners = len === 1 ? event.on : event.on.slice();
    // Node parity: once-listeners are removed BEFORE they run, so a
    // re-entrant emission from inside one does not fire it again.
    if (event.once.size > 0) this.#dropOnceListeners(eventName, event, len);
    let errors = null;
    let pending = null;
    for (let i = 0; i < len; i++) {
      try {
        const result = listeners[i](value);
        if (result !== null && typeof result === 'object' && typeof result.then === 'function') {
          (pending ??= []).push(result);
        }
      } catch (error) {
        (errors ??= []).push(error);
      }
    }
    if (pending === null) {
      return errors === null ? RESOLVED : Promise.reject(aggregate(errors, eventName));
    }
    return Promise.allSettled(pending).then((settled) => {
      for (const outcome of settled) {
        if (outcome.status === 'rejected') (errors ??= []).push(outcome.reason);
      }
      if (errors !== null) throw aggregate(errors, eventName);
    });
  }

  #dropOnceListeners(eventName, event, len) {
    const remaining = [];
    for (let i = 0; i < len; i++) {
      const listener = event.on[i];
      if (!event.once.has(listener)) remaining.push(listener);
    }
    if (remaining.length === 0) this.#events.delete(eventName);
    else this.#events.set(eventName, { on: remaining, once: new Set() });
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
    const event = this.#events.get(eventName);
    if (!event) return;
    const index = event.on.indexOf(listener);
    if (index > -1) event.on.splice(index, 1);
    event.once.delete(listener);
    if (event.on.length === 0) this.#events.delete(eventName);
  }

  clear(eventName) {
    if (eventName === undefined) {
      this.#events.clear();
      return;
    }
    this.#events.delete(eventName);
  }

  listenerCount(eventName) {
    const event = this.#events.get(eventName);
    return event ? event.on.length : 0;
  }
}

// The event vocabularies — the hub rejects any other name with a TypeError
// (hook names get the same treatment in src/hooks.js), so a typo cannot
// register a listener that never fires.
const ENGINE_EVENTS = Object.freeze([
  'request:start',
  'request:end',
  'request:error',
  'decision',
  'plan',
  'relations:resolved',
  'cache:hit',
  'cache:miss',
  'cache:error',
]);

const RESOLVER_EVENTS = Object.freeze([
  'request:start',
  'request:end',
  'request:error',
  'relation:checked',
  'cache:hit',
  'cache:miss',
  'cache:error',
]);

const DEFAULT_MAX_LISTENERS = 10;

function assertListener(listener) {
  if (typeof listener !== 'function') {
    throw new TypeError(`Invalid event listener — expected a function, got ${typeof listener}`);
  }
}

/**
 * Wraps an `Emitter` behind the contract the engine and the resolver rely on:
 *
 * - `wants(name)` is the hot-path gate — call sites build a payload ONLY when
 *   it returns true, so a request with no subscribers pays one size check;
 * - `emit(name, payload)` never throws and never leaves a rejection unhandled:
 *   every failing listener (sync throw or async rejection) is handed to
 *   `onSwallowed(error, eventName)` — events are observability, they can never
 *   affect a decision;
 * - `on`/`once`/`off`/`listenerCount` reject unknown event names (when an
 *   `allowed` list is given) and non-function listeners with a TypeError;
 *   `removeAllListeners(name?)` maps to the emitter's `clear`;
 * - `maxListeners` (default 10, `0` disables) is leak detection, never a
 *   limit: the first subscription past it calls `onLeak(name, count, max)`
 *   once per event name — a per-request `on()` is the classic mistake.
 *
 * @param {{
 *   onSwallowed?: (error: unknown, eventName: string) => void,
 *   allowed?: readonly string[] | null,
 *   maxListeners?: number,
 *   onLeak?: (eventName: string, count: number, max: number) => void,
 * }} [options]
 */
function createEventHub({ onSwallowed, allowed = null, maxListeners = DEFAULT_MAX_LISTENERS, onLeak } = {}) {
  const emitter = new Emitter();
  const swallow = typeof onSwallowed === 'function' ? onSwallowed : () => {};
  const allowedSet = allowed ? new Set(allowed) : null;
  const leakWarned = new Set();

  function assertName(eventName) {
    if (allowedSet !== null && !allowedSet.has(eventName)) {
      throw new TypeError(
        `Invalid event name — unknown event "${String(eventName)}" (expected one of ${allowed.join(', ')})`,
      );
    }
  }

  function subscribe(eventName, listener, once) {
    assertName(eventName);
    assertListener(listener);
    if (maxListeners > 0 && !leakWarned.has(eventName)) {
      const count = emitter.listenerCount(eventName) + 1;
      if (count > maxListeners) {
        leakWarned.add(eventName);
        try {
          onLeak?.(eventName, count, maxListeners);
        } catch {
          // Leak reporting is best-effort.
        }
      }
    }
    if (once) emitter.once(eventName, listener);
    else emitter.on(eventName, listener);
  }

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
    // True while anything is subscribed — derived, so unsubscribing restores
    // the callers' fast paths.
    get active() {
      return emitter.hasListeners();
    },
    on(eventName, listener) {
      subscribe(eventName, listener, false);
    },
    once(eventName, listener) {
      subscribe(eventName, listener, true);
    },
    off(eventName, listener) {
      assertName(eventName);
      assertListener(listener);
      emitter.off(eventName, listener);
    },
    removeAllListeners(eventName) {
      if (eventName !== undefined) assertName(eventName);
      emitter.clear(eventName);
    },
    listenerCount(eventName) {
      assertName(eventName);
      return emitter.listenerCount(eventName);
    },
    wants(eventName) {
      return emitter.hasListeners() && emitter.listenerCount(eventName) > 0;
    },
    emit(eventName, payload) {
      const pending = emitter.emit(eventName, payload);
      if (pending === RESOLVED) return;
      pending.then(undefined, (error) => report(error, eventName));
    },
  };
  return hub;
}

module.exports = { DEFAULT_MAX_LISTENERS, ENGINE_EVENTS, Emitter, RESOLVER_EVENTS, createEventHub };
