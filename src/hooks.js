const { KerberosHookError } = require('./errors.js');
const { withTimeout } = require('./async.js');

/**
 * Lifecycle hooks — user callbacks configured up front via the `hooks` option
 * and AWAITED inside the request flow (unlike events, which are fire-and-
 * forget observability). Same delegation shape as the logger/telemetry
 * writers: a factory that validates once at construction and returns either a
 * no-op runner (`enabled: false`, so call sites skip every await) or a runner
 * whose methods apply the error contract:
 *
 * - `beforeRequest`, `beforeResource`, `afterResource` and a SUCCESS-path
 *   `afterRequest` throw `KerberosHookError` (the caller applies its `onError`
 *   semantics) — a hook vetoes by throwing;
 * - `afterRequest` after an already-failed request, `afterResource` after a
 *   failed resource evaluation (`afterResourceFailed`) and `onError` are
 *   swallowed through `onSwallowed(error, hookName)` so they can never mask
 *   the original failure.
 *
 * `beforeRequest` is the one hook whose return value matters: a non-undefined
 * value is a REPLACEMENT for the request arguments (enrichment) — the caller
 * re-validates it and evaluates the replacement. Every other return value is
 * ignored.
 *
 * `timeoutMs` (opt-in) bounds every hook invocation through `withTimeout`; a
 * timed-out hook fails as `KerberosHookError` with `timedOut: true` and then
 * follows the same throwing/swallowing rule as any other hook failure. The
 * abandoned hook keeps running — the timeout only unblocks the request.
 *
 * `now` + `onTiming(hookName, durationMs)` (both optional) report the wall
 * time of every invocation; the caller passes them only when telemetry is
 * enabled so the clock is never read otherwise.
 */

const ENGINE_HOOKS = Object.freeze(['beforeRequest', 'afterRequest', 'beforeResource', 'afterResource', 'onError']);

const RESOLVER_HOOKS = Object.freeze(['beforeRequest', 'afterRequest', 'onError']);

function createDisabledHookRunner() {
  return {
    enabled: false,
    hasResourceHooks: false,
    beforeRequest() {},
    afterRequest() {},
    beforeResource() {},
    afterResource() {},
    afterResourceFailed() {},
    onError() {},
  };
}

/**
 * @param {Record<string, Function> | null | undefined} hooks
 * @param {{
 *   allowed?: readonly string[],
 *   onSwallowed?: (error: unknown, hookName: string) => void,
 *   timeoutMs?: number,
 *   now?: (() => number) | null,
 *   onTiming?: (hookName: string, durationMs: number) => void,
 * }} [options]
 */
function createHookRunner(hooks, { allowed = ENGINE_HOOKS, onSwallowed, timeoutMs = 0, now = null, onTiming } = {}) {
  if (hooks === undefined || hooks === null) return createDisabledHookRunner();
  if (typeof hooks !== 'object' || Array.isArray(hooks)) {
    throw new TypeError('Invalid hooks option — expected an object of hook functions');
  }

  const resolved = {};
  let configured = false;
  for (const key of Object.keys(hooks)) {
    if (!allowed.includes(key)) {
      throw new TypeError(`Invalid hooks option — unknown hook "${key}" (expected one of ${allowed.join(', ')})`);
    }
    const hook = hooks[key];
    if (hook === undefined || hook === null) continue;
    if (typeof hook !== 'function') throw new TypeError(`Invalid hooks option — "${key}" must be a function`);
    resolved[key] = hook;
    configured = true;
  }
  if (!configured) return createDisabledHookRunner();

  const swallow = typeof onSwallowed === 'function' ? onSwallowed : () => {};
  const timing = typeof now === 'function' && typeof onTiming === 'function' ? onTiming : null;
  const clock = timing ? now : null;

  function wrap(error, name) {
    // A timeout is already the typed error (built by makeTimeoutError below).
    if (error instanceof KerberosHookError && error.hook === name && error.timedOut) return error;
    return new KerberosHookError(`The ${name} hook failed: ${error?.message ?? String(error)}`, {
      hook: name,
      cause: error,
    });
  }

  function makeTimeoutError(name) {
    return () =>
      new KerberosHookError(`The ${name} hook timed out after ${timeoutMs}ms`, { hook: name, timedOut: true });
  }

  // Invokes one hook: sync throws and rejections both surface as rejections,
  // the timeout (when configured) races the returned promise, and the
  // duration is reported when a clock was provided.
  async function invoke(hook, name, args) {
    const startedAt = clock ? clock() : 0;
    try {
      let pending = hook(...args);
      if (timeoutMs && pending !== null && typeof pending === 'object' && typeof pending.then === 'function') {
        pending = withTimeout(pending, timeoutMs, makeTimeoutError(name));
      }
      return await pending;
    } finally {
      if (timing) {
        try {
          timing(name, clock() - startedAt);
        } catch {
          // Timing is observability — never in the way of the hook contract.
        }
      }
    }
  }

  // Throwing variant: the failure becomes a typed, named error for the caller.
  async function run(hook, name, args) {
    if (!hook) return undefined;
    try {
      return await invoke(hook, name, args);
    } catch (error) {
      throw wrap(error, name);
    }
  }

  // Swallowing variant: the request already failed — report (the raw error;
  // a timeout is already the typed KerberosHookError), never mask.
  async function runSwallowed(hook, name, args) {
    if (!hook) return;
    try {
      await invoke(hook, name, args);
    } catch (error) {
      try {
        swallow(error, name);
      } catch {
        // The swallow path is best-effort by definition.
      }
    }
  }

  const {
    beforeRequest = null,
    afterRequest = null,
    beforeResource = null,
    afterResource = null,
    onError = null,
  } = resolved;

  return {
    enabled: true,
    hasResourceHooks: Boolean(beforeResource || afterResource),
    // Resolves to the hook's return value: `undefined` = no change, anything
    // else = replacement arguments (validated by the caller).
    beforeRequest: (ctx) => run(beforeRequest, 'beforeRequest', [ctx]),
    afterRequest: (ctx, summary) =>
      summary.success
        ? run(afterRequest, 'afterRequest', [ctx, summary]).then(noop)
        : runSwallowed(afterRequest, 'afterRequest', [ctx, summary]),
    beforeResource: (ctx, info) => run(beforeResource, 'beforeResource', [ctx, info]).then(noop),
    afterResource: (ctx, info, result) => run(afterResource, 'afterResource', [ctx, info, result]).then(noop),
    // The resource failed (evaluation error or a vetoing beforeResource):
    // afterResource still sees the fail-closed result, but its own failure is
    // swallowed — the resource's original error is what surfaces.
    afterResourceFailed: (ctx, info, result) => runSwallowed(afterResource, 'afterResource', [ctx, info, result]),
    onError: (error, ctx) => runSwallowed(onError, 'onError', [error, ctx]),
  };
}

function noop() {}

module.exports = { ENGINE_HOOKS, RESOLVER_HOOKS, createHookRunner };
