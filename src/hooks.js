const { KerberosHookError } = require('./errors.js');

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
 * - `afterRequest` after an already-failed request and `onError` are swallowed
 *   through `onSwallowed(error, hookName)` so they can never mask the original
 *   failure (migronaut's `afterAll`/`onError` discipline).
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
    onError() {},
  };
}

/**
 * @param {Record<string, Function> | null | undefined} hooks
 * @param {{ allowed?: readonly string[], onSwallowed?: (error: unknown, hookName: string) => void }} [options]
 */
function createHookRunner(hooks, { allowed = ENGINE_HOOKS, onSwallowed } = {}) {
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

  // Throwing variant: the failure becomes a typed, named error for the caller.
  async function run(hook, name, args) {
    if (!hook) return;
    try {
      await hook(...args);
    } catch (error) {
      throw new KerberosHookError(`The ${name} hook failed: ${error?.message ?? String(error)}`, {
        hook: name,
        cause: error,
      });
    }
  }

  // Swallowing variant: the request already failed — report, never mask.
  async function runSwallowed(hook, name, args) {
    if (!hook) return;
    try {
      await hook(...args);
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
    beforeRequest: (ctx) => run(beforeRequest, 'beforeRequest', [ctx]),
    afterRequest: (ctx, summary) =>
      summary.success
        ? run(afterRequest, 'afterRequest', [ctx, summary])
        : runSwallowed(afterRequest, 'afterRequest', [ctx, summary]),
    beforeResource: (ctx, info) => run(beforeResource, 'beforeResource', [ctx, info]),
    afterResource: (ctx, info, result) => run(afterResource, 'afterResource', [ctx, info, result]),
    onError: (error, ctx) => runSwallowed(onError, 'onError', [error, ctx]),
  };
}

module.exports = { ENGINE_HOOKS, RESOLVER_HOOKS, createHookRunner };
