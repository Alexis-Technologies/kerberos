const { KerberosCacheError } = require('../errors.js');
const { withTimeout } = require('../async.js');

const DEFAULT_RETRY_ATTEMPTS = 3;
// Immediate back-to-back retries defeat the mechanism's purpose (any real
// network blip outlasts them) and triple the read load on an overloaded
// backend at the worst moment — so retries are spaced by default: full-jitter
// exponential backoff (delay ∈ [0, delayMs × 2^(attempt-1)]).
const DEFAULT_RETRY_DELAY_MS = 25;

function hasMethod(value, methodName) {
  return typeof value?.[methodName] === 'function';
}

// A programming error thrown by a buggy cache adapter cannot be transient —
// retrying it only delays the failure and mislabels it as one.
function isDeterministicError(error) {
  return error instanceof TypeError || error instanceof SyntaxError;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createDisabledCacheReader() {
  return {
    enabled: false,
    async get() {
      return undefined;
    },
  };
}

/**
 * Wraps any cache solution that exposes a `get(key)` method (CacheLike) so the
 * runtime stays agnostic about the actual backend (keyv, cacheable,
 * cache-manager, ...). Storage, TTL and multi-host invalidation (CacheSync via
 * qified) are fully delegated to the provided cache; Kerberos only ever reads.
 *
 * Transient backend failures (network blips, timeouts) are retried: `get` is
 * idempotent, so retrying is always safe. Retries use full-jitter exponential
 * backoff (`delayMs`, `jitter`); deterministic adapter errors (TypeError,
 * SyntaxError) are never retried. With `timeoutMs` set, a read that neither
 * resolves nor rejects counts as a failed attempt — without it, hang
 * protection is entirely the backend's responsibility. After exhausting the
 * attempts the failure surfaces as a typed `KerberosCacheError`.
 *
 * @param {{ get: (key: string) => unknown } | false | null | undefined} cache
 * @param {{ attempts?: number, delayMs?: number, jitter?: boolean, timeoutMs?: number } | null} [retry]
 *   retry policy; `attempts: 1` disables retrying, `delayMs: 0` restores
 *   immediate retries, `timeoutMs` (off by default) bounds each read attempt
 * @returns {{ enabled: boolean, get: (key: string) => Promise<unknown> }}
 */
function createCacheReader(cache, retry) {
  if (!cache) return createDisabledCacheReader();
  if (typeof cache !== 'object' && typeof cache !== 'function') return createDisabledCacheReader();
  if (!hasMethod(cache, 'get')) return createDisabledCacheReader();

  const attempts = Math.max(1, retry?.attempts ?? DEFAULT_RETRY_ATTEMPTS);
  const delayMs = Math.max(0, retry?.delayMs ?? DEFAULT_RETRY_DELAY_MS);
  const jitter = retry?.jitter ?? true;
  const timeoutMs = retry?.timeoutMs ?? 0;

  return {
    enabled: true,
    async get(key) {
      let lastError;
      let attemptsMade = 0;
      for (let attempt = 1; attempt <= attempts; attempt++) {
        attemptsMade = attempt;
        try {
          // Awaiting makes sync and async `get` implementations behave
          // identically (sync throws land in the catch). The race wrapper is
          // only paid when a timeout is configured — the no-timeout hot path
          // stays a direct awaited call.
          if (!timeoutMs) return await cache.get(key);
          return await withTimeout(
            Promise.resolve().then(() => cache.get(key)),
            timeoutMs,
            () => new Error(`timed out after ${timeoutMs}ms`),
          );
        } catch (error) {
          lastError = error;
          if (isDeterministicError(error)) break;
          if (attempt < attempts && delayMs > 0) {
            const backoff = delayMs * 2 ** (attempt - 1);
            await sleep(jitter ? Math.random() * backoff : backoff);
          }
        }
      }
      throw new KerberosCacheError(
        `Cache get("${key}") failed after ${attemptsMade} attempt(s): ${lastError?.message}`,
        { cause: lastError },
      );
    },
  };
}

module.exports = {
  createCacheReader,
};
