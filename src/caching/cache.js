const { KerberosCacheError } = require('../errors.js');

const DEFAULT_RETRY_ATTEMPTS = 3;

function hasMethod(value, methodName) {
  return typeof value?.[methodName] === 'function';
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
 * idempotent, so retrying is always safe. After exhausting the attempts the
 * failure surfaces as a typed `KerberosCacheError`.
 *
 * @param {{ get: (key: string) => unknown } | false | null | undefined} cache
 * @param {{ attempts?: number } | null} [retry]  - retry policy; `attempts: 1` disables retrying
 * @returns {{ enabled: boolean, get: (key: string) => Promise<unknown> }}
 */
function createCacheReader(cache, retry) {
  if (!cache) return createDisabledCacheReader();
  if (typeof cache !== 'object' && typeof cache !== 'function') return createDisabledCacheReader();
  if (!hasMethod(cache, 'get')) return createDisabledCacheReader();

  const attempts = Math.max(1, retry?.attempts ?? DEFAULT_RETRY_ATTEMPTS);

  return {
    enabled: true,
    // Awaiting makes sync and async `get` implementations behave identically.
    async get(key) {
      let lastError;
      for (let attempt = 1; attempt <= attempts; attempt++) {
        try {
          return await cache.get(key);
        } catch (error) {
          lastError = error;
        }
      }
      throw new KerberosCacheError(`Cache get("${key}") failed after ${attempts} attempt(s): ${lastError?.message}`, {
        cause: lastError,
      });
    },
  };
}

module.exports = {
  createCacheReader,
};
