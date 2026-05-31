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
 * @param {{ get: (key: string) => unknown } | false | null | undefined} cache
 * @returns {{ enabled: boolean, get: (key: string) => Promise<unknown> }}
 */
function createCacheReader(cache) {
  if (!cache) return createDisabledCacheReader();
  if (typeof cache !== 'object' && typeof cache !== 'function') return createDisabledCacheReader();
  if (!hasMethod(cache, 'get')) return createDisabledCacheReader();

  return {
    enabled: true,
    // Awaiting makes sync and async `get` implementations behave identically.
    async get(key) {
      return cache.get(key);
    },
  };
}

module.exports = {
  createCacheReader,
};
