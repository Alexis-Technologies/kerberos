/**
 * Thrown when a cache backend fails while resolving a dynamic policy
 * (after exhausting the configured retry attempts).
 */
class KerberosCacheError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'KerberosCacheError';
  }
}

/**
 * Thrown when a cached policy document cannot be deserialized or constructed
 * (corrupt/malformed entry). Deterministic — never retried; the entry is
 * treated as a cache miss.
 */
class KerberosCodecError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'KerberosCodecError';
  }
}

/**
 * Thrown when request arguments fail validation. Always propagates to the
 * caller regardless of the `onError` option — a malformed request is a
 * programming error, not an authorization deny.
 */
class KerberosValidationError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'KerberosValidationError';
  }
}

/**
 * Thrown for ReBAC relation errors: invalid relation schemas (unknown
 * references, name collisions, malformed expressions — fail-fast at
 * construction) and runtime guard violations (exceeding `maxDepth`, missing
 * reverse-index contract).
 */
class KerberosRelationsError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'KerberosRelationsError';
  }
}

module.exports = {
  KerberosCacheError,
  KerberosCodecError,
  KerberosRelationsError,
  KerberosValidationError,
};
