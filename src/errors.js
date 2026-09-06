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

/**
 * Thrown when a user lifecycle hook (`hooks` option) throws. Carries the name
 * of the failing hook and the original error as `cause`. In the engine it
 * follows the `onError` option like any evaluation-phase error ('throw'
 * propagates, 'deny' fails closed); the relations resolver always propagates
 * it. Hooks that run on an already-failed request (`afterRequest` after a
 * failure, `onError`) are swallowed instead, so they can never mask the
 * original error.
 */
class KerberosHookError extends Error {
  constructor(message, options) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'KerberosHookError';
    this.hook = options?.hook ?? null;
  }
}

module.exports = {
  KerberosCacheError,
  KerberosCodecError,
  KerberosHookError,
  KerberosRelationsError,
  KerberosValidationError,
};
