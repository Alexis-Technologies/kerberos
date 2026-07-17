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

module.exports = {
  KerberosCacheError,
  KerberosCodecError,
  KerberosValidationError,
};
