# Errors

All error classes are exported from the main entry. Evaluation-phase errors follow the [`onError`](/guide/configuration#options) option; `KerberosValidationError` always throws.

| Class | Thrown when |
| ----- | ----------- |
| `KerberosValidationError` | Malformed method arguments or request shapes (always propagates — a programming error, not a deny). |
| `KerberosCacheError` | A transient `cache.get` failure persists after the [`cacheRetry`](/guide/configuration#options) attempts. |
| `KerberosCodecError` | A cached policy/tuple document is corrupt or fails to deserialize (for policies it is logged and counts as a miss; for ReBAC tuple documents it throws — see [Dynamic tuples](/guide/relations-resolver#dynamic-tuples-cache-backed)). |
| `KerberosExprError` | A `{ $expr }` string uses a construct outside the [safe allowlist](/reference/safe-builtins), exceeds codec limits, or fails to parse. |
| `KerberosRelationsError` | The built-in ReBAC resolver hits `maxDepth`, a throwing caveat, or invalid relation data. |
