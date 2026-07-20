# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub Security Advisories](https://github.com/Alexis-Technologies/kerberos/security/advisories/new)
or by emailing the author (see `package.json`). Do not open public issues for
security reports. You should receive a response within a few days.

## Supported versions

Only the latest published `3.x` release receives security fixes.

## Threat model

Kerberos.js is an **in-process** authorization engine. Its trust boundaries are
deliberately different from a networked authorization server:

- **Policies are code.** In-memory policies contain live JavaScript functions
  (conditions, variables, outputs) that run with the privileges of your
  process. Loading a policy is equivalent to loading a module — author and
  review policies with the same care as application code. Kerberos does not
  sandbox in-memory policy functions.
- **Dynamic (cache-stored) policies are data.** Policies loaded through the
  `cache` option must be JSON. With the built-in safe codec
  (`codec: { jsep }`), `{ "$expr": "..." }` descriptors are evaluated by an
  **eval-free AST allowlist interpreter**: no `eval`, no `new Function`, no
  `fn.toString()`; identifiers resolve only against `{P, R, V, C}` and curated
  safe builtins; `__proto__` / `prototype` / `constructor` access is blocked at
  the interpreter level regardless of spelling; expression length, nesting
  depth and the AST cache size are bounded by default (configurable via
  `codec: { maxExprLength, maxDepth, maxCachedExprs }`).
- **A compromised policy store means compromised authorization decisions.**
  The codec prevents code execution and resource exhaustion from a hostile
  store, but an attacker who can write policies can still grant or deny
  permissions. Protect the store (Redis/Mongo/Postgres) accordingly and use
  the `serializePolicy` helper to validate documents before writing them.
- **Call IDs are correlation identifiers, not security tokens.** In insecure
  browser contexts (plain HTTP) where `crypto.randomUUID` is unavailable, IDs
  fall back to a `Math.random`-based pseudo UUID.
- **Relation tuples from a store are data.** The built-in ReBAC resolver
  (`@alexify/kerberos/relations`) applies the same model as dynamic policies:
  cached relation documents are plain JSON, entries not admitted by the
  compiled relation schema are skipped fail-closed, and recursion is bounded
  by a configurable `maxDepth`. **Data errors are never read as answers**: a
  corrupt document throws a typed `KerberosCodecError` and a caveat whose
  condition throws raises `KerberosRelationsError` (both propagate per the
  engine's `onError` semantics) — resolving them as "empty"/"not matched"
  would silently widen access in exclusion positions (`viewer − editor` with
  an unreadable editor document). A caveat that cleanly evaluates to `false`
  simply does not match. Caveat conditions authored as `{ "$expr": "..." }` go
  through the same eval-free codec interpreter (scoped to `{P, ctx}` roots).
  An attacker who can write tuples can still grant or deny relations — protect
  the store accordingly.
- **In-process ReBAC has no Zanzibar consistency.** There are no revision
  tokens (zookies) or per-request consistency levels: the staleness window for
  cache-backed tuples equals your cache-invalidation window, so a just-revoked
  relation may briefly still pass on another host (the "new enemy" scenario).
  If that window matters for your threat model, keep revocation-sensitive
  relationships in static tuples, shorten TTLs/invalidation latency, or use a
  centralized authorization service.
- **Query plans embed folded principal/constant values.** `planResources`
  partially evaluates policies against the fully-known principal, so the
  returned `filter` (and `meta.filterDebug`) contains **literal values derived
  from principal attributes, constants and variables** (e.g.
  `eq(request.resource.attr.owner, "<principal id>")`). Treat plans as output
  for trusted sinks — your database translator or backend — and do not forward
  raw plans or `filterDebug` strings to untrusted clients without reviewing
  what they disclose. Operands are guaranteed JSON-safe: values that JSON
  transport would corrupt (`undefined`, `NaN`/`Infinity`, `Date` objects,
  `BigInt`) are never emitted — such conditions degrade to the `opaque`
  operator instead.
- **Compiled `$expr` ASTs are deeply frozen.** Expression ASTs are cached and
  shared across every compiled closure of the same expression (and surfaced to
  the internal query planner). They are deep-frozen at parse time, so
  in-process code cannot mutate a cached AST to alter the behavior of other
  policies using the same expression.

## Philosophy: opt-in safety layers

Kerberos targets users who know what they are doing; safety layers are
explicit, composable opt-ins rather than built-in overhead:

- **Validation** is provided by the validation backend you pass (`z`, `ajv`,
  or `ajv` + `typebox`). Without a backend, policy shapes are accepted as-is
  for zero construction overhead — malformed policies then fail at evaluation
  time. If you load policies from anywhere you do not fully control, configure
  a validation backend.
- **Dynamic-policy safety** is provided by using `codec` together with
  `cache`. Passing `cache` without a codec hands cached values to policy
  constructors unmodified — do that only when you fully trust the store.
- **Failure semantics** are controlled by `onError` (`'throw'` by default;
  `'deny'` for fail-closed deployments). A throwing logger or telemetry
  backend can never affect authorization results — those integrations are
  internally guarded.
