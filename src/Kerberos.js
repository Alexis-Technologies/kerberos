const { ResourcePolicy } = require('./ResourcePolicy/index.js');
const { PrincipalPolicy } = require('./PrincipalPolicy/index.js');
const { RolePolicy } = require('./RolePolicy/index.js');
const { DerivedRoles } = require('./DerivedRoles/index.js');
const { ALL_ACTIONS, DEFAULT_VERSION, Effect, JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('./schemas');
const { KerberosJsonSchemas, KerberosTypeBoxSchemas, KerberosZodSchemas } = require('./schemas/kerberos.js');
const { createLoggerWriter } = require('./logging.js');
const { createTelemetryWriter } = require('./telemetry.js');
const { createCacheReader } = require('./caching/cache.js');
const { KerberosCodecError, KerberosRelationsError, KerberosValidationError } = require('./errors.js');
const { createLimiter, settleAll, withTimeout } = require('./async.js');
const { createSafeExprCodec } = require('./caching/codec.js');
const { PlanKind, countLeaves, toDebugString, toFilter } = require('./planning/nodes.js');
const { buildResourcePlan } = require('./planning/planner.js');
const { createAjvAdapter, parseWithValidation, registerAjvKeywords } = require('./validation');
// Platform runtime: bundlers swap this for `./runtime/browser.js` via the
// package.json `browser` field map when targeting the browser.
const { generateCallId, getNow } = require('./runtime/node.js');

function createEmptyPolicyResult() {
  return { effects: new Map(), outputs: new Map(), meta: { actions: {}, effectiveDerivedRoles: [] } };
}

// Hard cap on scope depth. Each scope segment multiplies per-request work
// (scope-chain walk × policy sources × cache reads on misses), and the chain
// builder itself is quadratic in segment count — so an unbounded,
// caller-influenced scope is a request-amplification / CPU-exhaustion vector.
// Enforced here (not only in the validation schemas) so the default
// no-validation-backend configuration is covered too; far above any realistic
// scope hierarchy.
const MAX_SCOPE_SEGMENTS = 16;

/**
 * Main authorization entry point. Supports plain runtime use, Zod validation,
 * JSON Schema + Ajv validation and TypeBox + Ajv validation.
 */
class Kerberos {
  /**
   * Generates a request-scoped call identifier used in logs and responses.
   *
   * @returns {string}
   */
  static generateCallId() {
    return generateCallId();
  }

  /**
   * Normalizes request scopes so "." behaves like an empty base scope.
   *
   * @param {string | undefined} scope
   * @returns {string}
   */
  static normalizeScope(scope) {
    if (scope === '.') return '';
    return scope ?? '';
  }

  /**
   * Builds the scope traversal chain from the most specific to the base scope.
   *
   * Throws `KerberosValidationError` when the scope exceeds
   * `MAX_SCOPE_SEGMENTS` dot-segments — a malformed request, so it always
   * propagates regardless of the `onError` option.
   *
   * @param {string | undefined} scope
   * @returns {string[]}
   */
  static getScopeSearchChain(scope) {
    const normalizedScope = Kerberos.normalizeScope(scope);
    if (!normalizedScope) return [''];

    const segments = normalizedScope.split('.');
    if (segments.length > MAX_SCOPE_SEGMENTS) {
      throw new KerberosValidationError(
        `Scope exceeds the maximum depth of ${MAX_SCOPE_SEGMENTS} dot-segments (got ${segments.length})`,
      );
    }
    const searchChain = [];

    for (let i = segments.length; i > 0; i--) searchChain.push(segments.slice(0, i).join('.'));
    searchChain.push('');

    return searchChain;
  }

  static parsePolicy(policy, options = {}) {
    if (policy instanceof ResourcePolicy) {
      return parseWithValidation(policy, {
        ...options,
        schema: options.resourceSchema ?? options.schema,
        buildJson: () => KerberosJsonSchemas.buildResourcePolicyInstance(),
        buildTypeBox: (t) => KerberosTypeBoxSchemas.buildResourcePolicyInstance(t),
        buildZod: (z) => KerberosZodSchemas.buildResourcePolicyInstance(z),
      });
    }
    if (policy instanceof PrincipalPolicy) {
      return parseWithValidation(policy, {
        ...options,
        schema: options.principalSchema ?? options.schema,
        buildJson: () => KerberosJsonSchemas.buildPrincipalPolicyInstance(),
        buildTypeBox: (t) => KerberosTypeBoxSchemas.buildPrincipalPolicyInstance(t),
        buildZod: (z) => KerberosZodSchemas.buildPrincipalPolicyInstance(z),
      });
    }
    if (policy instanceof RolePolicy) {
      return parseWithValidation(policy, {
        ...options,
        schema: options.roleSchema ?? options.schema,
        buildJson: () => KerberosJsonSchemas.buildRolePolicyInstance(),
        buildTypeBox: (t) => KerberosTypeBoxSchemas.buildRolePolicyInstance(t),
        buildZod: (z) => KerberosZodSchemas.buildRolePolicyInstance(z),
      });
    }
    const { schema, resourceSchema, principalSchema, roleSchema, ...nestedOptions } = options;
    // Classify by an OWN property only: `in` walks the prototype chain, so a
    // prototype-injected `rolePolicy`/`principalPolicy` (e.g. from untrusted
    // cached/deserialized JSON) must not be allowed to steer which policy
    // constructor is chosen.
    if (policy && typeof policy === 'object' && Object.prototype.hasOwnProperty.call(policy, 'rolePolicy')) {
      return new RolePolicy(policy, nestedOptions);
    }
    if (policy && typeof policy === 'object' && Object.prototype.hasOwnProperty.call(policy, 'principalPolicy')) {
      return new PrincipalPolicy(policy, nestedOptions);
    }
    return new ResourcePolicy(policy, nestedOptions);
  }

  static parseDerivedRoles(roles, options = {}) {
    if (roles instanceof DerivedRoles) {
      return parseWithValidation(roles, {
        ...options,
        buildJson: () => KerberosJsonSchemas.buildDerivedRolesInstance(),
        buildTypeBox: (t) => KerberosTypeBoxSchemas.buildDerivedRolesInstance(t),
        buildZod: (z) => KerberosZodSchemas.buildDerivedRolesInstance(z),
      });
    }
    const { schema, ...nestedOptions } = options;
    return new DerivedRoles(roles, nestedOptions);
  }

  static parseRequest({ principal, resource, actions, reqId, callId, includeMeta }, options = {}) {
    return parseWithValidation(
      { principal, resource, P: principal, R: resource, actions, reqId, callId, includeMeta },
      {
        ...options,
        buildJson: () => JsonSchemas.buildRequest(),
        buildTypeBox: (t) => TypeBoxSchemas.buildRequest(t),
        buildZod: (z) => ZodSchemas.buildRequest(z),
      },
    );
  }

  /**
   * Parses `isAllowed` arguments using the configured validation backend.
   *
   * @param {unknown} args
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseIsAllowedArgs(args, options = {}) {
    return parseWithValidation(args, {
      ...options,
      buildJson: () => KerberosJsonSchemas.buildIsAllowedArgs(),
      buildTypeBox: (t) => KerberosTypeBoxSchemas.buildIsAllowedArgs(t),
      buildZod: (z) => KerberosZodSchemas.buildIsAllowedArgs(z),
    });
  }

  /**
   * Parses `checkResources` arguments using the configured validation backend.
   *
   * @param {unknown} args
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseCheckResourcesArgs(args, options = {}) {
    return parseWithValidation(args, {
      ...options,
      buildJson: () => KerberosJsonSchemas.buildCheckResourcesArgs(),
      buildTypeBox: (t) => KerberosTypeBoxSchemas.buildCheckResourcesArgs(t),
      buildZod: (z) => KerberosZodSchemas.buildCheckResourcesArgs(z),
    });
  }

  /**
   * Parses `planResources` arguments using the configured validation backend.
   *
   * @param {unknown} args
   * @param {object} [options]
   * @returns {unknown}
   */
  static parsePlanResourcesArgs(args, options = {}) {
    return parseWithValidation(args, {
      ...options,
      buildJson: () => KerberosJsonSchemas.buildPlanResourcesArgs(),
      buildTypeBox: (t) => KerberosTypeBoxSchemas.buildPlanResourcesArgs(t),
      buildZod: (z) => KerberosZodSchemas.buildPlanResourcesArgs(z),
    });
  }

  #resourcePolicies = new Map();

  #principalPolicies = new Map();

  #rolePolicies = new Map();

  #derivedRoles = new Map();

  #logger = createLoggerWriter(false);

  #telemetry = createTelemetryWriter(null);

  #cache = createCacheReader(null);

  /** @type {((json: unknown) => unknown) | null} */
  #codecDeserialize = null;

  #z = null;

  #ajv = null;

  #typebox = null;

  #resourcePolicyValidator = null;

  #principalPolicyValidator = null;

  #rolePolicyValidator = null;

  #derivedRolesValidator = null;

  #isAllowedArgsValidator = null;

  #checkResourcesArgsValidator = null;

  #planResourcesArgsValidator = null;

  #getCallId = null;

  #onError = 'throw';

  // `cacheRetry.onExhausted`: 'throw' (default, fail-closed) or 'miss' — after
  // the reader exhausts its retries, count the read as a cache miss so the
  // scope-chain walk continues to lower-precedence static sources instead of
  // turning a cache outage into a total authorization outage.
  #cacheOnExhausted = 'throw';

  // Prepended to every cache key (policies + derived roles) so multiple
  // tenants/environments can share one store without colliding — derived-roles
  // names are otherwise a single global namespace.
  #cacheKeyPrefix = '';

  // Optional bound on each `relations.check`/`relations.list` call; 0 = off
  // (hang protection is the resolver's responsibility then).
  #relationsTimeoutMs = 0;

  // Engine-level audit enrichment (`audit: { includeMeta: true }`): decision
  // tracing runs for EVERY request when a logger is attached, so audit entries
  // carry meta.resolution and the policy-miss reason regardless of the
  // caller's per-request includeMeta response flag. The RESPONSE stays gated
  // on the request flag — this only enriches what the audit sink sees.
  #auditIncludeMeta = false;

  #warnedObservabilityFailure = false;

  // Bounds the checkResources batch fan-out (one evaluation chain per
  // resource otherwise launches simultaneously). Infinity = historical
  // unbounded behavior.
  #maxConcurrency = Infinity;

  // Cross-request memo of built policy instances, keyed by the IDENTITY of the
  // raw cached value: backends with an in-memory layer (plain Map, cacheable's
  // L1) return a stable object reference until the document is replaced, so an
  // unchanged document skips deserialize+validate+construct entirely while
  // TTL/invalidation stays fully backend-owned (a new stored value is a new
  // reference, which naturally misses). Serializing backends (keyv's JSON
  // round-trip) return fresh objects per read and simply keep rebuilding.
  #builtFromCache = new WeakMap();

  // String-valued entries can't go in a WeakMap — bounded per-key memo
  // comparing the raw string instead.
  #builtFromCacheStrings = new Map();

  static #MAX_MEMOIZED_STRING_DOCS = 256;

  /** @type {{ check: Function, list?: Function } | null} */
  #relations = null;

  // Per-instance memo of scope search chains: requests repeatedly resolve the
  // same scopes, and rebuilding the chain does string split/join work 2+N
  // times per request (once per role). Bounded so unbounded caller-supplied
  // scopes cannot grow memory; beyond the cap chains are computed uncached.
  #scopeChains = new Map();

  static #MAX_CACHED_SCOPE_CHAINS = 1000;

  #getScopeChain(scope) {
    const normalized = Kerberos.normalizeScope(scope);
    const atCapacity = this.#scopeChains.size >= Kerberos.#MAX_CACHED_SCOPE_CHAINS;
    let chain = this.#scopeChains.get(normalized);
    if (!chain) {
      chain = Kerberos.getScopeSearchChain(normalized);
      // Evict the least-recently-used entry instead of refusing to insert —
      // the memo used to freeze on whichever tenants booted first, serving
      // every later tenant from the uncached path forever.
      if (atCapacity) this.#scopeChains.delete(this.#scopeChains.keys().next().value);
      this.#scopeChains.set(normalized, chain);
    } else if (atCapacity) {
      // LRU touch (Map insertion order) — only paid once the memo is full;
      // below capacity the order is irrelevant and the hot path stays a get.
      this.#scopeChains.delete(normalized);
      this.#scopeChains.set(normalized, chain);
    }
    return chain;
  }

  /**
   * @param {unknown[]} policies
   * @param {unknown[]} derivedRoles
   * @param {object} [options]
   */
  constructor(
    policies,
    derivedRoles,
    {
      logger,
      telemetry,
      audit,
      cache,
      cacheRetry,
      cacheKeyPrefix,
      codec,
      onError,
      relations,
      relationsTimeoutMs,
      maxConcurrency,
      z,
      ajv,
      typebox,
      getCallId,
    } = {
      logger: false,
      telemetry: null,
      audit: null,
      cache: null,
      cacheRetry: null,
      cacheKeyPrefix: '',
      codec: null,
      onError: 'throw',
      relations: null,
      relationsTimeoutMs: 0,
      maxConcurrency: null,
      z: null,
      ajv: null,
      typebox: null,
      getCallId: null,
    },
  ) {
    this.#getCallId = Kerberos.generateCallId;

    if (onError !== undefined && onError !== null && onError !== 'throw' && onError !== 'deny') {
      throw new TypeError(`Invalid onError option "${onError}" — expected 'throw' or 'deny'`);
    }
    this.#onError = onError ?? 'throw';

    const onExhausted = cacheRetry?.onExhausted;
    if (onExhausted !== undefined && onExhausted !== null && onExhausted !== 'throw' && onExhausted !== 'miss') {
      throw new TypeError(`Invalid cacheRetry.onExhausted option "${onExhausted}" — expected 'throw' or 'miss'`);
    }
    this.#cacheOnExhausted = onExhausted ?? 'throw';

    if (cacheKeyPrefix !== undefined && cacheKeyPrefix !== null && typeof cacheKeyPrefix !== 'string') {
      throw new TypeError('Invalid cacheKeyPrefix option — expected a string');
    }
    this.#cacheKeyPrefix = cacheKeyPrefix ?? '';

    if (relationsTimeoutMs !== undefined && relationsTimeoutMs !== null) {
      if (typeof relationsTimeoutMs !== 'number' || !Number.isFinite(relationsTimeoutMs) || relationsTimeoutMs < 0) {
        throw new TypeError('Invalid relationsTimeoutMs option — expected a non-negative finite number');
      }
      this.#relationsTimeoutMs = relationsTimeoutMs;
    }

    if (audit !== undefined && audit !== null) {
      if (typeof audit !== 'object') {
        throw new TypeError('Invalid audit option — expected an object like { includeMeta: true }');
      }
      this.#auditIncludeMeta = audit.includeMeta === true;
    }

    if (maxConcurrency !== undefined && maxConcurrency !== null) {
      if (typeof maxConcurrency !== 'number' || Number.isNaN(maxConcurrency) || maxConcurrency < 1) {
        throw new TypeError('Invalid maxConcurrency option — expected a number >= 1');
      }
      this.#maxConcurrency = maxConcurrency;
    }

    // ReBAC delegation seam: any object with `check` (and optionally `list`)
    // works — a SQL/ORM-backed resolver or the built-in Zanzibar-lite one from
    // `@alexify/kerberos/relations`.
    if (relations !== undefined && relations !== null) {
      if (typeof relations.check !== 'function') {
        throw new TypeError('Invalid relations option — expected an object with a check(args, options) method');
      }
      this.#relations = relations;
    }

    this.#ajv = ajv ?? null;
    this.#typebox = typebox ?? null;

    if (this.#ajv) registerAjvKeywords(this.#ajv);

    // Backend dispatch happens ONCE (priority mirrors resolveValidationAdapter:
    // Zod → TypeBox+Ajv → JSON Schema+Ajv), then every validator wires through
    // the same builder-name list — a new argument schema (like planResources'
    // in v3.1) is one line here instead of three hand-synced blocks, and
    // wiring a validator for only one backend is structurally impossible.
    let buildValidator = null;
    if (z) {
      this.#z = z;
      buildValidator = (builderName) => KerberosZodSchemas[builderName](z);
    } else if (this.#ajv && this.#typebox) {
      buildValidator = (builderName) => createAjvAdapter(this.#ajv, KerberosTypeBoxSchemas[builderName](this.#typebox));
    } else if (this.#ajv) {
      buildValidator = (builderName) => createAjvAdapter(this.#ajv, KerberosJsonSchemas[builderName]());
    }
    if (buildValidator) {
      this.#resourcePolicyValidator = buildValidator('buildResourcePolicyInstance');
      this.#principalPolicyValidator = buildValidator('buildPrincipalPolicyInstance');
      this.#rolePolicyValidator = buildValidator('buildRolePolicyInstance');
      this.#derivedRolesValidator = buildValidator('buildDerivedRolesInstance');
      this.#isAllowedArgsValidator = buildValidator('buildIsAllowedArgs');
      this.#checkResourcesArgsValidator = buildValidator('buildCheckResourcesArgs');
      this.#planResourcesArgsValidator = buildValidator('buildPlanResourcesArgs');
    }

    const { resourcePolicies, principalPolicies, rolePolicies } = this.#getPoliciesMaps(policies);
    this.#resourcePolicies = resourcePolicies;
    this.#principalPolicies = principalPolicies;
    this.#rolePolicies = rolePolicies;
    this.#derivedRoles = this.#getDerivedRolesMap(derivedRoles);

    this.#logger = createLoggerWriter(logger);
    this.#telemetry = createTelemetryWriter(telemetry);
    this.#cache = createCacheReader(cache, cacheRetry);

    if (codec?.deserialize) {
      this.#codecDeserialize = (value) => codec.deserialize(value);
    } else if (codec?.jsep) {
      const builtinCodec = createSafeExprCodec({
        jsep: codec.jsep,
        maxCachedExprs: codec.maxCachedExprs,
        maxExprLength: codec.maxExprLength,
        maxDepth: codec.maxDepth,
      });
      this.#codecDeserialize = (value) => builtinCodec.deserialize(value);
    }

    if (typeof getCallId === 'function') this.#getCallId = getCallId;
  }

  #policyOptions() {
    return { z: this.#z, ajv: this.#ajv, typebox: this.#typebox };
  }

  /**
   * Reads a JSON-safe document from the cache and rebuilds a runtime instance.
   * Returns null on miss so callers can fall through to the next scope/source.
   *
   * @param {string} key
   * @param {(shape: unknown) => unknown} build
   * @returns {Promise<unknown>}
   */
  // Guarded observability signals for cache lookups: a debug log entry plus
  // the kerberos.cache.requests counter with result hit/miss/error.
  #recordCacheResult(key, result) {
    this.#telemetry.recordCacheRequest(result);
    // Skip the timestamp + entry allocation when the logger is the disabled
    // no-op writer (the default): a cache-backed batch calls this once per
    // cache.get, so eager construction is pure waste. The telemetry counter
    // above stays — it is cheap and may be enabled independently.
    if (!this.#logger.enabled) return;
    try {
      this.#logger.debug(
        { timestamp: new Date().toISOString(), event: `Cache.${result}`, key },
        `Kerberos.js cache ${result} for ${key}`,
      );
    } catch (sinkError) {
      // Audit logging must never break authorization.
      this.#observabilityFailure(sinkError);
    }
  }

  async #resolveFromCache(key, build) {
    if (!this.#cache.enabled) return null;
    let value;
    try {
      // A transient backend failure surfaces here as KerberosCacheError (after
      // the reader's retry loop) and propagates per the `onError` semantics —
      // unless `cacheRetry.onExhausted: 'miss'` opts into degraded mode below.
      value = await this.#cache.get(key);
    } catch (error) {
      this.#recordCacheResult(key, 'error');
      if (this.#cacheOnExhausted === 'miss') {
        // Opt-in degraded mode: the exhausted read counts as a miss so
        // evaluation falls through to the remaining (static) sources. The
        // degradation stays visible via the 'error' cache metric above plus a
        // guarded error log entry.
        this.#logMethodError('CacheDegradedToMiss', null, null, error);
        return null;
      }
      throw error;
    }
    if (value === undefined || value === null) {
      this.#recordCacheResult(key, 'miss');
      return null;
    }

    // Identity-keyed rebuild skip: the same (key, raw value) pair yields the
    // same instance without re-running deserialize/validation/construction.
    // Keyed per cache key too — the same raw object under a DIFFERENT key
    // would be built with a different constructor.
    const isObjectValue = typeof value === 'object';
    if (isObjectValue) {
      const memo = this.#builtFromCache.get(value);
      if (memo && memo.key === key) {
        this.#recordCacheResult(key, 'hit');
        return memo.built;
      }
    } else if (typeof value === 'string') {
      const memo = this.#builtFromCacheStrings.get(key);
      if (memo && memo.raw === value) {
        this.#recordCacheResult(key, 'hit');
        return memo.built;
      }
    }

    try {
      const shape = this.#codecDeserialize ? this.#codecDeserialize(value) : value;
      const built = build(shape);
      this.#recordCacheResult(key, 'hit');
      if (isObjectValue) {
        this.#builtFromCache.set(value, { key, built });
      } else if (typeof value === 'string') {
        // Bounded: evict the oldest entry (Map insertion order) at capacity.
        if (this.#builtFromCacheStrings.size >= Kerberos.#MAX_MEMOIZED_STRING_DOCS) {
          this.#builtFromCacheStrings.delete(this.#builtFromCacheStrings.keys().next().value);
        }
        this.#builtFromCacheStrings.set(key, { raw: value, built });
      }
      return built;
    } catch (error) {
      // A corrupt/malformed entry is deterministic (retrying cannot help), so
      // it is logged and treated as a cache miss instead of failing the
      // request — the affected policy simply does not resolve.
      this.#recordCacheResult(key, 'error');
      this.#logMethodError(
        'CacheDeserialize',
        null,
        null,
        new KerberosCodecError(`Failed to deserialize cached policy for key "${key}": ${error.message}`, {
          cause: error,
        }),
      );
      return null;
    }
  }

  #getPoliciesMaps(policies) {
    const resourcePolicies = new Map();
    const principalPolicies = new Map();
    const rolePolicies = new Map();
    for (const policy of policies) {
      const handledPolicy = Kerberos.parsePolicy(policy, {
        resourceSchema: this.#resourcePolicyValidator,
        principalSchema: this.#principalPolicyValidator,
        roleSchema: this.#rolePolicyValidator,
        z: this.#z,
        ajv: this.#ajv,
        typebox: this.#typebox,
      });

      // Normalize the scope into the storage key so the documented base-scope
      // alias (`'.'` ≡ `''`) is reachable: lookups resolve via the normalized
      // scope chain, so an un-normalized `'.'` key would never be selected.
      // Duplicate keys throw: silently letting the last policy win could drop
      // a deny rule — a privilege-escalation hazard, not a convenience.
      if (handledPolicy instanceof PrincipalPolicy) {
        const key = `${handledPolicy.principal}.${handledPolicy.version}.${Kerberos.normalizeScope(handledPolicy.scope)}`;
        if (principalPolicies.has(key)) throw new Error(`Duplicate principal policy "${key}"`);
        principalPolicies.set(key, handledPolicy);
        continue;
      }

      if (handledPolicy instanceof RolePolicy) {
        const key = `${handledPolicy.role}.${handledPolicy.version}.${Kerberos.normalizeScope(handledPolicy.scope)}`;
        if (rolePolicies.has(key)) throw new Error(`Duplicate role policy "${key}"`);
        rolePolicies.set(key, handledPolicy);
        continue;
      }

      const key = `${handledPolicy.kind}.${handledPolicy.version}.${Kerberos.normalizeScope(handledPolicy.scope)}`;
      if (resourcePolicies.has(key)) throw new Error(`Duplicate resource policy "${key}"`);
      resourcePolicies.set(key, handledPolicy);
    }
    return { resourcePolicies, principalPolicies, rolePolicies };
  }

  #getDerivedRolesMap(roles) {
    const derivedRolesMap = new Map();
    if (!roles) return derivedRolesMap;
    for (const role of roles) {
      const handledRole = Kerberos.parseDerivedRoles(role, {
        schema: this.#derivedRolesValidator,
        z: this.#z,
        ajv: this.#ajv,
        typebox: this.#typebox,
      });
      if (derivedRolesMap.has(handledRole.name)) {
        throw new Error(`Duplicate derived roles definition "${handledRole.name}"`);
      }
      derivedRolesMap.set(handledRole.name, handledRole);
    }
    return derivedRolesMap;
  }

  /**
   * Resolves one derived-roles definition set by name: in-memory first, then
   * the cache fallback. Shared by runtime evaluation and query planning.
   */
  async #resolveDerivedRolesSetByName(name, lookups, trace) {
    const role = this.#derivedRoles.get(name);
    if (role) {
      trace?.push({ source: 'derivedRoles', name, matched: true });
      return role;
    }
    // Same per-call singleflight memo as policy lookups ('derivedRoles:' can
    // never collide with the 'principal'/'role'/'resource' source prefixes).
    const memoKey = `derivedRoles:${name}`;
    let promise = lookups?.get(memoKey);
    if (!promise) {
      promise = this.#resolveFromCache(
        `${this.#cacheKeyPrefix}derivedRoles:${name}`,
        (shape) => new DerivedRoles(shape, this.#policyOptions()),
      );
      lookups?.set(memoKey, promise);
    }
    const resolved = await promise;
    // Imports were the one cache-backed resolution step invisible to
    // meta.resolution: a vanished/corrupt derived-roles document silently
    // stops rules from matching, so the outcome must be traceable.
    trace?.push(
      resolved
        ? { source: 'derivedRoles', name, matched: true, origin: 'cache' }
        : { source: 'derivedRoles', name, matched: false },
    );
    return resolved;
  }

  // Returns active derived-role name → `parentRoles` (null when ungated), which
  // resource-policy conflict resolution needs to attribute a rule to the
  // principal roles it was written for.
  async #getImportedDerivedRoles(policy, req, relationsMemo, trace, lookups, otel) {
    const importedRoles = new Map();
    const relationCandidates = [];
    for (const name of policy.importDerivedRoles) {
      const role = await this.#resolveDerivedRolesSetByName(name, lookups, trace);
      if (!role) continue;
      const derivedRoles = role.getActivated(req);
      if (derivedRoles) {
        for (const [derivedRole, parentRoles] of derivedRoles) importedRoles.set(derivedRole, parentRoles);
      }
      for (const candidate of role.getRelationCandidates(req)) relationCandidates.push(candidate);
    }

    if (relationCandidates.length) {
      if (this.#relations) {
        const granted = await this.#resolveRelationCandidates(relationCandidates, req, relationsMemo, trace, otel);
        if (granted.length) {
          const parentRolesByName = new Map(relationCandidates.map((c) => [c.name, c.parentRoles]));
          for (const name of granted) importedRoles.set(name, parentRolesByName.get(name) ?? null);
        }
      } else if (trace) {
        // Relation-backed definitions without a configured `relations`
        // resolver can never activate — surface that in the decision trace
        // instead of denying silently.
        for (const candidate of relationCandidates) {
          trace.push({
            source: 'relations',
            name: candidate.name,
            relation: candidate.relation,
            matched: false,
            reason: 'no-relations-resolver',
          });
        }
      }
    }

    return importedRoles;
  }

  /**
   * Resolves relation-backed derived-role candidates through the configured
   * `relations` resolver: list-first (one batched call), falling back to
   * parallel `check` calls. The per-request `memo` is shared across every
   * resolution in the request (and across all resources of a batch), so a
   * resolver that honors it evaluates each subproblem once.
   */
  async #resolveRelationCandidates(candidates, req, memo, trace, otel) {
    // Seam-level visibility: with a CUSTOM resolver, relation latency was
    // previously unattributable from the request span — measure the whole
    // resolution and annotate the span (built-in-resolver metrics stay inside
    // the resolver itself to avoid double counting).
    const startedAt = this.#telemetry.enabled ? getNow() : 0;
    // Several derived roles may point at the same relation — resolve each
    // relation once.
    const relationNames = [];
    const seenRelations = new Set();
    for (const candidate of candidates) {
      if (seenRelations.has(candidate.relation)) continue;
      seenRelations.add(candidate.relation);
      relationNames.push(candidate.relation);
    }

    // With `relationsTimeoutMs` set, a resolver call that neither resolves nor
    // rejects fails as KerberosRelationsError instead of hanging authorization.
    const relationsTimeout = this.#relationsTimeoutMs;
    const relationsTimedOut = (op) =>
      new KerberosRelationsError(`relations.${op} timed out after ${relationsTimeout}ms`);

    let granted;
    if (typeof this.#relations.list === 'function') {
      const listed = await withTimeout(
        Promise.resolve().then(() =>
          // callId joins resolver-side spans/diagnostics to this decision.
          this.#relations.list(
            { principal: req.P, resource: req.R, relations: relationNames },
            { memo, callId: req.callId },
          ),
        ),
        relationsTimeout,
        () => relationsTimedOut('list'),
      );
      granted = listed instanceof Set ? listed : new Set(listed ?? []);
    } else {
      // Parallel checks; allSettled so one rejection never leaves siblings
      // unawaited. A failure still surfaces after all settle (per the onError
      // semantics) — a resolver error must not silently read as "not granted".
      const checks = [];
      for (const relation of relationNames) {
        checks.push(
          withTimeout(
            Promise.resolve().then(() =>
              this.#relations.check({ principal: req.P, resource: req.R, relation }, { memo, callId: req.callId }),
            ),
            relationsTimeout,
            () => relationsTimedOut('check'),
          ),
        );
      }
      const settled = await Promise.allSettled(checks);
      granted = new Set();
      let firstError = null;
      for (let i = 0; i < settled.length; i++) {
        if (settled[i].status === 'rejected') {
          if (!firstError) firstError = settled[i].reason;
          continue;
        }
        if (settled[i].value === true) granted.add(relationNames[i]);
      }
      if (firstError) throw firstError instanceof Error ? firstError : new Error(String(firstError));
    }

    if (this.#telemetry.enabled) {
      this.#telemetry.recordRelationResolution(otel, {
        count: relationNames.length,
        duration: getNow() - startedAt,
      });
    }

    const grantedRoles = [];
    for (const candidate of candidates) {
      const matched = granted.has(candidate.relation);
      trace?.push({ source: 'relations', name: candidate.name, relation: candidate.relation, matched });
      if (matched) grantedRoles.push(candidate.name);
    }
    return grantedRoles;
  }

  // Every logger call is guarded: a throwing user logger must never affect
  // authorization control flow (an ALLOW decision was previously flipped to
  // DENY when logger.write threw after the decision was computed). Mirrors
  // the swallow pattern used by the telemetry writer.
  // Wraps argument/request parsing so validation failures surface as typed
  // KerberosValidationError, which ALWAYS propagates to the caller regardless
  // of the `onError` option — a malformed request is a programming error, not
  // an authorization deny.
  #parseArgs(validator, label, args) {
    if (!validator) return args;
    try {
      return validator.parse(args);
    } catch (error) {
      if (error instanceof KerberosValidationError) throw error;
      throw new KerberosValidationError(`${label}: ${error.message}`, { cause: error });
    }
  }

  // Swallowed sink failures stay swallowed (the never-affect-authorization
  // contract) but must not be INVISIBLE: count them on the telemetry channel
  // (kerberos.observability.failures) and warn once per instance, so a
  // permanently-broken audit logger is discoverable before someone needs the
  // audit trail.
  #observabilityFailure(sinkError) {
    this.#telemetry.recordObservabilityFailure('logger');
    if (this.#warnedObservabilityFailure) return;
    this.#warnedObservabilityFailure = true;
    try {
      console.warn(
        `Kerberos.js: the audit logger threw and was swallowed (authorization is unaffected; further warnings suppressed): ${sinkError?.message}`,
      );
    } catch {
      // Even the warning is best-effort.
    }
  }

  #log(input, reqKind, callId) {
    if (!this.#logger.enabled) return;
    try {
      this.#logger.write(input, reqKind, callId);
    } catch (sinkError) {
      // Audit logging must never break authorization.
      this.#observabilityFailure(sinkError);
    }
  }

  #logMethodStart(reqKind, callId, reqId) {
    // Every public call hits this twice (start/finish) via #runRequest; build
    // the timestamp/entry only when a logger is actually attached. Mirrors
    // RelationResolver#logDebug's `if (!this.#log.enabled) return`.
    if (!this.#logger.enabled) return;
    try {
      this.#logger.debug(
        {
          callId,
          reqId,
          timestamp: new Date().toISOString(),
          reqKind,
          event: `${reqKind}.start`,
        },
        `Kerberos.js ${reqKind} start!`,
      );
    } catch (sinkError) {
      // Audit logging must never break authorization.
      this.#observabilityFailure(sinkError);
    }
  }

  #logMethodError(reqKind, callId, reqId, error) {
    if (!this.#logger.enabled) return;
    try {
      this.#logger.error(
        {
          callId,
          reqId,
          timestamp: new Date().toISOString(),
          reqKind,
          event: `${reqKind}.error`,
          errorName: error?.name,
          errorMessage: error?.message,
          stack: error?.stack,
        },
        `Kerberos.js ${reqKind} error!`,
      );
    } catch (sinkError) {
      // Audit logging must never break authorization.
      this.#observabilityFailure(sinkError);
    }
  }

  // Guarded plan-result audit entry — the decision-level counterpart of the
  // per-action audit logs, so it goes out at INFO level like them: an
  // ALWAYS_ALLOWED filter (a fail-open query) must survive a production
  // `level: 'info'` sink, not vanish with the lifecycle debug events.
  #logPlanResult(callId, reqId, resourceKind, filter, counts, actions) {
    if (!this.#logger.enabled) return;
    try {
      this.#logger.info(
        {
          callId,
          reqId,
          timestamp: new Date().toISOString(),
          reqKind: 'PlanResources',
          event: 'PlanResources.result',
          resourceKind,
          filterKind: filter.kind,
          actions,
          opaqueCount: counts.opaque,
          relationCount: counts.relation,
        },
        'Kerberos.js PlanResources result!',
      );
    } catch (sinkError) {
      // Audit logging must never break authorization.
      this.#observabilityFailure(sinkError);
    }
  }

  #logMethodFinish(reqKind, callId, reqId, duration) {
    if (!this.#logger.enabled) return;
    try {
      this.#logger.debug(
        {
          callId,
          reqId,
          timestamp: new Date().toISOString(),
          reqKind,
          event: `${reqKind}.finish`,
          duration,
        },
        `Kerberos.js ${reqKind} finish!`,
      );
    } catch (sinkError) {
      // Audit logging must never break authorization.
      this.#observabilityFailure(sinkError);
    }
  }

  /**
   * Unified policy resolver: walks the scope search chain over the in-memory
   * map first, then (on a full miss) over the cache. All three policy sources
   * differ only by map, cache key prefix, lookup id and constructor.
   *
   * When a `trace` array is provided (decision tracing, gated on
   * `includeMeta`), every resolution attempt is recorded with the scopes that
   * were searched and where the policy was found (or that it wasn't).
   *
   * When a `lookups` memo is provided (one per `checkResources` batch /
   * `planResources` call), the resolution PROMISE is memoized by
   * `source:id:version:scope` — the same singleflight pattern as the relations
   * memo — so a batch resolves each distinct policy once instead of once per
   * resource (with a remote cache that is the difference between O(resources ×
   * sources × scopes) and O(sources × scopes) backend reads). The trace entry
   * is stored with the result and replayed into every caller's trace buffer.
   * Single-shot `isAllowed` passes no memo and takes the allocation-free fast
   * path below — memo bookkeeping would be pure overhead there.
   */
  async #resolvePolicy(source, map, id, version, scope, Constructor, trace, lookups) {
    if (!lookups) {
      // Fast path: no memo bookkeeping, and — because `?.` short-circuits
      // argument evaluation — no entry objects at all unless tracing is on.
      const scopeSearchChain = this.#getScopeChain(scope);

      for (const searchScope of scopeSearchChain) {
        const policy = map.get(`${id}.${version}.${searchScope}`);
        if (policy) {
          trace?.push({ source, id, version, scopesSearched: scopeSearchChain, matchedScope: searchScope });
          return policy;
        }
      }

      if (this.#cache.enabled) {
        for (const searchScope of scopeSearchChain) {
          const policy = await this.#resolveFromCache(
            `${this.#cacheKeyPrefix}${source}:${id}:${version}:${searchScope}`,
            (shape) => new Constructor(shape, this.#policyOptions()),
          );
          if (policy) {
            trace?.push({
              source,
              id,
              version,
              scopesSearched: scopeSearchChain,
              matchedScope: searchScope,
              origin: 'cache',
            });
            return policy;
          }
        }
      }

      trace?.push({ source, id, version, scopesSearched: scopeSearchChain, matchedScope: null });
      return null;
    }

    const normalizedScope = Kerberos.normalizeScope(scope);
    const memoKey = `${source}:${id}:${version}:${normalizedScope}`;
    let promise = lookups.get(memoKey);
    if (!promise) {
      promise = this.#resolvePolicyUncached(source, map, id, version, normalizedScope, Constructor);
      lookups.set(memoKey, promise);
    }
    const { policy, entry } = await promise;
    trace?.push(entry);
    return policy;
  }

  async #resolvePolicyUncached(source, map, id, version, scope, Constructor) {
    const scopeSearchChain = this.#getScopeChain(scope);

    for (const searchScope of scopeSearchChain) {
      const policy = map.get(`${id}.${version}.${searchScope}`);
      if (policy) {
        return { policy, entry: { source, id, version, scopesSearched: scopeSearchChain, matchedScope: searchScope } };
      }
    }

    if (this.#cache.enabled) {
      for (const searchScope of scopeSearchChain) {
        const policy = await this.#resolveFromCache(
          `${this.#cacheKeyPrefix}${source}:${id}:${version}:${searchScope}`,
          (shape) => new Constructor(shape, this.#policyOptions()),
        );
        if (policy) {
          return {
            policy,
            entry: {
              source,
              id,
              version,
              scopesSearched: scopeSearchChain,
              matchedScope: searchScope,
              origin: 'cache',
            },
          };
        }
      }
    }

    return { policy: null, entry: { source, id, version, scopesSearched: scopeSearchChain, matchedScope: null } };
  }

  #getResourcePolicy(req, trace, lookups) {
    const version = req.R.policyVersion ?? DEFAULT_VERSION;
    return this.#resolvePolicy(
      'resource',
      this.#resourcePolicies,
      req.R.kind,
      version,
      req.R.scope,
      ResourcePolicy,
      trace,
      lookups,
    );
  }

  #getPrincipalPolicy(req, trace, lookups) {
    const version = req.P.policyVersion ?? DEFAULT_VERSION;
    return this.#resolvePolicy(
      'principal',
      this.#principalPolicies,
      req.P.id,
      version,
      req.P.scope,
      PrincipalPolicy,
      trace,
      lookups,
    );
  }

  #getRolePolicyByName(role, req, trace, lookups) {
    const version = req.P.policyVersion ?? DEFAULT_VERSION;
    return this.#resolvePolicy('role', this.#rolePolicies, role, version, req.P.scope, RolePolicy, trace, lookups);
  }

  async #getRolePolicies(req, trace, lookups) {
    const uniqueRoles = [];
    const seenRoles = new Set();
    for (const role of req.P.roles) {
      if (seenRoles.has(role)) continue;
      seenRoles.add(role);
      uniqueRoles.push(role);
    }

    // Role lookups have no short-circuit (every role's policy is needed
    // before evaluation starts), so on the cache path they resolve as one
    // settled wave instead of sequential round trips — the same rationale as
    // #planPolicySources' three-chain wave. Per-role trace buffers keep
    // meta.resolution deterministic regardless of completion order. The
    // in-memory path stays sequential (each lookup is already a sync Map hit).
    if (this.#cache.enabled && uniqueRoles.length > 1) {
      const traces = trace ? uniqueRoles.map(() => []) : null;
      const resolved = await settleAll(
        uniqueRoles.map((role, i) => this.#getRolePolicyByName(role, req, traces ? traces[i] : null, lookups)),
      );
      if (traces) for (const buffer of traces) for (const entry of buffer) trace.push(entry);
      const policies = [];
      for (const policy of resolved) if (policy) policies.push(policy);
      return policies;
    }

    const policies = [];
    for (const role of uniqueRoles) {
      const policy = await this.#getRolePolicyByName(role, req, trace, lookups);
      if (policy) policies.push(policy);
    }

    return policies;
  }

  async #evaluateRolePolicy(
    policy,
    req,
    memo = new Map(),
    stack = new Set(),
    actionsKey = req.actions.join(','),
    lookups = null,
  ) {
    const policyKey = `${policy.role}.${policy.version}.${policy.scope ?? ''}|${actionsKey}`;
    if (memo.has(policyKey)) return memo.get(policyKey);
    if (stack.has(policyKey)) throw new Error(`Circular role policy inheritance detected for role "${policy.role}"`);

    stack.add(policyKey);

    const result = policy.check(req);

    for (const parentRole of policy.parentRoles) {
      const parentPolicy = await this.#getRolePolicyByName(parentRole, req, null, lookups);
      if (!parentPolicy) continue;

      const parentResult = await this.#evaluateRolePolicy(parentPolicy, req, memo, stack, actionsKey, lookups);
      Kerberos.#applyParentRoleResult(result, parentResult, req);
    }

    stack.delete(policyKey);
    memo.set(policyKey, result);
    return result;
  }

  // parentRoles inheritance: a child's allowed action survives only when
  // every locally-defined parent also allows it. Shared by the async and sync
  // role evaluators so the semantics live in exactly one place.
  static #applyParentRoleResult(result, parentResult, req) {
    for (const [src, output] of parentResult.outputs.entries()) result.outputs.set(src, output);

    for (const action of req.actions) {
      if (!result.effects.has(action)) continue;
      if (result.effects.get(action) === Effect.Deny) continue;

      if (!parentResult.effects.has(action) || parentResult.effects.get(action) !== Effect.Allow) {
        result.effects.set(action, Effect.Deny);
        if (parentResult.meta.actions[action]) result.meta.actions[action] = parentResult.meta.actions[action];
      }
    }
  }

  // Deny-wins merge of one role policy's result into the accumulated role
  // layer. Shared by the async and sync role evaluators.
  // Union across role policies (Cerbos semantics): the principal may do what
  // ANY of its roles permits. A role that does not permit an action simply does
  // not contribute it — it cannot take it away from another role.
  static #mergeRoleResultInto(effects, outputs, actionsMeta, result, req) {
    for (const [src, output] of result.outputs.entries()) outputs.set(src, output);

    for (const action of req.actions) {
      if (!result.effects.has(action)) continue;

      if (result.effects.get(action) === Effect.Allow) {
        effects.set(action, Effect.Allow);
        if (result.meta.actions[action]) actionsMeta[action] = result.meta.actions[action];
        continue;
      }

      // Record the first refusal only so that `meta` explains a filtered action
      // when no other role ends up permitting it.
      if (!effects.has(action)) {
        effects.set(action, Effect.Deny);
        if (result.meta.actions[action]) actionsMeta[action] = result.meta.actions[action];
      }
    }
  }

  async #evaluateRolePolicies(req, trace, lookups) {
    const rolePolicies = await this.#getRolePolicies(req, trace, lookups);
    if (!rolePolicies.length) return { ...createEmptyPolicyResult(), hadPolicies: false };

    const effects = new Map();
    const outputs = new Map();
    const actionsMeta = {};
    const memo = new Map();
    const actionsKey = req.actions.join(',');

    for (const policy of rolePolicies) {
      const result = await this.#evaluateRolePolicy(policy, req, memo, new Set(), actionsKey, lookups);
      // A policy whose rules never target this resource kind yields no effects
      // and so contributes nothing to the union — the role permits NOTHING
      // here. Having a role policy restricts the role everywhere, not only for
      // the kinds the policy happens to mention.
      Kerberos.#mergeRoleResultInto(effects, outputs, actionsMeta, result, req);
    }

    // A role with NO role policy at all is unrestricted, so the union across
    // the principal's roles permits everything and the filter must not narrow.
    // Only when every role is constrained does the layer apply.
    if (rolePolicies.length < Kerberos.#uniqueRoleCount(req)) {
      return { ...createEmptyPolicyResult(), hadPolicies: false };
    }

    return {
      effects,
      outputs,
      meta: {
        actions: actionsMeta,
        effectiveDerivedRoles: [],
      },
      hadPolicies: true,
    };
  }

  static #uniqueRoleCount(req) {
    const seen = new Set();
    for (const role of req.P.roles) seen.add(role);
    return seen.size;
  }

  /**
   * Resolves the transitive parentRoles closure for the query planner: every
   * role reachable from the principal's role policies, mapped to its resolved
   * policy (or null). Parent lookups are untraced — runtime parity with
   * `#evaluateRolePolicy`, which resolves parents without a trace.
   */
  async #resolveRolePolicyClosure(rolePolicies, req, lookups) {
    const closure = new Map();
    let frontier = [];
    const queued = new Set();
    for (const policy of rolePolicies) {
      closure.set(policy.role, policy);
      for (const parentRole of policy.parentRoles) {
        if (!queued.has(parentRole)) {
          queued.add(parentRole);
          frontier.push(parentRole);
        }
      }
    }
    // Level-batched BFS (the RelationResolver #subjectClosure pattern): each
    // frontier resolves as one settled wave, so a 50-role closure over a
    // remote cache pays O(depth) round-trip waves instead of O(roles)
    // sequential ones. The closure map doubles as the visited set, so
    // parentRoles cycles terminate here and are reported by the planner.
    while (frontier.length) {
      const unresolved = frontier.filter((role) => !closure.has(role));
      if (!unresolved.length) break;
      const resolved = await settleAll(unresolved.map((role) => this.#getRolePolicyByName(role, req, null, lookups)));
      const next = [];
      for (let i = 0; i < unresolved.length; i++) {
        const policy = resolved[i] ?? null;
        closure.set(unresolved[i], policy);
        if (policy) {
          for (const parentRole of policy.parentRoles) {
            if (!closure.has(parentRole) && !queued.has(parentRole)) {
              queued.add(parentRole);
              next.push(parentRole);
            }
          }
        }
      }
      frontier = next;
    }
    return closure;
  }

  async #resolveDerivedRolesSets(policy, lookups, trace) {
    const sets = [];
    for (const name of policy.importDerivedRoles) {
      const set = await this.#resolveDerivedRolesSetByName(name, lookups, trace);
      if (set) sets.push(set);
    }
    return sets;
  }

  // The two dependent planning chains (roles → parent closure; resource →
  // derived-roles sets) — split out so #planPolicySources can run all three
  // sources as one concurrent allSettled wave.
  async #planRoleSources(req, trace, lookups) {
    const rolePolicies = await this.#getRolePolicies(req, trace, lookups);
    const rolePolicyClosure = await this.#resolveRolePolicyClosure(rolePolicies, req, lookups);
    return { rolePolicies, rolePolicyClosure };
  }

  async #planResourceSources(req, trace, lookups) {
    const resourcePolicy = await this.#getResourcePolicy(req, trace, lookups);
    const derivedRolesSets = resourcePolicy ? await this.#resolveDerivedRolesSets(resourcePolicy, lookups, trace) : [];
    return { resourcePolicy, derivedRolesSets };
  }

  /**
   * Resolves every policy source the planner needs (async, cache-aware); the
   * planner itself (`buildResourcePlan`) is pure and synchronous.
   *
   * The three independent chains (principal / role+closure / resource+derived
   * roles) resolve concurrently: in-memory lookups stay synchronous-fast, but
   * with a cache-backed store this turns up to three sequential round-trip
   * waves into one. `Promise.allSettled` follows the engine's parallelism
   * policy — every sibling settles, then the first rejection rethrows. Each
   * chain records into its own trace buffer, concatenated in the canonical
   * principal → roles → resource order, so `meta.resolution` stays
   * deterministic regardless of cache-read completion order.
   */
  async #planPolicySources(principal, resource, actions, trace, lookups) {
    const req = { principal, resource, P: principal, R: resource, actions };
    const principalTrace = trace ? [] : null;
    const roleTrace = trace ? [] : null;
    const resourceTrace = trace ? [] : null;

    const settled = await Promise.allSettled([
      this.#getPrincipalPolicy(req, principalTrace, lookups),
      this.#planRoleSources(req, roleTrace, lookups),
      this.#planResourceSources(req, resourceTrace, lookups),
    ]);

    if (trace) {
      for (const entry of principalTrace) trace.push(entry);
      for (const entry of roleTrace) trace.push(entry);
      for (const entry of resourceTrace) trace.push(entry);
    }

    for (const outcome of settled) {
      if (outcome.status === 'rejected') {
        throw outcome.reason instanceof Error ? outcome.reason : new Error(String(outcome.reason));
      }
    }

    const principalPolicy = settled[0].value;
    const { rolePolicies, rolePolicyClosure } = settled[1].value;
    const { resourcePolicy, derivedRolesSets } = settled[2].value;
    return { principalPolicy, rolePolicies, rolePolicyClosure, resourcePolicy, derivedRolesSets };
  }

  /**
   * Evaluates all policy sources for a request. Effects are always canonical
   * `EFFECT_ALLOW`/`EFFECT_DENY` strings — the `effectAsBoolean` response
   * format is applied at the response boundary by `checkResources`.
   *
   * When `req.includeMeta` is set, decision tracing is enabled: `meta` gains a
   * `resolution` array describing every policy lookup (scopes searched, where
   * a policy matched), and unresolved actions get a `reason`
   * (`'policy-miss'` — no policy produced a decision; policy-level checks add
   * `'rule-miss'` / `'condition-not-met'`).
   */
  async #evaluatePolicySources(req, relationsMemo, lookups, otel) {
    // Tracing runs for the response (includeMeta) OR for the audit sink
    // (audit: { includeMeta: true } + an attached logger) — the response
    // itself stays gated on the per-request flag at the call sites.
    const trace = req.includeMeta || (this.#auditIncludeMeta && this.#logger.enabled) ? [] : null;

    const principalPolicy = await this.#getPrincipalPolicy(req, trace, lookups);
    const principalResult = principalPolicy ? principalPolicy.check(req) : createEmptyPolicyResult();

    const unresolvedActions = [];
    for (const action of req.actions) {
      if (!principalResult.effects.has(action)) unresolvedActions.push(action);
    }
    let roleResult = createEmptyPolicyResult();
    let resourceResult = createEmptyPolicyResult();

    if (unresolvedActions.length) {
      const roleReq = unresolvedActions.length === req.actions.length ? req : { ...req, actions: unresolvedActions };
      roleResult = await this.#evaluateRolePolicies(roleReq, trace, lookups);
    }

    // The resource layer is consulted for every action the principal policy
    // left open — role policies narrow it, they never stand in for it.
    if (unresolvedActions.length) {
      const resourcePolicy = await this.#getResourcePolicy(req, trace, lookups);
      if (resourcePolicy) {
        const resourceReq =
          unresolvedActions.length === req.actions.length ? req : { ...req, actions: unresolvedActions };
        const importedDerivedRoles = await this.#getImportedDerivedRoles(
          resourcePolicy,
          req,
          relationsMemo,
          trace,
          lookups,
          otel,
        );
        resourceResult = resourcePolicy.check(resourceReq, importedDerivedRoles);
      }
    }

    return Kerberos.#mergeSourceResults(req, trace, principalResult, roleResult, resourceResult);
  }

  // Per-action precedence merge (principal > roles > resource > default DENY)
  // plus the response meta/outputs assembly. Shared by the async and sync
  // evaluation drivers so the layering semantics live in exactly one place.
  static #mergeSourceResults(req, trace, principalResult, roleResult, resourceResult) {
    const effects = new Map();
    const actionsMeta = {};
    for (const action of req.actions) {
      if (principalResult.effects.has(action)) {
        effects.set(action, principalResult.effects.get(action));
        if (principalResult.meta.actions[action]) actionsMeta[action] = principalResult.meta.actions[action];
        continue;
      }

      // Role policies are a narrowing filter over the resource layer, not a
      // layer that can grant on its own (Cerbos semantics: "a role policy
      // cannot grant access that the resource policy does not already allow").
      // The filter applies only when every principal role is constrained by an
      // applicable role policy — see #evaluateRolePolicies.
      const filteredOut = roleResult.hadPolicies && roleResult.effects.get(action) !== Effect.Allow;

      if (resourceResult.effects.has(action)) {
        const resourceEffect = resourceResult.effects.get(action);
        if (filteredOut && resourceEffect === Effect.Allow) {
          effects.set(action, Effect.Deny);
          actionsMeta[action] = roleResult.meta.actions[action] ?? { reason: 'rule-miss' };
        } else {
          effects.set(action, resourceEffect);
          if (resourceResult.meta.actions[action]) actionsMeta[action] = resourceResult.meta.actions[action];
        }
        continue;
      }

      // No policy source produced a decision for this action → default DENY.
      // With tracing on, record WHY: no applicable policy existed at all.
      effects.set(action, Effect.Deny);
      if (trace) actionsMeta[action] = { reason: 'policy-miss' };
    }

    const meta = {
      actions: actionsMeta,
      effectiveDerivedRoles: resourceResult.meta.effectiveDerivedRoles ?? [],
    };
    if (trace) meta.resolution = trace;

    return {
      effects,
      outputs: new Map([
        ...principalResult.outputs.entries(),
        ...roleResult.outputs.entries(),
        ...resourceResult.outputs.entries(),
      ]),
      meta,
    };
  }

  // -------------------------------------------------------------------------
  // Synchronous evaluation driver — used when NO cache and NO relations
  // resolver are configured (the zero-dependency in-memory baseline): every
  // lookup is a sync Map hit, so the interior skips promise allocation and
  // microtask hops entirely (~10 awaited frames per request otherwise). The
  // layering/merge semantics are NOT duplicated: both drivers share
  // #applyParentRoleResult / #mergeRoleResultInto / #mergeSourceResults, and
  // test/SyncAsyncParity.test.js pins driver equivalence end-to-end.
  // -------------------------------------------------------------------------

  #resolvePolicyFromMemory(source, map, id, version, scope, trace) {
    const scopeSearchChain = this.#getScopeChain(scope);

    for (const searchScope of scopeSearchChain) {
      const policy = map.get(`${id}.${version}.${searchScope}`);
      if (policy) {
        trace?.push({ source, id, version, scopesSearched: scopeSearchChain, matchedScope: searchScope });
        return policy;
      }
    }

    trace?.push({ source, id, version, scopesSearched: scopeSearchChain, matchedScope: null });
    return null;
  }

  #getRolePoliciesSync(req, trace) {
    const version = req.P.policyVersion ?? DEFAULT_VERSION;
    const policies = [];
    const seenRoles = new Set();
    for (const role of req.P.roles) {
      if (seenRoles.has(role)) continue;
      seenRoles.add(role);
      const policy = this.#resolvePolicyFromMemory('role', this.#rolePolicies, role, version, req.P.scope, trace);
      if (policy) policies.push(policy);
    }
    return policies;
  }

  #evaluateRolePolicySync(policy, req, memo, stack, actionsKey) {
    const policyKey = `${policy.role}.${policy.version}.${policy.scope ?? ''}|${actionsKey}`;
    if (memo.has(policyKey)) return memo.get(policyKey);
    if (stack.has(policyKey)) throw new Error(`Circular role policy inheritance detected for role "${policy.role}"`);

    stack.add(policyKey);

    const result = policy.check(req);
    const version = req.P.policyVersion ?? DEFAULT_VERSION;

    for (const parentRole of policy.parentRoles) {
      // Untraced, like the async evaluator's parent lookups.
      const parentPolicy = this.#resolvePolicyFromMemory(
        'role',
        this.#rolePolicies,
        parentRole,
        version,
        req.P.scope,
        null,
      );
      if (!parentPolicy) continue;

      const parentResult = this.#evaluateRolePolicySync(parentPolicy, req, memo, stack, actionsKey);
      Kerberos.#applyParentRoleResult(result, parentResult, req);
    }

    stack.delete(policyKey);
    memo.set(policyKey, result);
    return result;
  }

  #evaluateRolePoliciesSync(req, trace) {
    const rolePolicies = this.#getRolePoliciesSync(req, trace);
    if (!rolePolicies.length) return { ...createEmptyPolicyResult(), hadPolicies: false };

    const effects = new Map();
    const outputs = new Map();
    const actionsMeta = {};
    const memo = new Map();
    const actionsKey = req.actions.join(',');

    for (const policy of rolePolicies) {
      const result = this.#evaluateRolePolicySync(policy, req, memo, new Set(), actionsKey);
      Kerberos.#mergeRoleResultInto(effects, outputs, actionsMeta, result, req);
    }

    if (rolePolicies.length < Kerberos.#uniqueRoleCount(req)) {
      return { ...createEmptyPolicyResult(), hadPolicies: false };
    }

    return {
      effects,
      outputs,
      meta: {
        actions: actionsMeta,
        effectiveDerivedRoles: [],
      },
      hadPolicies: true,
    };
  }

  #getImportedDerivedRolesSync(policy, req, trace) {
    const importedRoles = new Map();
    const relationCandidates = [];
    for (const name of policy.importDerivedRoles) {
      const role = this.#derivedRoles.get(name);
      if (!role) {
        // Mirrors the async driver: an import that resolves nowhere (no cache
        // configured here) is traced as unmatched.
        trace?.push({ source: 'derivedRoles', name, matched: false });
        continue;
      }
      trace?.push({ source: 'derivedRoles', name, matched: true });
      const derivedRoles = role.getActivated(req);
      if (derivedRoles) {
        for (const [derivedRole, parentRoles] of derivedRoles) importedRoles.set(derivedRole, parentRoles);
      }
      for (const candidate of role.getRelationCandidates(req)) relationCandidates.push(candidate);
    }

    // The sync driver runs only when no `relations` resolver is configured —
    // relation-backed definitions can never activate; trace mirrors the async
    // no-resolver branch.
    if (relationCandidates.length && trace) {
      for (const candidate of relationCandidates) {
        trace.push({
          source: 'relations',
          name: candidate.name,
          relation: candidate.relation,
          matched: false,
          reason: 'no-relations-resolver',
        });
      }
    }

    return importedRoles;
  }

  #evaluatePolicySourcesSync(req) {
    const trace = req.includeMeta || (this.#auditIncludeMeta && this.#logger.enabled) ? [] : null;

    const principalPolicy = this.#resolvePolicyFromMemory(
      'principal',
      this.#principalPolicies,
      req.P.id,
      req.P.policyVersion ?? DEFAULT_VERSION,
      req.P.scope,
      trace,
    );
    const principalResult = principalPolicy ? principalPolicy.check(req) : createEmptyPolicyResult();

    const unresolvedActions = [];
    for (const action of req.actions) {
      if (!principalResult.effects.has(action)) unresolvedActions.push(action);
    }
    let roleResult = createEmptyPolicyResult();
    let resourceResult = createEmptyPolicyResult();

    if (unresolvedActions.length) {
      const roleReq = unresolvedActions.length === req.actions.length ? req : { ...req, actions: unresolvedActions };
      roleResult = this.#evaluateRolePoliciesSync(roleReq, trace);
    }

    // Mirrors the async driver: the resource layer always runs for the actions
    // the principal policy left open; role policies only narrow it.
    if (unresolvedActions.length) {
      const resourcePolicy = this.#resolvePolicyFromMemory(
        'resource',
        this.#resourcePolicies,
        req.R.kind,
        req.R.policyVersion ?? DEFAULT_VERSION,
        req.R.scope,
        trace,
      );
      if (resourcePolicy) {
        const resourceReq =
          unresolvedActions.length === req.actions.length ? req : { ...req, actions: unresolvedActions };
        const importedDerivedRoles = this.#getImportedDerivedRolesSync(resourcePolicy, req, trace);
        resourceResult = resourcePolicy.check(resourceReq, importedDerivedRoles);
      }
    }

    return Kerberos.#mergeSourceResults(req, trace, principalResult, roleResult, resourceResult);
  }

  #buildResponseResource(resource) {
    const responseResource = { id: resource.id, kind: resource.kind };
    if (resource.policyVersion) responseResource.policyVersion = resource.policyVersion;

    const normalizedScope = Kerberos.normalizeScope(resource.scope);
    if (normalizedScope) responseResource.scope = normalizedScope;

    return responseResource;
  }

  // Response-boundary effect formatting: internals always work with canonical
  // EFFECT_ALLOW/EFFECT_DENY strings; `effectAsBoolean` converts here, once.
  #effectsToResponse(effects, effectAsBoolean) {
    const actions = {};
    for (const [action, effect] of effects) {
      actions[action] = effectAsBoolean ? effect === Effect.Allow : effect;
    }
    return actions;
  }

  /**
   * Shared request lifecycle for the public methods: telemetry span, start /
   * error / finish audit events, `onError` semantics and duration timing.
   * `denyFallback(callId, otel, error)` builds the method-specific
   * fail-closed result used when `onError: 'deny'` is configured (and may
   * emit its own audit/decision records).
   */
  async #runRequest(reqKind, reqId, handler, denyFallback) {
    const startedAt = getNow();
    const callId = this.#getCallId();

    return this.#telemetry.withRequestSpan(reqKind, callId, reqId, async (otel) => {
      try {
        this.#logMethodStart(reqKind, callId, reqId);
        return await handler(callId, otel);
      } catch (error) {
        this.#logMethodError(reqKind, callId, reqId, error);
        this.#telemetry.recordError(otel, error);
        // Malformed arguments are programming errors and always propagate;
        // evaluation-phase errors follow the configured `onError` semantics.
        if (error instanceof KerberosValidationError) throw error;
        if (this.#onError === 'deny') return denyFallback(callId, otel, error);
        throw error;
      } finally {
        const duration = getNow() - startedAt;
        this.#logMethodFinish(reqKind, callId, reqId, duration);
        this.#telemetry.endRequest(otel, reqKind, duration);
      }
    });
  }

  /**
   * Evaluates a single action against a resource.
   *
   * @param {Record<string, unknown>} args
   * @returns {Promise<boolean>}
   */
  async isAllowed(args) {
    const reqKind = 'IsAllowed';
    // Captured by the deny fallback so a fail-closed decision still produces
    // an audit entry + decisions-counter increment (null until parsing
    // succeeded — a pre-parse failure has nothing decision-shaped to log).
    let auditContext = null;

    return this.#runRequest(
      reqKind,
      args?.reqId,
      async (callId, otel) => {
        const parsedArgs = this.#parseArgs(this.#isAllowedArgsValidator, 'Invalid isAllowed arguments', args);

        // The request is assembled from the ALREADY-validated args plus
        // engine-generated fields — re-validating it (the old buildRequest
        // pass) deep-parsed the same principal/resource up to two more times
        // per call and, under Zod, split P/principal into different clones.
        // The public static Kerberos.parseRequest keeps full validation for
        // external callers.
        const req = {
          principal: parsedArgs.principal,
          resource: parsedArgs.resource,
          P: parsedArgs.principal,
          R: parsedArgs.resource,
          actions: [parsedArgs.action],
          reqId: parsedArgs.reqId,
          callId,
          includeMeta: parsedArgs.includeMeta,
        };

        auditContext = { req, action: parsedArgs.action };
        const relationsMemo = this.#relations ? new Map() : null;
        // Fully-synchronous configuration (no cache, no relations): the sync
        // driver skips the interior async frames entirely. Otherwise:
        // single-shot call, no lookups memo — #resolvePolicy's fast path
        // skips the memo bookkeeping (batching is checkResources' job).
        const { effects, outputs, meta } =
          !this.#cache.enabled && !this.#relations
            ? this.#evaluatePolicySourcesSync(req)
            : await this.#evaluatePolicySources(req, relationsMemo, null, otel);
        const isAllowed = effects.get(parsedArgs.action) === Effect.Allow || effects.get(ALL_ACTIONS) === Effect.Allow;

        const input = [{ req, result: { effects, outputs, meta } }];
        this.#log(input, reqKind, callId);
        this.#telemetry.recordDecisions(otel, input, reqKind);

        return isAllowed;
      },
      (callId, otel, error) => {
        if (auditContext) {
          const { req, action } = auditContext;
          const meta = {
            actions: { [action]: { reason: 'evaluation-error', errorName: error?.name } },
            effectiveDerivedRoles: [],
          };
          const input = [{ req, result: { effects: new Map([[action, Effect.Deny]]), outputs: new Map(), meta } }];
          this.#log(input, reqKind, callId);
          this.#telemetry.recordDecisions(otel, input, reqKind);
        }
        return false;
      },
    );
  }

  /**
   * Evaluates a set of resources and actions in a single request.
   *
   * @param {Record<string, unknown>} args
   * @param {boolean} [effectAsBoolean=false]
   * @returns {Promise<{ results: unknown[], kerberosCallId: string, reqId?: string }>}
   */
  async checkResources(args, effectAsBoolean = false) {
    const reqKind = 'CheckResources';

    return this.#runRequest(
      reqKind,
      args?.reqId,
      async (callId, otel) => {
        const parsedArgs = this.#parseArgs(this.#checkResourcesArgsValidator, 'Invalid checkResources arguments', args);

        // Requests are assembled from the ALREADY-validated args (the batch
        // validator covered the principal once and every resource entry) —
        // the old per-resource buildRequest pass re-parsed the same principal
        // 2x per resource on top of that.
        const reqs = [];
        for (const { resource, actions } of parsedArgs.resources) {
          reqs.push({
            principal: parsedArgs.principal,
            resource,
            P: parsedArgs.principal,
            R: resource,
            actions,
            reqId: parsedArgs.reqId,
            callId,
            includeMeta: parsedArgs.includeMeta,
          });
        }

        // Resources evaluate concurrently; allSettled keeps result order and
        // guarantees one rejected resource never fails the others. A rejected
        // resource yields a fail-closed result (all its actions DENY) plus an
        // error log/telemetry record, isolating failures at resource level.
        // One relations memo for the whole batch: the principal is the same,
        // so relation subproblems (e.g. group membership chains) resolved for
        // one resource are reused by the others.
        const relationsMemo = this.#relations ? new Map() : null;
        // One lookups memo for the whole batch, like relationsMemo: each
        // distinct policy resolves once per batch instead of once per
        // resource. Only worth its bookkeeping when a cache is configured —
        // in-memory lookups are already O(1) Map hits, so static-only configs
        // take #resolvePolicy's memo-less fast path.
        const lookups = this.#cache.enabled ? new Map() : null;
        let settled;
        if (!this.#cache.enabled && !this.#relations) {
          // Fully-synchronous configuration: evaluate in a plain loop while
          // preserving the per-resource fail-closed isolation contract via
          // the same settled-shaped outcomes the async wave produces.
          settled = [];
          for (const req of reqs) {
            try {
              settled.push({ status: 'fulfilled', value: this.#evaluatePolicySourcesSync(req) });
            } catch (error) {
              settled.push({ status: 'rejected', reason: error });
            }
          }
        } else {
          const limit = Number.isFinite(this.#maxConcurrency) ? createLimiter(this.#maxConcurrency) : null;
          const promises = [];
          for (const req of reqs) {
            promises.push(
              limit
                ? limit(() => this.#evaluatePolicySources(req, relationsMemo, lookups, otel))
                : this.#evaluatePolicySources(req, relationsMemo, lookups, otel),
            );
          }
          settled = await Promise.allSettled(promises);
        }

        const results = [];
        const inputForLog = [];
        for (let i = 0; i < settled.length; i++) {
          const req = reqs[i];
          const { resource } = parsedArgs.resources[i];

          if (settled[i].status === 'rejected') {
            const error = settled[i].reason;
            this.#logMethodError(reqKind, callId, parsedArgs.reqId, error);
            this.#telemetry.recordError(otel, error);

            // Error-shaped denials must be distinguishable from policy
            // denials: every action carries the 'evaluation-error' reason
            // (mirroring the 'policy-miss' convention) so an outage never
            // masquerades as a policy DENY. The marker reaches the RESPONSE
            // only under includeMeta, but ALWAYS reaches the audit log and
            // the kerberos.decisions counter — fail-closed decisions must not
            // vanish from the decision stream exactly when the system is
            // misbehaving. Note `onError` applies at REQUEST level only —
            // per-resource evaluation errors always fail-close here.
            const deniedActions = {};
            const deniedEffects = new Map();
            const actionsMeta = {};
            for (const action of req.actions) {
              deniedActions[action] = effectAsBoolean ? false : Effect.Deny;
              deniedEffects.set(action, Effect.Deny);
              actionsMeta[action] = { reason: 'evaluation-error', errorName: error?.name };
            }
            const errorMeta = { actions: actionsMeta, effectiveDerivedRoles: [] };
            const failedResult = {
              resource: this.#buildResponseResource(resource),
              actions: deniedActions,
              outputs: [],
            };
            if (req.includeMeta) failedResult.meta = errorMeta;
            results.push(failedResult);
            inputForLog.push({ req, result: { effects: deniedEffects, outputs: new Map(), meta: errorMeta } });
            continue;
          }

          const { effects, outputs, meta } = settled[i].value;
          const result = {
            resource: this.#buildResponseResource(resource),
            actions: this.#effectsToResponse(effects, effectAsBoolean),
            outputs: [...outputs.values()],
          };
          if (req.includeMeta) result.meta = meta;
          results.push(result);
          inputForLog.push({ req, result: { effects, outputs, meta } });
        }

        this.#log(inputForLog, reqKind, callId);
        this.#telemetry.recordDecisions(otel, inputForLog, reqKind);

        const response = { results, kerberosCallId: callId };
        if (parsedArgs.reqId) response.reqId = parsedArgs.reqId;
        return response;
      },
      (callId) => {
        // Fail-closed shape parity: callers index results positionally
        // (results[i] ↔ resources[i]) like Cerbos's CheckResources, so the
        // request-level fallback builds one DENY result per requested
        // resource instead of an empty list — guarded field-by-field, since
        // validation may not have run when the failure happened.
        const results = [];
        const rawResources = Array.isArray(args?.resources) ? args.resources : [];
        for (const entry of rawResources) {
          const resource = entry?.resource;
          if (!resource || typeof resource.id !== 'string' || typeof resource.kind !== 'string') continue;
          const deniedActions = {};
          if (Array.isArray(entry.actions)) {
            for (const action of entry.actions) {
              if (typeof action === 'string') deniedActions[action] = effectAsBoolean ? false : Effect.Deny;
            }
          }
          results.push({ resource: this.#buildResponseResource(resource), actions: deniedActions, outputs: [] });
        }
        const response = { results, kerberosCallId: callId };
        if (typeof args?.reqId === 'string') response.reqId = args.reqId;
        return response;
      },
    );
  }

  // Response scaffold shared by the success path and the onError:'deny'
  // fallback: echoes the request form (`action` vs `actions`) like Cerbos.
  static #buildPlanResponse(callId, reqId, resource, action, actions, filter) {
    const response = { kerberosCallId: callId };
    if (reqId) response.reqId = reqId;
    if (action !== undefined) response.action = action;
    else if (actions !== undefined) response.actions = actions;
    response.resourceKind = resource?.kind;
    response.policyVersion = resource?.policyVersion ?? DEFAULT_VERSION;
    response.filter = filter;
    return response;
  }

  /**
   * Builds a Cerbos-compatible resources query plan: which resources of a
   * kind the principal could act on, as a filter to translate into a data
   * query. `resource.attr` carries the KNOWN attributes; everything else is
   * treated as unknown and surfaces in the residual condition as
   * `request.resource.attr.*` / `request.resource.id` operands. Kerberos
   * extensions: the `opaque` operator (statically unplannable condition —
   * translators must post-filter) and `relation` (ReBAC dependency — see
   * `expandRelationOperands`).
   *
   * @param {Record<string, unknown>} args
   * @returns {Promise<Record<string, unknown>>}
   */
  async planResources(args) {
    const reqKind = 'PlanResources';

    return this.#runRequest(
      reqKind,
      args?.reqId,
      async (callId, otel) => {
        const parsedArgs = this.#parseArgs(this.#planResourcesArgsValidator, 'Invalid planResources arguments', args);

        // The schemas keep `action`/`actions` independently optional; the
        // exactly-one-of invariant (and the wildcard rejection) are enforced
        // here so the rule also holds without a validation backend.
        const hasAction = parsedArgs.action !== undefined;
        const hasActions = parsedArgs.actions !== undefined;
        if (hasAction === hasActions) {
          throw new KerberosValidationError(
            'Invalid planResources arguments: provide exactly one of "action" or "actions"',
          );
        }
        const actions = hasAction ? [parsedArgs.action] : [...parsedArgs.actions];
        // Guarded here too (not only in the schemas): with no validation
        // backend an empty list would otherwise plan an empty conjunction —
        // KIND_ALWAYS_ALLOWED, a fail-open.
        if (!actions.length) {
          throw new KerberosValidationError('Invalid planResources arguments: "actions" must not be empty');
        }
        for (const action of actions) {
          if (typeof action !== 'string' || !action.length) {
            throw new KerberosValidationError('Invalid planResources arguments: actions must be non-empty strings');
          }
          if (action === ALL_ACTIONS) {
            throw new KerberosValidationError(
              `Invalid planResources arguments: the wildcard action "${ALL_ACTIONS}" cannot be planned`,
            );
          }
        }

        const trace = parsedArgs.includeMeta ? [] : null;
        const sources = await this.#planPolicySources(
          parsedArgs.principal,
          parsedArgs.resource,
          actions,
          trace,
          // Dedupes role-closure lookups; only worth it on the cache path.
          this.#cache.enabled ? new Map() : null,
        );
        const { node } = buildResourcePlan({
          principal: parsedArgs.principal,
          resource: parsedArgs.resource,
          actions,
          ...sources,
          hasRelations: Boolean(this.#relations),
          trace,
        });

        const filter = toFilter(node);

        // Decision-level observability: the plan outcome (an ALWAYS_ALLOWED
        // filter is a fail-open query) must be visible to operators, like the
        // per-action decisions of isAllowed/checkResources are.
        const counts = countLeaves(node);
        this.#telemetry.recordPlan(otel, {
          kind: filter.kind,
          resourceKind: parsedArgs.resource.kind,
          actionsCount: actions.length,
          opaqueCount: counts.opaque,
          relationCount: counts.relation,
          principalId: parsedArgs.principal.id,
        });
        this.#logPlanResult(callId, parsedArgs.reqId, parsedArgs.resource.kind, filter, counts, actions);

        const response = Kerberos.#buildPlanResponse(
          callId,
          parsedArgs.reqId,
          parsedArgs.resource,
          hasAction ? parsedArgs.action : undefined,
          actions,
          filter,
        );

        if (parsedArgs.includeMeta) {
          const matchedScopes = {
            principal: sources.principalPolicy ? (sources.principalPolicy.scope ?? '') : null,
            resource: sources.resourcePolicy ? (sources.resourcePolicy.scope ?? '') : null,
            roles: {},
          };
          const seenRoles = new Set();
          for (const role of parsedArgs.principal.roles) {
            if (seenRoles.has(role)) continue;
            seenRoles.add(role);
            const policy = sources.rolePolicyClosure.get(role);
            matchedScopes.roles[role] = policy ? (policy.scope ?? '') : null;
          }
          response.meta = { filterDebug: toDebugString(node), matchedScopes, resolution: trace };
        }

        return response;
      },
      (callId) =>
        Kerberos.#buildPlanResponse(
          callId,
          args?.reqId,
          args?.resource,
          typeof args?.action === 'string' ? args.action : undefined,
          Array.isArray(args?.actions) ? [...args.actions] : undefined,
          { kind: PlanKind.AlwaysDenied },
        ),
    );
  }
}

module.exports = {
  Kerberos,
  KerberosJsonSchemas,
  KerberosTypeBoxSchemas,
  KerberosZodSchemas,
};
