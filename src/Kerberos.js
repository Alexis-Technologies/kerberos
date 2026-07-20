const { ResourcePolicy } = require('./ResourcePolicy/index.js');
const { PrincipalPolicy } = require('./PrincipalPolicy/index.js');
const { RolePolicy } = require('./RolePolicy/index.js');
const { DerivedRoles } = require('./DerivedRoles/index.js');
const { ALL_ACTIONS, DEFAULT_VERSION, Effect, JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('./schemas');
const { KerberosJsonSchemas, KerberosTypeBoxSchemas, KerberosZodSchemas } = require('./schemas/kerberos.js');
const { createLoggerWriter } = require('./logging.js');
const { createTelemetryWriter } = require('./telemetry.js');
const { createCacheReader } = require('./caching/cache.js');
const { KerberosCodecError, KerberosValidationError } = require('./errors.js');
const { createSafeExprCodec } = require('./caching/codec.js');
const { PlanKind, toDebugString, toFilter } = require('./planning/nodes.js');
const { buildResourcePlan } = require('./planning/planner.js');
const { createAjvAdapter, parseWithValidation, registerAjvKeywords } = require('./validation');
// Platform runtime: bundlers swap this for `./runtime/browser.js` via the
// package.json `browser` field map when targeting the browser.
const { generateCallId, getNow } = require('./runtime/node.js');

function createEmptyPolicyResult() {
  return { effects: new Map(), outputs: new Map(), meta: { actions: {}, effectiveDerivedRoles: [] } };
}

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
   * @param {string | undefined} scope
   * @returns {string[]}
   */
  static getScopeSearchChain(scope) {
    const normalizedScope = Kerberos.normalizeScope(scope);
    if (!normalizedScope) return [''];

    const segments = normalizedScope.split('.');
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

  #requestValidator = null;

  #isAllowedArgsValidator = null;

  #checkResourcesArgsValidator = null;

  #planResourcesArgsValidator = null;

  #getCallId = null;

  #onError = 'throw';

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
    let chain = this.#scopeChains.get(normalized);
    if (!chain) {
      chain = Kerberos.getScopeSearchChain(normalized);
      if (this.#scopeChains.size < Kerberos.#MAX_CACHED_SCOPE_CHAINS) this.#scopeChains.set(normalized, chain);
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
    { logger, telemetry, cache, cacheRetry, codec, onError, relations, z, ajv, typebox, getCallId } = {
      logger: false,
      telemetry: null,
      cache: null,
      cacheRetry: null,
      codec: null,
      onError: 'throw',
      relations: null,
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

    if (z) {
      this.#z = z;
      this.#resourcePolicyValidator = KerberosZodSchemas.buildResourcePolicyInstance(z);
      this.#principalPolicyValidator = KerberosZodSchemas.buildPrincipalPolicyInstance(z);
      this.#rolePolicyValidator = KerberosZodSchemas.buildRolePolicyInstance(z);
      this.#derivedRolesValidator = KerberosZodSchemas.buildDerivedRolesInstance(z);
      this.#requestValidator = ZodSchemas.buildRequest(z);
      this.#isAllowedArgsValidator = KerberosZodSchemas.buildIsAllowedArgs(z);
      this.#checkResourcesArgsValidator = KerberosZodSchemas.buildCheckResourcesArgs(z);
      this.#planResourcesArgsValidator = KerberosZodSchemas.buildPlanResourcesArgs(z);
    } else if (this.#ajv && this.#typebox) {
      this.#resourcePolicyValidator = createAjvAdapter(
        this.#ajv,
        KerberosTypeBoxSchemas.buildResourcePolicyInstance(this.#typebox),
      );
      this.#principalPolicyValidator = createAjvAdapter(
        this.#ajv,
        KerberosTypeBoxSchemas.buildPrincipalPolicyInstance(this.#typebox),
      );
      this.#rolePolicyValidator = createAjvAdapter(
        this.#ajv,
        KerberosTypeBoxSchemas.buildRolePolicyInstance(this.#typebox),
      );
      this.#derivedRolesValidator = createAjvAdapter(
        this.#ajv,
        KerberosTypeBoxSchemas.buildDerivedRolesInstance(this.#typebox),
      );
      this.#requestValidator = createAjvAdapter(this.#ajv, TypeBoxSchemas.buildRequest(this.#typebox));
      this.#isAllowedArgsValidator = createAjvAdapter(
        this.#ajv,
        KerberosTypeBoxSchemas.buildIsAllowedArgs(this.#typebox),
      );
      this.#checkResourcesArgsValidator = createAjvAdapter(
        this.#ajv,
        KerberosTypeBoxSchemas.buildCheckResourcesArgs(this.#typebox),
      );
      this.#planResourcesArgsValidator = createAjvAdapter(
        this.#ajv,
        KerberosTypeBoxSchemas.buildPlanResourcesArgs(this.#typebox),
      );
    } else if (this.#ajv) {
      this.#resourcePolicyValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildResourcePolicyInstance());
      this.#principalPolicyValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildPrincipalPolicyInstance());
      this.#rolePolicyValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildRolePolicyInstance());
      this.#derivedRolesValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildDerivedRolesInstance());
      this.#requestValidator = createAjvAdapter(this.#ajv, JsonSchemas.buildRequest());
      this.#isAllowedArgsValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildIsAllowedArgs());
      this.#checkResourcesArgsValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildCheckResourcesArgs());
      this.#planResourcesArgsValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildPlanResourcesArgs());
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
    try {
      this.#logger.debug(
        { timestamp: new Date().toISOString(), event: `Cache.${result}`, key },
        `Kerberos.js cache ${result} for ${key}`,
      );
    } catch {
      // Audit logging must never break authorization.
    }
  }

  async #resolveFromCache(key, build) {
    if (!this.#cache.enabled) return null;
    let value;
    try {
      // A transient backend failure surfaces here as KerberosCacheError (after
      // the reader's retry loop) and propagates per the `onError` semantics.
      value = await this.#cache.get(key);
    } catch (error) {
      this.#recordCacheResult(key, 'error');
      throw error;
    }
    if (value === undefined || value === null) {
      this.#recordCacheResult(key, 'miss');
      return null;
    }
    try {
      const shape = this.#codecDeserialize ? this.#codecDeserialize(value) : value;
      const built = build(shape);
      this.#recordCacheResult(key, 'hit');
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
  async #resolveDerivedRolesSetByName(name) {
    const role = this.#derivedRoles.get(name);
    if (role) return role;
    return this.#resolveFromCache(`derivedRoles:${name}`, (shape) => new DerivedRoles(shape, this.#policyOptions()));
  }

  async #getImportedDerivedRoles(policy, req, relationsMemo, trace) {
    const importedRoles = new Set();
    const relationCandidates = [];
    for (const name of policy.importDerivedRoles) {
      const role = await this.#resolveDerivedRolesSetByName(name);
      if (!role) continue;
      const derivedRoles = role.get(req);
      if (derivedRoles) for (const derivedRole of derivedRoles) importedRoles.add(derivedRole);
      for (const candidate of role.getRelationCandidates(req)) relationCandidates.push(candidate);
    }

    if (relationCandidates.length) {
      if (this.#relations) {
        const granted = await this.#resolveRelationCandidates(relationCandidates, req, relationsMemo, trace);
        for (const name of granted) importedRoles.add(name);
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
  async #resolveRelationCandidates(candidates, req, memo, trace) {
    // Several derived roles may point at the same relation — resolve each
    // relation once.
    const relationNames = [];
    const seenRelations = new Set();
    for (const candidate of candidates) {
      if (seenRelations.has(candidate.relation)) continue;
      seenRelations.add(candidate.relation);
      relationNames.push(candidate.relation);
    }

    let granted;
    if (typeof this.#relations.list === 'function') {
      const listed = await this.#relations.list(
        { principal: req.P, resource: req.R, relations: relationNames },
        { memo },
      );
      granted = listed instanceof Set ? listed : new Set(listed ?? []);
    } else {
      // Parallel checks; allSettled so one rejection never leaves siblings
      // unawaited. A failure still surfaces after all settle (per the onError
      // semantics) — a resolver error must not silently read as "not granted".
      const checks = [];
      for (const relation of relationNames) {
        checks.push(this.#relations.check({ principal: req.P, resource: req.R, relation }, { memo }));
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
  #parseValidated(label, parse) {
    try {
      return parse();
    } catch (error) {
      if (error instanceof KerberosValidationError) throw error;
      throw new KerberosValidationError(`${label}: ${error.message}`, { cause: error });
    }
  }

  #log(input, reqKind, callId) {
    try {
      this.#logger.write(input, reqKind, callId);
    } catch {
      // Audit logging must never break authorization.
    }
  }

  #logMethodStart(reqKind, callId, reqId) {
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
    } catch {
      // Audit logging must never break authorization.
    }
  }

  #logMethodError(reqKind, callId, reqId, error) {
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
    } catch {
      // Audit logging must never break authorization.
    }
  }

  #logMethodFinish(reqKind, callId, reqId, duration) {
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
    } catch {
      // Audit logging must never break authorization.
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
   */
  async #resolvePolicy(source, map, id, version, scope, Constructor, trace) {
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
          `${source}:${id}:${version}:${searchScope}`,
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

  #getResourcePolicy(req, trace) {
    const version = req.R.policyVersion ?? DEFAULT_VERSION;
    return this.#resolvePolicy(
      'resource',
      this.#resourcePolicies,
      req.R.kind,
      version,
      req.R.scope,
      ResourcePolicy,
      trace,
    );
  }

  #getPrincipalPolicy(req, trace) {
    const version = req.P.policyVersion ?? DEFAULT_VERSION;
    return this.#resolvePolicy(
      'principal',
      this.#principalPolicies,
      req.P.id,
      version,
      req.P.scope,
      PrincipalPolicy,
      trace,
    );
  }

  #getRolePolicyByName(role, req, trace) {
    const version = req.P.policyVersion ?? DEFAULT_VERSION;
    return this.#resolvePolicy('role', this.#rolePolicies, role, version, req.P.scope, RolePolicy, trace);
  }

  async #getRolePolicies(req, trace) {
    const policies = [];
    const seenRoles = new Set();

    for (const role of req.P.roles) {
      if (seenRoles.has(role)) continue;
      seenRoles.add(role);
      const policy = await this.#getRolePolicyByName(role, req, trace);
      if (policy) policies.push(policy);
    }

    return policies;
  }

  async #evaluateRolePolicy(policy, req, memo = new Map(), stack = new Set(), actionsKey = req.actions.join(',')) {
    const policyKey = `${policy.role}.${policy.version}.${policy.scope ?? ''}|${actionsKey}`;
    if (memo.has(policyKey)) return memo.get(policyKey);
    if (stack.has(policyKey)) throw new Error(`Circular role policy inheritance detected for role "${policy.role}"`);

    stack.add(policyKey);

    const result = policy.check(req);

    for (const parentRole of policy.parentRoles) {
      const parentPolicy = await this.#getRolePolicyByName(parentRole, req);
      if (!parentPolicy) continue;

      const parentResult = await this.#evaluateRolePolicy(parentPolicy, req, memo, stack, actionsKey);
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

    stack.delete(policyKey);
    memo.set(policyKey, result);
    return result;
  }

  async #evaluateRolePolicies(req, trace) {
    const rolePolicies = await this.#getRolePolicies(req, trace);
    if (!rolePolicies.length) return { ...createEmptyPolicyResult(), hadPolicies: false };

    const effects = new Map();
    const outputs = new Map();
    const actionsMeta = {};
    const memo = new Map();
    const actionsKey = req.actions.join(',');

    for (const policy of rolePolicies) {
      const result = await this.#evaluateRolePolicy(policy, req, memo, new Set(), actionsKey);
      for (const [src, output] of result.outputs.entries()) outputs.set(src, output);

      for (const action of req.actions) {
        if (!result.effects.has(action)) continue;

        if (result.effects.get(action) === Effect.Deny) {
          effects.set(action, Effect.Deny);
          if (result.meta.actions[action]) actionsMeta[action] = result.meta.actions[action];
          continue;
        }

        if (!effects.has(action)) {
          effects.set(action, Effect.Allow);
          if (result.meta.actions[action]) actionsMeta[action] = result.meta.actions[action];
        }
      }
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

  /**
   * Resolves the transitive parentRoles closure for the query planner: every
   * role reachable from the principal's role policies, mapped to its resolved
   * policy (or null). Parent lookups are untraced — runtime parity with
   * `#evaluateRolePolicy`, which resolves parents without a trace.
   */
  async #resolveRolePolicyClosure(rolePolicies, req) {
    const closure = new Map();
    const queue = [];
    for (const policy of rolePolicies) {
      closure.set(policy.role, policy);
      for (const parentRole of policy.parentRoles) queue.push(parentRole);
    }
    // Cursor-based BFS (no shift); the closure map doubles as the visited set,
    // so parentRoles cycles terminate here and are reported by the planner.
    for (let i = 0; i < queue.length; i++) {
      const role = queue[i];
      if (closure.has(role)) continue;
      const policy = await this.#getRolePolicyByName(role, req);
      closure.set(role, policy ?? null);
      if (policy) for (const parentRole of policy.parentRoles) queue.push(parentRole);
    }
    return closure;
  }

  async #resolveDerivedRolesSets(policy) {
    const sets = [];
    for (const name of policy.importDerivedRoles) {
      const set = await this.#resolveDerivedRolesSetByName(name);
      if (set) sets.push(set);
    }
    return sets;
  }

  // The two dependent planning chains (roles → parent closure; resource →
  // derived-roles sets) — split out so #planPolicySources can run all three
  // sources as one concurrent allSettled wave.
  async #planRoleSources(req, trace) {
    const rolePolicies = await this.#getRolePolicies(req, trace);
    const rolePolicyClosure = await this.#resolveRolePolicyClosure(rolePolicies, req);
    return { rolePolicies, rolePolicyClosure };
  }

  async #planResourceSources(req, trace) {
    const resourcePolicy = await this.#getResourcePolicy(req, trace);
    const derivedRolesSets = resourcePolicy ? await this.#resolveDerivedRolesSets(resourcePolicy) : [];
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
  async #planPolicySources(principal, resource, actions, trace) {
    const req = { principal, resource, P: principal, R: resource, actions };
    const principalTrace = trace ? [] : null;
    const roleTrace = trace ? [] : null;
    const resourceTrace = trace ? [] : null;

    const settled = await Promise.allSettled([
      this.#getPrincipalPolicy(req, principalTrace),
      this.#planRoleSources(req, roleTrace),
      this.#planResourceSources(req, resourceTrace),
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
  async #evaluatePolicySources(req, relationsMemo) {
    const trace = req.includeMeta ? [] : null;

    const principalPolicy = await this.#getPrincipalPolicy(req, trace);
    const principalResult = principalPolicy ? principalPolicy.check(req) : createEmptyPolicyResult();

    const unresolvedActions = [];
    for (const action of req.actions) {
      if (!principalResult.effects.has(action)) unresolvedActions.push(action);
    }
    let roleResult = createEmptyPolicyResult();
    let resourceResult = createEmptyPolicyResult();

    const roleUnresolvedActions = [];
    if (unresolvedActions.length) {
      const roleReq = unresolvedActions.length === req.actions.length ? req : { ...req, actions: unresolvedActions };
      roleResult = await this.#evaluateRolePolicies(roleReq, trace);

      for (const action of unresolvedActions) {
        if (!roleResult.effects.has(action)) roleUnresolvedActions.push(action);
      }
    }

    if (roleUnresolvedActions.length) {
      const resourcePolicy = await this.#getResourcePolicy(req, trace);
      if (resourcePolicy) {
        const resourceReq =
          roleUnresolvedActions.length === req.actions.length ? req : { ...req, actions: roleUnresolvedActions };
        const importedDerivedRoles = await this.#getImportedDerivedRoles(resourcePolicy, req, relationsMemo, trace);
        resourceResult = resourcePolicy.check(resourceReq, importedDerivedRoles);
      }
    }

    const effects = new Map();
    const actionsMeta = {};
    for (const action of req.actions) {
      if (principalResult.effects.has(action)) {
        effects.set(action, principalResult.effects.get(action));
        if (principalResult.meta.actions[action]) actionsMeta[action] = principalResult.meta.actions[action];
        continue;
      }

      if (roleResult.effects.has(action)) {
        effects.set(action, roleResult.effects.get(action));
        if (roleResult.meta.actions[action]) actionsMeta[action] = roleResult.meta.actions[action];
        continue;
      }

      if (resourceResult.effects.has(action)) {
        effects.set(action, resourceResult.effects.get(action));
        if (resourceResult.meta.actions[action]) actionsMeta[action] = resourceResult.meta.actions[action];
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
   * `denyFallback(callId)` builds the method-specific fail-closed result used
   * when `onError: 'deny'` is configured.
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
        if (this.#onError === 'deny') return denyFallback(callId);
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

    return this.#runRequest(
      reqKind,
      args?.reqId,
      async (callId, otel) => {
        const parsedArgs = this.#parseValidated('Invalid isAllowed arguments', () =>
          Kerberos.parseIsAllowedArgs(args, {
            schema: this.#isAllowedArgsValidator,
            z: this.#z,
            ajv: this.#ajv,
            typebox: this.#typebox,
          }),
        );

        const req = this.#parseValidated('Invalid request', () =>
          Kerberos.parseRequest(
            {
              principal: parsedArgs.principal,
              resource: parsedArgs.resource,
              actions: [parsedArgs.action],
              reqId: parsedArgs.reqId,
              callId,
              includeMeta: parsedArgs.includeMeta,
            },
            {
              schema: this.#requestValidator,
              z: this.#z,
              ajv: this.#ajv,
              typebox: this.#typebox,
            },
          ),
        );

        const relationsMemo = this.#relations ? new Map() : null;
        const { effects, outputs, meta } = await this.#evaluatePolicySources(req, relationsMemo);
        const isAllowed = effects.get(parsedArgs.action) === Effect.Allow || effects.get(ALL_ACTIONS) === Effect.Allow;

        const input = [{ req, result: { effects, outputs, meta } }];
        this.#log(input, reqKind, callId);
        this.#telemetry.recordDecisions(otel, input, reqKind);

        return isAllowed;
      },
      () => false,
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
        const parsedArgs = this.#parseValidated('Invalid checkResources arguments', () =>
          Kerberos.parseCheckResourcesArgs(args, {
            schema: this.#checkResourcesArgsValidator,
            z: this.#z,
            ajv: this.#ajv,
            typebox: this.#typebox,
          }),
        );

        // Validation stays synchronous and up-front: a malformed resource
        // entry fails the whole request (programming error), before any
        // evaluation starts.
        const reqs = [];
        for (const { resource, actions } of parsedArgs.resources) {
          reqs.push(
            this.#parseValidated('Invalid request', () =>
              Kerberos.parseRequest(
                {
                  principal: parsedArgs.principal,
                  resource,
                  actions,
                  reqId: parsedArgs.reqId,
                  callId,
                  includeMeta: parsedArgs.includeMeta,
                },
                {
                  schema: this.#requestValidator,
                  z: this.#z,
                  ajv: this.#ajv,
                  typebox: this.#typebox,
                },
              ),
            ),
          );
        }

        // Resources evaluate concurrently; allSettled keeps result order and
        // guarantees one rejected resource never fails the others. A rejected
        // resource yields a fail-closed result (all its actions DENY) plus an
        // error log/telemetry record, isolating failures at resource level.
        // One relations memo for the whole batch: the principal is the same,
        // so relation subproblems (e.g. group membership chains) resolved for
        // one resource are reused by the others.
        const relationsMemo = this.#relations ? new Map() : null;
        const promises = [];
        for (const req of reqs) promises.push(this.#evaluatePolicySources(req, relationsMemo));
        const settled = await Promise.allSettled(promises);

        const results = [];
        const inputForLog = [];
        for (let i = 0; i < settled.length; i++) {
          const req = reqs[i];
          const { resource } = parsedArgs.resources[i];

          if (settled[i].status === 'rejected') {
            const error = settled[i].reason;
            this.#logMethodError(reqKind, callId, parsedArgs.reqId, error);
            this.#telemetry.recordError(otel, error);

            const deniedActions = {};
            for (const action of req.actions) deniedActions[action] = effectAsBoolean ? false : Effect.Deny;
            results.push({
              resource: this.#buildResponseResource(resource),
              actions: deniedActions,
              outputs: [],
            });
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
      (callId) => ({ results: [], kerberosCallId: callId, reqId: args?.reqId }),
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
      async (callId) => {
        const parsedArgs = this.#parseValidated('Invalid planResources arguments', () =>
          Kerberos.parsePlanResourcesArgs(args, {
            schema: this.#planResourcesArgsValidator,
            z: this.#z,
            ajv: this.#ajv,
            typebox: this.#typebox,
          }),
        );

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
        const sources = await this.#planPolicySources(parsedArgs.principal, parsedArgs.resource, actions, trace);
        const { node } = buildResourcePlan({
          principal: parsedArgs.principal,
          resource: parsedArgs.resource,
          actions,
          ...sources,
          hasRelations: Boolean(this.#relations),
          trace,
        });

        const response = Kerberos.#buildPlanResponse(
          callId,
          parsedArgs.reqId,
          parsedArgs.resource,
          hasAction ? parsedArgs.action : undefined,
          actions,
          toFilter(node),
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
