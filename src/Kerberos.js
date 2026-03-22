const { ResourcePolicy } = require('./ResourcePolicy/index.js');
const { PrincipalPolicy } = require('./PrincipalPolicy/index.js');
const { DerivedRoles } = require('./DerivedRoles/index.js');
const { ALL_ACTIONS, Effect, JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('./schemas');
const { KerberosJsonSchemas, KerberosTypeBoxSchemas, KerberosZodSchemas } = require('./schemas/kerberos.js');
const { createLoggerWriter } = require('./logging.js');
const { createAjvAdapter, parseWithValidation, registerAjvKeywords } = require('./validation');

// Import crypto for Node.js environment
let nodeCrypto;
try {
  nodeCrypto = require('crypto');
} catch (error) {
  // Ignore error, will fall back to browser crypto or manual generation
}

let nodePerformance;
try {
  ({ performance: nodePerformance } = require('node:perf_hooks'));
} catch (error) {
  // Ignore error, will fall back to global performance or Date.now
}

function getNow() {
  if (nodePerformance?.now) return nodePerformance.now();
  if (globalThis?.performance?.now) return globalThis.performance.now();
  return Date.now();
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
    // Try Node.js crypto.randomUUID first
    if (nodeCrypto?.randomUUID) return nodeCrypto.randomUUID();
    // Try Browser crypto.randomUUID
    if (window?.crypto?.randomUUID) return window.crypto.randomUUID();
    // Fall back to pseudo UUID v4-like generator
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
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
    const { schema, resourceSchema, principalSchema, ...nestedOptions } = options;
    if (policy && typeof policy === 'object' && 'principalPolicy' in policy) {
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
      }
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

  #resourcePolicies = new Map();

  #principalPolicies = new Map();

  #derivedRoles = new Map();

  #logger = createLoggerWriter(false);

  #z = null;

  #ajv = null;

  #typebox = null;

  #resourcePolicyValidator = null;

  #principalPolicyValidator = null;

  #derivedRolesValidator = null;

  #requestValidator = null;

  #isAllowedArgsValidator = null;

  #checkResourcesArgsValidator = null;

  #getCallId = null;

  /**
   * @param {unknown[]} policies
   * @param {unknown[]} derivedRoles
   * @param {object} [options]
   */
  constructor(policies, derivedRoles, { logger, z, ajv, typebox, getCallId } = { logger: false, z: null, ajv: null, typebox: null, getCallId: null }) {
    this.#getCallId = Kerberos.generateCallId;

    this.#ajv = ajv ?? null;
    this.#typebox = typebox ?? null;

    if (this.#ajv) registerAjvKeywords(this.#ajv);

    if (z) {
      this.#z = z;
      this.#resourcePolicyValidator = KerberosZodSchemas.buildResourcePolicyInstance(z);
      this.#principalPolicyValidator = KerberosZodSchemas.buildPrincipalPolicyInstance(z);
      this.#derivedRolesValidator = KerberosZodSchemas.buildDerivedRolesInstance(z);
      this.#requestValidator = ZodSchemas.buildRequest(z);
      this.#isAllowedArgsValidator = KerberosZodSchemas.buildIsAllowedArgs(z);
      this.#checkResourcesArgsValidator = KerberosZodSchemas.buildCheckResourcesArgs(z);
    } else if (this.#ajv && this.#typebox) {
      this.#resourcePolicyValidator = createAjvAdapter(this.#ajv, KerberosTypeBoxSchemas.buildResourcePolicyInstance(this.#typebox));
      this.#principalPolicyValidator = createAjvAdapter(this.#ajv, KerberosTypeBoxSchemas.buildPrincipalPolicyInstance(this.#typebox));
      this.#derivedRolesValidator = createAjvAdapter(this.#ajv, KerberosTypeBoxSchemas.buildDerivedRolesInstance(this.#typebox));
      this.#requestValidator = createAjvAdapter(this.#ajv, TypeBoxSchemas.buildRequest(this.#typebox));
      this.#isAllowedArgsValidator = createAjvAdapter(this.#ajv, KerberosTypeBoxSchemas.buildIsAllowedArgs(this.#typebox));
      this.#checkResourcesArgsValidator = createAjvAdapter(this.#ajv, KerberosTypeBoxSchemas.buildCheckResourcesArgs(this.#typebox));
    } else if (this.#ajv) {
      this.#resourcePolicyValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildResourcePolicyInstance());
      this.#principalPolicyValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildPrincipalPolicyInstance());
      this.#derivedRolesValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildDerivedRolesInstance());
      this.#requestValidator = createAjvAdapter(this.#ajv, JsonSchemas.buildRequest());
      this.#isAllowedArgsValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildIsAllowedArgs());
      this.#checkResourcesArgsValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildCheckResourcesArgs());
    }

    const { resourcePolicies, principalPolicies } = this.#getPoliciesMaps(policies);
    this.#resourcePolicies = resourcePolicies;
    this.#principalPolicies = principalPolicies;
    this.#derivedRoles = this.#getDerivedRolesMap(derivedRoles);

    this.#logger = createLoggerWriter(logger);
    if (typeof getCallId === 'function') this.#getCallId = getCallId;
  }

  #getPoliciesMaps(policies) {
    const resourcePolicies = new Map();
    const principalPolicies = new Map();
    for (const policy of policies) {
      const handledPolicy = Kerberos.parsePolicy(policy, {
        resourceSchema: this.#resourcePolicyValidator,
        principalSchema: this.#principalPolicyValidator,
        z: this.#z,
        ajv: this.#ajv,
        typebox: this.#typebox,
      });

      if (handledPolicy instanceof PrincipalPolicy) {
        principalPolicies.set(`${handledPolicy.principal}.${handledPolicy.version}.${handledPolicy.scope ?? ''}`, handledPolicy);
        continue;
      }

      resourcePolicies.set(`${handledPolicy.kind}.${handledPolicy.version}.${handledPolicy.scope ?? ''}`, handledPolicy);
    }
    return { resourcePolicies, principalPolicies };
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
      derivedRolesMap.set(handledRole.name, handledRole);
    }
    return derivedRolesMap;
  }

  #getImportedDerivedRoles(policy, req) {
    const importedRoles = new Set();
    for (const name of policy.importDerivedRoles) {
      const role = this.#derivedRoles.get(name);
      if (!role) continue;
      const derivedRoles = role.get(req);
      if (!derivedRoles) continue;
      for (const derivedRole of derivedRoles) importedRoles.add(derivedRole);
    }
    return importedRoles;
  }

  #log(input, reqKind, callId) {
    this.#logger.write(input, reqKind, callId);
  }

  #logMethodStart(reqKind, callId, reqId) {
    this.#logger.debug({
      callId,
      reqId,
      timestamp: new Date().toISOString(),
      reqKind,
      event: `${reqKind}.start`,
    }, `Kerberos.js ${reqKind} start!`);
  }

  #logMethodError(reqKind, callId, reqId, error) {
    this.#logger.error({
      callId,
      reqId,
      timestamp: new Date().toISOString(),
      reqKind,
      event: `${reqKind}.error`,
      errorName: error?.name,
      errorMessage: error?.message,
      stack: error?.stack,
    }, `Kerberos.js ${reqKind} error!`);
  }

  #logMethodFinish(reqKind, callId, reqId, duration) {
    this.#logger.debug({
      callId,
      reqId,
      timestamp: new Date().toISOString(),
      reqKind,
      event: `${reqKind}.finish`,
      duration,
    }, `Kerberos.js ${reqKind} finish!`);
  }

  #getResourcePolicy(req) {
    const scopeSearchChain = Kerberos.getScopeSearchChain(req.R.scope);
    const version = req.R.policyVersion ?? 'default';

    for (const scope of scopeSearchChain) {
      const policy = this.#resourcePolicies.get(`${req.R.kind}.${version}.${scope}`);
      if (policy) return policy;
    }
    return null;
  }

  #getPrincipalPolicy(req) {
    const scopeSearchChain = Kerberos.getScopeSearchChain(req.P.scope);
    const version = req.P.policyVersion ?? 'default';

    for (const scope of scopeSearchChain) {
      const policy = this.#principalPolicies.get(`${req.P.id}.${version}.${scope}`);
      if (policy) return policy;
    }
    return null;
  }

  #evaluatePolicySources(req, effectAsBoolean = false) {
    const principalPolicy = this.#getPrincipalPolicy(req);
    const principalResult = principalPolicy
      ? principalPolicy.check(req, effectAsBoolean)
      : { effects: new Map(), outputs: new Map(), meta: { actions: {}, effectiveDerivedRoles: [] } };

    const unresolvedActions = [];
    for (const action of req.actions) {
      if (!principalResult.effects.has(action)) unresolvedActions.push(action);
    }
    let resourceResult = { effects: new Map(), outputs: new Map(), meta: { actions: {}, effectiveDerivedRoles: [] } };

    if (unresolvedActions.length) {
      const resourcePolicy = this.#getResourcePolicy(req);
      if (resourcePolicy) {
        const resourceReq = unresolvedActions.length === req.actions.length ? req : { ...req, actions: unresolvedActions };
        resourceResult = resourcePolicy.check(resourceReq, this.#getImportedDerivedRoles(resourcePolicy, req), effectAsBoolean);
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

      if (resourceResult.effects.has(action)) {
        effects.set(action, resourceResult.effects.get(action));
        if (resourceResult.meta.actions[action]) actionsMeta[action] = resourceResult.meta.actions[action];
        continue;
      }

      effects.set(action, !effectAsBoolean ? Effect.Deny : false);
    }

    return {
      effects,
      outputs: new Map([
        ...principalResult.outputs.entries(),
        ...resourceResult.outputs.entries(),
      ]),
      meta: {
        actions: actionsMeta,
        effectiveDerivedRoles: resourceResult.meta.effectiveDerivedRoles ?? [],
      },
    };
  }

  #buildResponseResource(resource) {
    const responseResource = { id: resource.id, kind: resource.kind };
    if (resource.policyVersion) responseResource.policyVersion = resource.policyVersion;

    const normalizedScope = Kerberos.normalizeScope(resource.scope);
    if (normalizedScope) responseResource.scope = normalizedScope;

    return responseResource;
  }

  /**
   * Evaluates a single action against a resource.
   *
   * @param {Record<string, unknown>} args
   * @returns {Promise<boolean>}
   */
  async isAllowed(args) {
    const reqKind = 'IsAllowed';
    const startedAt = getNow();
    const callId = this.#getCallId();
    const reqId = args?.reqId;

    try {
      this.#logMethodStart(reqKind, callId, reqId);

      const parsedArgs = Kerberos.parseIsAllowedArgs(args, {
        schema: this.#isAllowedArgsValidator,
        z: this.#z,
        ajv: this.#ajv,
        typebox: this.#typebox,
      });

      const req = Kerberos.parseRequest(
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
        }
      );

      const { effects, outputs, meta } = this.#evaluatePolicySources(req);
      const isAllowed = effects.get(parsedArgs.action) === Effect.Allow || effects.get(ALL_ACTIONS) === Effect.Allow;

      this.#log([{ req, result: { effects, outputs, meta } }], reqKind, callId);

      return isAllowed;
    } catch (error) {
      this.#logMethodError(reqKind, callId, reqId, error);
      if (this.#logger.enabled) return false;
      throw error;
    } finally {
      this.#logMethodFinish(reqKind, callId, reqId, getNow() - startedAt);
    }
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
    const startedAt = getNow();
    const callId = this.#getCallId();
    const reqId = args?.reqId;

    try {
      this.#logMethodStart(reqKind, callId, reqId);

      const results = [];
      const inputForLog = [];
      const parsedArgs = Kerberos.parseCheckResourcesArgs(args, {
        schema: this.#checkResourcesArgsValidator,
        z: this.#z,
        ajv: this.#ajv,
        typebox: this.#typebox,
      });

      for (const { resource, actions } of parsedArgs.resources) {
        const req = Kerberos.parseRequest(
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
          }
        );

        const { effects, outputs, meta } = this.#evaluatePolicySources(req, effectAsBoolean);

        const result = {
          resource: this.#buildResponseResource(resource),
          actions: Object.fromEntries([...effects.entries()]),
          outputs: [...outputs.values()],
        };
        if (req.includeMeta) result.meta = meta;
        results.push(result);
        inputForLog.push({ req, result: { effects, outputs, meta } });
      }

      this.#log(inputForLog, reqKind, callId);

      const response = { results, kerberosCallId: callId };
      if (parsedArgs.reqId) response.reqId = parsedArgs.reqId;
      return response;
    } catch (error) {
      this.#logMethodError(reqKind, callId, reqId, error);
      if (this.#logger.enabled) return { results: [], kerberosCallId: callId, reqId };
      throw error;
    } finally {
      this.#logMethodFinish(reqKind, callId, reqId, getNow() - startedAt);
    }
  }
}

module.exports = {
  Kerberos,
  KerberosJsonSchemas,
  KerberosTypeBoxSchemas,
  KerberosZodSchemas,
};
