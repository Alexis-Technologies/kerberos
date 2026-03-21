const { ResourcePolicy } = require('./ResourcePolicy/index.js');
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
        buildJson: () => KerberosJsonSchemas.buildResourcePolicyInstance(),
        buildTypeBox: (t) => KerberosTypeBoxSchemas.buildResourcePolicyInstance(t),
        buildZod: (z) => KerberosZodSchemas.buildResourcePolicyInstance(z),
      });
    }
    const { schema, ...nestedOptions } = options;
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

  #policies = new Map();

  #derivedRoles = new Map();

  #logger = createLoggerWriter(false);

  #z = null;

  #ajv = null;

  #typebox = null;

  #resourcePolicyValidator = null;

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
      this.#derivedRolesValidator = KerberosZodSchemas.buildDerivedRolesInstance(z);
      this.#requestValidator = ZodSchemas.buildRequest(z);
      this.#isAllowedArgsValidator = KerberosZodSchemas.buildIsAllowedArgs(z);
      this.#checkResourcesArgsValidator = KerberosZodSchemas.buildCheckResourcesArgs(z);
    } else if (this.#ajv && this.#typebox) {
      this.#resourcePolicyValidator = createAjvAdapter(this.#ajv, KerberosTypeBoxSchemas.buildResourcePolicyInstance(this.#typebox));
      this.#derivedRolesValidator = createAjvAdapter(this.#ajv, KerberosTypeBoxSchemas.buildDerivedRolesInstance(this.#typebox));
      this.#requestValidator = createAjvAdapter(this.#ajv, TypeBoxSchemas.buildRequest(this.#typebox));
      this.#isAllowedArgsValidator = createAjvAdapter(this.#ajv, KerberosTypeBoxSchemas.buildIsAllowedArgs(this.#typebox));
      this.#checkResourcesArgsValidator = createAjvAdapter(this.#ajv, KerberosTypeBoxSchemas.buildCheckResourcesArgs(this.#typebox));
    } else if (this.#ajv) {
      this.#resourcePolicyValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildResourcePolicyInstance());
      this.#derivedRolesValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildDerivedRolesInstance());
      this.#requestValidator = createAjvAdapter(this.#ajv, JsonSchemas.buildRequest());
      this.#isAllowedArgsValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildIsAllowedArgs());
      this.#checkResourcesArgsValidator = createAjvAdapter(this.#ajv, KerberosJsonSchemas.buildCheckResourcesArgs());
    }

    this.#policies = this.#getPoliciesMap(policies);
    this.#derivedRoles = this.#getDerivedRolesMap(derivedRoles);

    this.#logger = createLoggerWriter(logger);
    if (typeof getCallId === 'function') this.#getCallId = getCallId;
  }

  #getPoliciesMap(policies) {
    const policiesMap = new Map();
    for (const policy of policies) {
      const handledPolicy = Kerberos.parsePolicy(policy, {
        schema: this.#resourcePolicyValidator,
        z: this.#z,
        ajv: this.#ajv,
        typebox: this.#typebox,
      });
      policiesMap.set(`${handledPolicy.kind}.${handledPolicy.version}.${handledPolicy.scope ?? ''}`, handledPolicy);
    }
    return policiesMap;
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

  #getPolicy(req) {
    const scopeSearchChain = Kerberos.getScopeSearchChain(req.R.scope);
    const version = req.R.policyVersion ?? 'default';

    for (const scope of scopeSearchChain) {
      const policy = this.#policies.get(`${req.R.kind}.${version}.${scope}`);
      if (policy) return policy;
    }
    return null;
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
    const callId = this.#getCallId();
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

    const policy = this.#getPolicy(req);
    if (!policy) {
      const effects = new Map([[parsedArgs.action, Effect.Deny]]);
      const outputs = new Map();
      const meta = { actions: {}, effectiveDerivedRoles: [] };
      this.#log([{ req, result: { effects, outputs, meta } }], 'IsAllowed', callId);
      return false;
    }

    const { effects, outputs, meta } = policy.check(req, this.#getImportedDerivedRoles(policy, req));
    const isAllowed = effects.get(parsedArgs.action) === Effect.Allow || effects.get(ALL_ACTIONS) === Effect.Allow;

    this.#log([{ req, result: { effects, outputs, meta } }], 'IsAllowed', callId);

    return isAllowed;
  }

  /**
   * Evaluates a set of resources and actions in a single request.
   *
   * @param {Record<string, unknown>} args
   * @param {boolean} [effectAsBoolean=false]
   * @returns {Promise<{ results: unknown[], kerberosCallId: string, reqId?: string }>}
   */
  async checkResources(args, effectAsBoolean = false) {
    const callId = this.#getCallId();
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

      const policy = this.#getPolicy(req);
      if (!policy) {
        const effects = new Map();
        const outputs = new Map();
        const meta = { actions: {}, effectiveDerivedRoles: [] };
        for (const action of actions) effects.set(action, !effectAsBoolean ? Effect.Deny : false);
        const result = {
          resource: this.#buildResponseResource(resource),
          actions: Object.fromEntries([...effects.entries()]),
          outputs: [...outputs.values()],
        };
        if (req.includeMeta) result.meta = meta;
        results.push(result);
        inputForLog.push({ req, result: { effects, outputs, meta } });
        continue;
      }

      const { effects, outputs, meta } = policy.check(req, this.#getImportedDerivedRoles(policy, req), effectAsBoolean);

      const result = {
        resource: this.#buildResponseResource(resource),
        actions: Object.fromEntries([...effects.entries()]),
        outputs: [...outputs.values()],
      };
      if (req.includeMeta) result.meta = meta;
      results.push(result);
      inputForLog.push({ req, result: { effects, outputs, meta } });
    }

    this.#log(inputForLog, 'CheckResources', callId);

    const response = { results, kerberosCallId: callId };
    if (parsedArgs.reqId) response.reqId = parsedArgs.reqId;
    return response;
  }
}

module.exports = {
  Kerberos,
  KerberosJsonSchemas,
  KerberosTypeBoxSchemas,
  KerberosZodSchemas,
};
