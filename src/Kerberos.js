const { ResourcePolicy } = require('./ResourcePolicy/index.js');
const { DerivedRoles } = require('./DerivedRoles/index.js');
const { ALL_ACTIONS, Effect, ZodSchemas } = require('./schemas.js');

// Import crypto for Node.js environment
let nodeCrypto;
try {
  nodeCrypto = require('crypto');
} catch (error) {
  // Ignore error, will fall back to browser crypto or manual generation
}

class KerberosZodSchemas extends ZodSchemas {
  static buildResourcePolicyInstance(z) {
    return z.instanceof(ResourcePolicy);
  }

  static buildDerivedRolesInstance(z) {
    return z.instanceof(DerivedRoles);
  }

  static buildIsAllowedArgs(z) {
    return z.object({
      principal: ZodSchemas.buildRequestPrincipal(z),
      action: z.string(),
      resource: ZodSchemas.buildRequestResource(z),
    });
  }

  static buildCheckResourcesArgs(z) {
    return z.object({
      reqId: z.string().optional(),
      principal: ZodSchemas.buildRequestPrincipal(z),
      resources: z
        .array(
          z.object({
            resource: ZodSchemas.buildRequestResource(z),
            actions: z.array(z.string()).nonempty(),
          })
        )
        .nonempty(),
      includeMeta: z.boolean().optional(),
    });
  }
}

class Kerberos {
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

  static normalizeScope(scope) {
    if (scope === '.') return '';
    return scope ?? '';
  }

  static getScopeSearchChain(scope) {
    const normalizedScope = Kerberos.normalizeScope(scope);
    if (!normalizedScope) return [''];

    const segments = normalizedScope.split('.');
    const searchChain = [];

    for (let i = segments.length; i > 0; i--) searchChain.push(segments.slice(0, i).join('.'));
    searchChain.push('');

    return searchChain;
  }

  static parsePolicy(policy, { schema, z } = {}) {
    if (schema) return policy instanceof ResourcePolicy ? schema.parse(policy) : new ResourcePolicy(policy, { z });
    if (z) return policy instanceof ResourcePolicy ? KerberosZodSchemas.buildResourcePolicyInstance(z).parse(policy) : new ResourcePolicy(policy, { z });
    return policy instanceof ResourcePolicy ? policy : new ResourcePolicy(policy);
  }

  static parseDerivedRoles(roles, { schema, z } = {}) {
    if (schema) return roles instanceof DerivedRoles ? schema.parse(roles) : new DerivedRoles(roles, { z });
    if (z) return roles instanceof DerivedRoles ? KerberosZodSchemas.buildDerivedRolesInstance(z).parse(roles) : new DerivedRoles(roles, { z });
    return roles instanceof DerivedRoles ? roles : new DerivedRoles(roles);
  }

  static parseRequest({ principal, resource, actions, reqId, callId, includeMeta }, { schema, z } = {}) {
    if (schema) return schema.parse({ principal, resource, P: principal, R: resource, actions, reqId, callId, includeMeta });
    if (z) return ZodSchemas.buildRequest(z).parse({ principal, resource, P: principal, R: resource, actions, reqId, callId, includeMeta });
    return { principal, resource, P: principal, R: resource, actions, reqId, callId, includeMeta };
  }

  static parseIsAllowedArgs(args, { schema, z } = {}) {
    if (schema) return schema.parse(args);
    if (z) return KerberosZodSchemas.buildIsAllowedArgs(z).parse(args);
    return args;
  }

  static parseCheckResourcesArgs(args, { schema, z } = {}) {
    if (schema) return schema.parse(args);
    if (z) return KerberosZodSchemas.buildCheckResourcesArgs(z).parse(args);
    return args;
  }

  #policies = new Map();

  #derivedRoles = new Map();

  #logger = console;

  #loggingEnabled = false;

  #z = null;

  #resourcePolicyInstanceZodSchema = null;

  #derivedRolesInstanceZodSchema = null;

  #requestZodSchema = null;

  #isAllowedArgsZodSchema = null;

  #checkResourcesArgsZodSchema = null;

  #getCallId = null;

  constructor(policies, derivedRoles, { logger, z, getCallId } = { logger: false, z: null, getCallId: null }) {
    this.#getCallId = Kerberos.generateCallId;

    if (z) {
      this.#z = z;
      this.#resourcePolicyInstanceZodSchema = KerberosZodSchemas.buildResourcePolicyInstance(z);
      this.#derivedRolesInstanceZodSchema = KerberosZodSchemas.buildDerivedRolesInstance(z);
      this.#requestZodSchema = ZodSchemas.buildRequest(z);
      this.#isAllowedArgsZodSchema = KerberosZodSchemas.buildIsAllowedArgs(z);
      this.#checkResourcesArgsZodSchema = KerberosZodSchemas.buildCheckResourcesArgs(z);
    }

    this.#policies = this.#getPoliciesMap(policies);
    this.#derivedRoles = this.#getDerivedRolesMap(derivedRoles);

    if (typeof logger === 'object') this.#logger = logger;
    if (logger) this.#loggingEnabled = true;
    if (typeof getCallId === 'function') this.#getCallId = getCallId;
  }

  #getPoliciesMap(policies) {
    const policiesMap = new Map();
    for (const policy of policies) {
      const handledPolicy = Kerberos.parsePolicy(policy, { schema: this.#resourcePolicyInstanceZodSchema, z: this.#z });
      policiesMap.set(`${handledPolicy.kind}.${handledPolicy.version}.${handledPolicy.scope ?? ''}`, handledPolicy);
    }
    return policiesMap;
  }

  #getDerivedRolesMap(roles) {
    const derivedRolesMap = new Map();
    if (!roles) return derivedRolesMap;
    for (const role of roles) {
      const handledRole = Kerberos.parseDerivedRoles(role, { schema: this.#derivedRolesInstanceZodSchema, z: this.#z });
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

  #buildLogData(input, reqKind, callId) {
    const logData = { table: [], json: [] };
    for (const { req, result } of input) {
      for (const action of req.actions) {
        const logEntry = {
          callId,
          reqId: req.reqId,
          timestamp: new Date().toISOString(),
          reqKind,
          principalId: req.P.id,
          principalScope: req.P.scope,
          principalPolicyVersion: req.P.policyVersion,
          resourceKind: req.R.kind,
          resourceId: req.R.id,
          resourceScope: req.R.scope,
          resourcePolicyVersion: req.R.policyVersion,
          action,
          effect: result.effects.get(action),
          outputs: result.outputs ? [...result.outputs.values()] : [],
          meta: result.meta,
        };

        if (!logEntry.callId) delete logEntry.callId;
        if (!logEntry.reqId) delete logEntry.reqId;
        if (!logEntry.principalScope) delete logEntry.principalScope;
        if (!logEntry.principalPolicyVersion) delete logEntry.principalPolicyVersion;
        if (!logEntry.resourceScope) delete logEntry.resourceScope;
        if (!logEntry.resourcePolicyVersion) delete logEntry.resourcePolicyVersion;
        if (!logEntry.meta) delete logEntry.meta;

        logData.json.push(logEntry);

        const logEntryForTable = { ...logEntry };

        const exludedForTable = ['reqId', 'principalScope', 'principalPolicyVersion', 'resourceScope', 'resourcePolicyVersion', 'outputs', 'meta'];
        const readableHeadersMap = {
          callId: 'Call ID',
          reqId: 'Request ID',
          timestamp: 'Timestamp',
          reqKind: 'Request kind',
          principalId: 'Principal ID',
          principalScope: 'Principal Scope',
          principalPolicyVersion: 'Principal Policy Version',
          resourceKind: 'Resource kind',
          resourceId: 'Resource ID',
          resourceScope: 'Resource Scope',
          resourcePolicyVersion: 'Resource Policy Version',
          action: 'Action',
          effect: 'Effect',
          outputs: 'Outputs',
          meta: 'Meta',
        };

        for (const key of Object.keys(logEntryForTable)) {
          if (exludedForTable.includes(key)) delete logEntryForTable[key];
          else {
            logEntryForTable[readableHeadersMap[key]] = logEntryForTable[key];
            delete logEntryForTable[key];
          }
        }

        logData.table.push(logEntryForTable);
      }
    }
    return logData;
  }

  #log(input, reqKind, callId) {
    if (!this.#loggingEnabled) return;

    this.#logger.group?.('Kerberos.js');

    if (reqKind === 'IsAllowed') {
      const [{ req, result }] = input;
      const [action] = req.actions;
      const effect = result.effects.get(action);
      this.#logger.log?.(`Principal ${req.P.id} is ${effect === Effect.Allow || effect === true ? 'ALLOWED' : 'DENIED'} to perform action ${action} on resource ${req.R.id}`);
    }

    const logData = this.#buildLogData(input, reqKind, callId);
    this.#logger.table?.(logData.table);
    if (this.#logger.debug) {
      for (const logEntry of logData.json) this.#logger.debug?.(logEntry, `Kerberos.js request log`);
    }

    this.#logger.groupEnd?.();
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

  async isAllowed(args) {
    const callId = this.#getCallId();
    const parsedArgs = Kerberos.parseIsAllowedArgs(args, { schema: this.#isAllowedArgsZodSchema, z: this.#z });
    const req = Kerberos.parseRequest(
      {
        principal: parsedArgs.principal,
        resource: parsedArgs.resource,
        actions: [parsedArgs.action],
        reqId: parsedArgs.reqId,
        callId,
        includeMeta: parsedArgs.includeMeta,
      },
      { schema: this.#requestZodSchema, z: this.#z }
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

  async checkResources(args, effectAsBoolean = false) {
    const callId = this.#getCallId();
    const results = [];
    const inputForLog = [];
    const parsedArgs = Kerberos.parseCheckResourcesArgs(args, { schema: this.#checkResourcesArgsZodSchema, z: this.#z });

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
        { schema: this.#requestZodSchema, z: this.#z }
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

module.exports = { Kerberos, KerberosZodSchemas };
