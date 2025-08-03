const { ResourcePolicy } = require('./ResourcePolicy/index.js');
const { DerivedRoles } = require('./DerivedRoles/index.js');
const { ALL_ACTIONS, Effect, ZodSchemas } = require('./schemas.js');

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
      principal: ZodSchemas.buildRequestPrincipal(z),
      resources: z
        .array(
          z.object({
            resource: ZodSchemas.buildRequestResource(z),
            actions: z.array(z.string()).nonempty(),
          })
        )
        .nonempty(),
    });
  }

  static buildCheckResourcesResponse(z) {
    return z.object({
      results: z
        .array(
          z.object({
            resource: ZodSchemas.buildRequestResource(z).pick({ id: true, kind: true }),
            actions: z.record(z.string(), z.union([z.nativeEnum(Effect), z.boolean()])),
          })
        )
        .nonempty(),
    });
  }
}

// TODO: 1) outputs, 2) scopes, 3) metadata
class Kerberos {
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

  static parseRequest(principal, resource, { schema, z } = {}) {
    if (schema) return schema.parse({ principal, resource, P: principal, R: resource });
    if (z) return ZodSchemas.buildRequest(z).parse({ principal, resource, P: principal, R: resource });
    return { principal, resource, P: principal, R: resource };
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

  static parseCheckResourcesResponse(response, { schema, z } = {}) {
    if (schema) return schema.parse(response);
    if (z) return KerberosZodSchemas.buildCheckResourcesResponse(z).parse(response);
    return response;
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

  #checkResourcesResponseZodSchema = null;

  constructor(policies, derivedRoles, { logger, z } = { logger: false, z: null }) {
    if (z) {
      this.#z = z;
      this.#resourcePolicyInstanceZodSchema = KerberosZodSchemas.buildResourcePolicyInstance(z);
      this.#derivedRolesInstanceZodSchema = KerberosZodSchemas.buildDerivedRolesInstance(z);
      this.#requestZodSchema = ZodSchemas.buildRequest(z);
      this.#isAllowedArgsZodSchema = KerberosZodSchemas.buildIsAllowedArgs(z);
      this.#checkResourcesArgsZodSchema = KerberosZodSchemas.buildCheckResourcesArgs(z);
      this.#checkResourcesResponseZodSchema = KerberosZodSchemas.buildCheckResourcesResponse(z);
    }

    this.#policies = this.#getPoliciesMap(policies);
    this.#derivedRoles = this.#getDerivedRolesMap(derivedRoles);

    if (typeof logger === 'object') this.#logger = logger;
    if (logger) this.#loggingEnabled = true;
  }

  #getPoliciesMap(policies) {
    const policiesMap = new Map();
    for (const policy of policies) {
      const handledPolicy = Kerberos.parsePolicy(policy, { schema: this.#resourcePolicyInstanceZodSchema, z: this.#z });
      policiesMap.set(handledPolicy.kind, handledPolicy);
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

  #buildLogData(input, reqKind) {
    const logData = [];
    for (const { reqWithActions, result } of input) {
      for (const action of reqWithActions.actions) {
        logData.push({
          Timestamp: new Date().toISOString(),
          'Request kind': reqKind,
          'Principal ID': reqWithActions.P.id,
          'Resource kind': reqWithActions.R.kind,
          'Resource ID': reqWithActions.R.id,
          Action: action,
          Effect: result[action],
        });
      }
    }
    return logData;
  }

  #log(input, reqKind) {
    if (!this.#loggingEnabled) return;

    this.#logger.group?.('Kerberos.js');

    if (reqKind === 'IsAllowed') {
      const [{ reqWithActions, result }] = input;
      const [action] = reqWithActions.actions;
      const effect = result[action];
      this.#logger.log?.(`Principal ${reqWithActions.P.id} is ${effect === Effect.Allow || effect === true ? 'ALLOWED' : 'DENIED'} to perform action ${action} on resource ${reqWithActions.R.id}`);
    }

    const debugData = this.#buildLogData(input, reqKind);
    if (this.#logger.table) {
      this.#logger.table?.(debugData);
    } else {
      this.#logger.debug?.(`Kerberos.js request log: ${JSON.stringify(debugData, null, 2)}`);
    }

    this.#logger.groupEnd?.();
  }

  async isAllowed(args) {
    const parsedArgs = Kerberos.parseIsAllowedArgs(args, { schema: this.#isAllowedArgsZodSchema, z: this.#z });
    const req = Kerberos.parseRequest(parsedArgs.principal, parsedArgs.resource, { schema: this.#requestZodSchema, z: this.#z });

    const policy = this.#policies.get(req.R.kind);
    const reqWithActions = { ...req, actions: [parsedArgs.action] };
    if (!policy) {
      this.#log([{ reqWithActions, result: { [parsedArgs.action]: Effect.Deny } }], 'IsAllowed');
      return false;
    }

    const result = policy.check(reqWithActions, this.#getImportedDerivedRoles(policy, req));
    const isAllowed = result.get(parsedArgs.action) === Effect.Allow || result.get(ALL_ACTIONS) === Effect.Allow;

    this.#log([{ reqWithActions: { ...req, actions: [parsedArgs.action] }, result: { [parsedArgs.action]: isAllowed ? Effect.Allow : Effect.Deny } }], 'IsAllowed');

    return isAllowed;
  }

  async checkResources(args, effectAsBoolean = false) {
    const results = [];
    const inputForLog = [];
    const parsedArgs = Kerberos.parseCheckResourcesArgs(args, { schema: this.#checkResourcesArgsZodSchema, z: this.#z });

    for (const { resource, actions } of parsedArgs.resources) {
      const req = Kerberos.parseRequest(parsedArgs.principal, resource, { schema: this.#requestZodSchema, z: this.#z });

      const policy = this.#policies.get(req.R.kind);
      if (!policy) {
        const actionsResult = {};
        for (const action of actions) actionsResult[action] = !effectAsBoolean ? Effect.Deny : false;
        results.push({ resource, actions: actionsResult });
        inputForLog.push({ reqWithActions: { ...req, actions }, result: actionsResult });
        continue;
      }

      const reqWithActions = { ...req, actions };
      const result = policy.check(reqWithActions, this.#getImportedDerivedRoles(policy, req), effectAsBoolean);

      const actionsResult = Object.fromEntries([...result.entries()]);
      results.push({ resource, actions: actionsResult });
      inputForLog.push({ reqWithActions, result: actionsResult });
    }

    this.#log(inputForLog, 'CheckResources');

    return Kerberos.parseCheckResourcesResponse({ results }, { schema: this.#checkResourcesResponseZodSchema, z: this.#z });
  }
}

module.exports = { Kerberos, KerberosZodSchemas };
