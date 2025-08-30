const { ResourcePolicy } = require('./ResourcePolicy/index.js');
const { DerivedRoles } = require('./DerivedRoles/index.js');
const { Outputs } = require('./Outputs/index.js');
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
    });
  }
}

// TODO: 1) scopes, 2) metadata
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

  constructor(policies, derivedRoles, { logger, z } = { logger: false, z: null }) {
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
        // TODO: enable output logging
        // const policy = this.#policies.get(reqWithActions.R.kind);
        // const output = result.outputs?.get(Outputs.buildSrc({
        //   version: policy.shape.resourcePolicy.version,
        //   name: policy.shape.resourcePolicy.name,
        //   kind: policy.kind,
        //   index: undefined,
        // }));

        logData.push({
          Timestamp: new Date().toISOString(),
          'Request kind': reqKind,
          'Principal ID': reqWithActions.P.id,
          'Resource kind': reqWithActions.R.kind,
          'Resource ID': reqWithActions.R.id,
          Action: action,
          Effect: result.effects.get(action),
          // Output: output?.val,
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
      const effect = result.effects.get(action);
      this.#logger.log?.(`Principal ${reqWithActions.P.id} is ${effect === Effect.Allow || effect === true ? 'ALLOWED' : 'DENIED'} to perform action ${action} on resource ${reqWithActions.R.id}`);
    }

    const logData = this.#buildLogData(input, reqKind);
    if (this.#logger.table) {
      this.#logger.table?.(logData);
    } else {
      this.#logger.debug?.(logData, `Kerberos.js request log`);
    }

    this.#logger.groupEnd?.();
  }

  async isAllowed(args) {
    const parsedArgs = Kerberos.parseIsAllowedArgs(args, { schema: this.#isAllowedArgsZodSchema, z: this.#z });
    const req = Kerberos.parseRequest(parsedArgs.principal, parsedArgs.resource, { schema: this.#requestZodSchema, z: this.#z });

    const policy = this.#policies.get(req.R.kind);
    const reqWithActions = { ...req, actions: [parsedArgs.action] };
    if (!policy) {
      const effects = new Map([[parsedArgs.action, Effect.Deny]]);
      this.#log([{ reqWithActions, result: { effects, outputs: new Map() } }], 'IsAllowed');
      return false;
    }

    const { effects, outputs } = policy.check(reqWithActions, this.#getImportedDerivedRoles(policy, req));
    const isAllowed = effects.get(parsedArgs.action) === Effect.Allow || effects.get(ALL_ACTIONS) === Effect.Allow;

    this.#log([{ reqWithActions: { ...req, actions: [parsedArgs.action] }, result: { effects, outputs } }], 'IsAllowed');

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
        const effects = new Map();
        const outputs = new Map();
        for (const action of actions) effects.set(action, !effectAsBoolean ? Effect.Deny : false);
        results.push({
          resource: { id: resource.id, kind: resource.kind },
          actions: Object.fromEntries([...effects.entries()]),
          outputs: [...outputs.values()],
        });
        inputForLog.push({ reqWithActions: { ...req, actions }, result: { effects, outputs } });
        continue;
      }

      const reqWithActions = { ...req, actions };
      const { effects, outputs } = policy.check(reqWithActions, this.#getImportedDerivedRoles(policy, req), effectAsBoolean);

      results.push({
        resource: { id: resource.id, kind: resource.kind },
        actions: Object.fromEntries([...effects.entries()]),
        outputs: [...outputs.values()],
      });
      inputForLog.push({ reqWithActions, result: { effects, outputs } });
    }

    this.#log(inputForLog, 'CheckResources');

    const response = { results };
    if (parsedArgs.reqId) response.reqId = parsedArgs.reqId;
    return response;
  }
}

module.exports = { Kerberos, KerberosZodSchemas };
