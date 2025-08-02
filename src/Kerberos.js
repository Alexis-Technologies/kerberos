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
    if (schema) return policy instanceof ResourcePolicy ? schema.parse(policy) : new ResourcePolicy(policy);
    if (z) return policy instanceof ResourcePolicy ? KerberosZodSchemas.buildResourcePolicyInstance(z).parse(policy) : new ResourcePolicy(policy);
    return policy instanceof ResourcePolicy ? policy : new ResourcePolicy(policy);
  }

  static parseDerivedRoles(roles, { schema, z } = {}) {
    if (schema) return roles instanceof DerivedRoles ? schema.parse(roles) : new DerivedRoles(roles);
    if (z) return roles instanceof DerivedRoles ? KerberosZodSchemas.buildDerivedRolesInstance(z).parse(roles) : new DerivedRoles(roles);
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

  static parseCheckResourcesResponse(response, effectAsBoolean = false, { schema, z } = {}) {
    if (schema) return schema.parse(response);
    if (z) return KerberosZodSchemas.buildCheckResourcesResponse(z).parse(response);
    return response;
  }

  static transformCheckResourcesResponse(response, effectAsBoolean = false) {
    return {
      ...response,
      results: response.results.map((r) => ({
        ...r,
        actions: Object.fromEntries(Object.entries(r.actions).map(([action, effect]) => [action, !effectAsBoolean ? effect : effect === Effect.Allow])),
      })),
    };
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
    return new Map(
      policies.map((policy) => {
        const handledPolicy = Kerberos.parsePolicy(policy, { schema: this.#resourcePolicyInstanceZodSchema });
        return [handledPolicy.kind, handledPolicy];
      })
    );
  }

  #getDerivedRolesMap(roles) {
    return (
      new Map(
        roles?.map((role) => {
          const handledRole = Kerberos.parseDerivedRoles(role, { schema: this.#derivedRolesInstanceZodSchema });
          return [handledRole.name, handledRole];
        })
      ) ?? new Map()
    );
  }

  #getImportedDerivedRoles(policy, req) {
    return policy.importDerivedRoles
      .map((name) => this.#derivedRoles.get(name))
      .filter((v) => !!v)
      .reduce((acc, curr) => new Set([...acc, ...curr.get(req)]), new Set());
  }

  #buildLogData(input, reqKind) {
    return input.flatMap(({ reqWithActions, result }) =>
      reqWithActions.actions.map((action) => ({
        Timestamp: new Date().toISOString(),
        'Request kind': reqKind,
        'Principal ID': reqWithActions.P.id,
        'Resource kind': reqWithActions.R.kind,
        'Resource ID': reqWithActions.R.id,
        Action: action,
        Effect: result[action],
      }))
    );
  }

  #log(input, reqKind) {
    if (!this.#loggingEnabled) return;

    this.#logger.group?.('Kerberos.js');

    if (reqKind === 'IsAllowed') {
      const [{ reqWithActions, result }] = input;
      const [action] = reqWithActions.actions;
      const effect = result[action];
      this.#logger.log?.(`Principal ${reqWithActions.P.id} is ${effect === Effect.Allow ? 'ALLOWED' : 'DENIED'} to perform action ${action} on resource ${reqWithActions.R.id}`);
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
    const parsedArgs = Kerberos.parseIsAllowedArgs(args, { schema: this.#isAllowedArgsZodSchema });
    const req = Kerberos.parseRequest(parsedArgs.principal, parsedArgs.resource, { schema: this.#requestZodSchema });

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
    const inputForLog = [];
    const parsedArgs = Kerberos.parseCheckResourcesArgs(args, { schema: this.#checkResourcesArgsZodSchema });
    const results = parsedArgs.resources.map(({ resource, actions }) => {
      const req = Kerberos.parseRequest(parsedArgs.principal, resource, { schema: this.#requestZodSchema });

      const policy = this.#policies.get(req.R.kind);
      if (!policy) {
        return {
          resource,
          actions: Object.fromEntries(actions.map((action) => [action, !effectAsBoolean ? Effect.Deny : false])),
        };
      }

      const reqWithActions = { ...req, actions };
      const result = policy.check(reqWithActions, this.#getImportedDerivedRoles(policy, req));

      const actionsResult = Object.fromEntries([...result.entries()]);
      inputForLog.push({ reqWithActions, result: actionsResult });

      return { resource, actions: actionsResult };
    });

    this.#log(inputForLog, 'CheckResources');

    return Kerberos.parseCheckResourcesResponse(Kerberos.transformCheckResourcesResponse({ results }));
  }
}

module.exports = { Kerberos, KerberosZodSchemas };
