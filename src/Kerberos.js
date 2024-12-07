import { z } from 'zod';

import { ResourcePolicy } from './ResourcePolicy/index.js';
import { DerivedRoles } from './DerivedRoles/index.js';
import { RequestSchema, RequestPrincipalSchema, RequestResourceSchema, Effect } from './schemas.js';

const ResourcePolicyInstanceSchema = z.instanceof(ResourcePolicy);
const DerivedRolesInstanceSchema = z.instanceof(DerivedRoles);
const IsAllowedArgsSchema = z.object({
  principal: RequestPrincipalSchema,
  action: z.string(),
  resource: RequestResourceSchema,
});
const CheckResourcesArgsSchema = z.object({
  principal: RequestPrincipalSchema,
  resources: z
    .array(
      z.object({
        resource: RequestResourceSchema,
        actions: z.array(z.string()).nonempty(),
      })
    )
    .nonempty(),
});
const CheckResourcesResponseSchema = z.object({
  results: z
    .array(
      z.object({
        resource: RequestResourceSchema.pick({ id: true, kind: true }),
        actions: z.record(z.string(), z.union([z.nativeEnum(Effect), z.boolean()])),
      })
    )
    .nonempty(),
});

// TODO: 1) outputs, 2) scopes, 3) metadata
export class Kerberos {
  static parsePolicy(policy) {
    return policy instanceof ResourcePolicy ? ResourcePolicyInstanceSchema.parse(policy) : new ResourcePolicy(policy);
  }

  static parseDerivedRoles(roles) {
    return roles instanceof DerivedRoles ? DerivedRolesInstanceSchema.parse(roles) : new DerivedRoles(roles);
  }

  static parseRequest(principal, resource) {
    return RequestSchema.parse({ principal, resource, P: principal, R: resource });
  }

  #logger = console;

  #loggingEnabled = false;

  constructor(policies, derivedRoles, { logger } = { logger: false }) {
    this.policies = this.getPoliciesMap(policies);
    this.derivedRoles = this.getDerivedRolesMap(derivedRoles);
    if (typeof logger === 'object') this.#logger = logger;
    if (logger) this.#loggingEnabled = true;
  }

  getPoliciesMap(policies) {
    return new Map(
      policies.map((policy) => {
        const handledPolicy = Kerberos.parsePolicy(policy);
        return [handledPolicy.kind, handledPolicy];
      })
    );
  }

  getDerivedRolesMap(roles) {
    return (
      new Map(
        roles?.map((role) => {
          const handledRole = Kerberos.parseDerivedRoles(role);
          return [handledRole.name, handledRole];
        })
      ) ?? new Map()
    );
  }

  getImportedDerivedRoles(policy, req) {
    return policy.importDerivedRoles
      .map((name) => this.derivedRoles.get(name))
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

  log(input, reqKind) {
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

  isAllowed(args) {
    const parsedArgs = IsAllowedArgsSchema.parse(args);
    const req = Kerberos.parseRequest(parsedArgs.principal, parsedArgs.resource);

    const policy = this.policies.get(req.R.kind);
    if (!policy) return false;

    const isAllowed = policy.isAllowed({ ...req, action: parsedArgs.action }, this.getImportedDerivedRoles(policy, req));
    this.log([{ reqWithActions: { ...req, actions: [parsedArgs.action] }, result: { [parsedArgs.action]: isAllowed ? Effect.Allow : Effect.Deny } }], 'IsAllowed');
    return isAllowed;
  }

  checkResources(args, effectAsBoolean = false) {
    const inputForLog = [];
    const parsedArgs = CheckResourcesArgsSchema.parse(args);
    const results = parsedArgs.resources.map(({ resource, actions }) => {
      const req = Kerberos.parseRequest(parsedArgs.principal, resource);

      const policy = this.policies.get(req.R.kind);
      if (!policy) {
        return {
          resource,
          actions: Object.fromEntries(actions.map((action) => [action, !effectAsBoolean ? Effect.Deny : false])),
        };
      }

      const reqWithActions = { ...req, actions };
      const result = policy.check(reqWithActions, this.getImportedDerivedRoles(policy, req));

      const actionsResult = Object.fromEntries([...result.entries()]);
      inputForLog.push({ reqWithActions, result: actionsResult });

      return { resource, actions: actionsResult };
    });

    this.log(inputForLog, 'CheckResources');

    return CheckResourcesResponseSchema.transform((value) => {
      return {
        ...value,
        results: value.results.map((r) => ({
          ...r,
          actions: Object.fromEntries(Object.entries(r.actions).map(([action, effect]) => [action, !effectAsBoolean ? effect : effect === Effect.Allow])),
        })),
      };
    }).parse({ results });
  }
}
