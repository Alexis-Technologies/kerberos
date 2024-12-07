export type RequestPrincipal = {
  id: string;
  roles: string[];
  attr: Record<string, unknown>;
};

export type RequestResource = {
  name: string;
  id: string;
  kind: string;
  attr: Record<string, unknown>;
};

export type BaseRequest = {
  principal: RequestPrincipal;
  P: RequestPrincipal;
  resource: RequestResource;
  R: RequestResource;
};

export enum Effect {
  Allow = 'EFFECT_ALLOW',
  Deny = 'EFFECT_DENY',
}

type ConstantsSchema = Record<string, unknown>;
type RequestWithConstants = BaseRequest & Partial<{ C: ConstantsSchema; constants: ConstantsSchema }>;
export class Constants {
  constructor(schema: ConstantsSchema);
}

type VariablesSchema = Record<string, (req: RequestWithConstants) => unknown>;
type RequestWithVariables = BaseRequest & Partial<{ V: VariablesSchema; variables: VariablesSchema }>;
export class Variables {
  constructor(schema: VariablesSchema);
}

type ConditionSingleMatchExpression = (req: RequestWithConstants & RequestWithVariables) => boolean;
type ConditionMatch =
  | ConditionSingleMatchExpression
  | {
      any: [ConditionMatch, ...ConditionMatch[]];
    }
  | {
      all: [ConditionMatch, ...ConditionMatch[]];
    }
  | {
      none: [ConditionMatch, ...ConditionMatch[]];
    };
type ConditionsSchema = {
  match: ConditionMatch;
};
export class Conditions {
  constructor(schema: ConditionsSchema);
}

type DerivedRolesDefinition = {
  name: string;
  parentRoles: [string, ...string[]];
  condition: ConditionsSchema | Conditions;
};
type DerivedRolesSchema = {
  name: string;
  description?: string;
  variables?: VariablesSchema | Variables;
  constants?: ConstantsSchema | Constants;
  definitions: [DerivedRolesDefinition, ...DerivedRolesDefinition[]];
};
export class DerivedRoles {
  constructor(schema: DerivedRolesSchema);
}

type BaseRule = {
  actions: [string, ...string[]];
  effect: Effect;
  condition?: ConditionsSchema | Conditions;
};
type RuleWithRoles = BaseRule & {
  roles: [string, ...string[]] | ['*'];
};
type RuleWithDerivedRoles = BaseRule & {
  derivedRoles: [string, ...string[]];
};
type Rule = RuleWithRoles | RuleWithDerivedRoles;
type ResourcePolicySchema = {
  version: string;
  resource: string;
  rules: [Rule, ...Rule[]];
  variables?: VariablesSchema | Variables;
  constants?: ConstantsSchema | Constants;
  importDerivedRoles?: [string, ...string[]];
};
type ResourcePolicyRootSchema = {
  resourcePolicy: ResourcePolicySchema;
};
export class ResourcePolicy {
  constructor(schema: ResourcePolicyRootSchema);
}

type KerberosPolicy = ResourcePolicy | ResourcePolicyRootSchema;
type KerberosDerivedRoles = DerivedRoles | DerivedRolesSchema;
type KerberosOptions = {
  logger?: Partial<Console> | boolean;
};
export class Kerberos {
  constructor(policies: [KerberosPolicy, ...KerberosPolicy[]], derivedRoles: [KerberosDerivedRoles, ...KerberosDerivedRoles[]], options?: KerberosOptions);

  isAllowed(args: { principal: RequestPrincipal; resource: RequestResource; action: string }): boolean;

  checkResources(
    args: { principal: RequestPrincipal; resources: { resource: RequestResource; actions: string[] }[] },
    effectAsBoolean?: boolean,
  ): {
    results: { resource: Pick<RequestResource, 'id' | 'kind'>; actions: Record<string, typeof effectAsBoolean extends true ? boolean : Effect> }[];
  };
}
