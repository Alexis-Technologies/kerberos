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

export namespace Tests {
  type PrincipalMockSchema = RequestPrincipal & { name: string };
  export class PrincipalMock {
    constructor(schema: PrincipalMockSchema);

    get id(): string;

    get name(): string;

    get roles(): string[];

    get attr(): Record<string, unknown>;
  }

  export class PrincipalsMock {
    constructor(schemas: [PrincipalMock, ...PrincipalMock[]] | Record<string, Omit<PrincipalMockSchema, 'name'>>);

    get mocks(): PrincipalMock[];

    get(name: string): PrincipalMock | undefined;
  }

  export type ResourceMockSchema = RequestResource & { name: string };
  export class ResourceMock {
    constructor(schema: ResourceMockSchema);

    get id(): string;

    get name(): string;

    get kind(): string;

    get attr(): Record<string, unknown>;
  }

  export class ResourcesMock {
    constructor(schemas: [ResourceMock, ...ResourceMock[]] | Record<string, Omit<ResourceMockSchema, 'name'>>);

    get mocks(): ResourceMock[];

    get(name: string): ResourceMock | undefined;

    getById(id: string): ResourceMock | undefined;
  }

  type Describe = (name: string, fn: () => void) => void;
  type It = (name: string, fn: () => void) => void;
  type Assert = {
    ok(value: unknown, message?: string): void;
    strictEqual(actual: unknown, expected: unknown, message?: string): void;
  };
  type KerberosTestInputSchema = {
    principals: PrincipalsMock | [string, ...string[]];
    resources: ResourcesMock | [string, ...string[]];
    actions: [string, ...string[]];
  };
  type KerberosTestExpectedItemSchema = {
    principal: PrincipalMock | string;
    resource: ResourceMock | string;
    actions: Record<string, Effect | boolean>;
  };
  export type KerberosTestSchema = {
    name: string;
    input: KerberosTestInputSchema;
    expected: [KerberosTestExpectedItemSchema, ...KerberosTestExpectedItemSchema[]];
  };
  export class KerberosTest {
    constructor(schema: KerberosTestSchema, kerberos?: Kerberos);

    run(
      { kerberos, principals, resources, effectAsBoolean }: { kerberos: Kerberos; principals: PrincipalsMock[]; resources: ResourcesMock[]; effectAsBoolean?: boolean },
      { describe, it, assert }: { describe: Describe; it: It; assert: Assert },
    ): void;
  }

  type TestsPolicySchema = {
    name: string;
    principals: PrincipalsMock | [PrincipalMockSchema, ...PrincipalMockSchema[]];
    resources: ResourcesMock | [ResourceMockSchema, ...ResourceMockSchema[]];
    tests: KerberosTest[] | KerberosTestSchema[];
  };
  export class KerberosTests {
    constructor(kerberos: Kerberos, policies: [TestsPolicySchema, ...TestsPolicySchema[]]);

    run({ effectAsBoolean }: { effectAsBoolean?: boolean }, { describe, it, assert }: { describe: Describe; it: It; assert: Assert }): void;
  }
}
