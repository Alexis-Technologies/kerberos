export type ParseLikeValidator<T = unknown> = {
  parse(value: unknown): T;
};

export type ValidateLikeValidator<T = unknown> = {
  validate(value: unknown): T | boolean | void;
  message?: string;
};

export type CallableValidator<T = unknown> = ((value: unknown) => T | boolean | void) & {
  errors?: unknown;
};

export type ValidationSchema<T = unknown> =
  | ParseLikeValidator<T>
  | ValidateLikeValidator<T>
  | CallableValidator<T>
  | Record<string, unknown>;

export type AjvLike = {
  compile(schema: Record<string, unknown>): CallableValidator;
  addKeyword(config: Record<string, unknown>): unknown;
  getKeyword?(keyword: string): unknown;
};

export type TypeBoxLike = {
  String(options?: Record<string, unknown>): unknown;
  Object(properties: Record<string, unknown>, options?: Record<string, unknown>): unknown;
  Array(items: unknown, options?: Record<string, unknown>): unknown;
  Optional(schema: unknown): unknown;
  Record(key: unknown, value: unknown, options?: Record<string, unknown>): unknown;
  Unknown(options?: Record<string, unknown>): unknown;
  Union(items: unknown[], options?: Record<string, unknown>): unknown;
  Literal(value: string | boolean | number, options?: Record<string, unknown>): unknown;
  Unsafe(schema: Record<string, unknown>): unknown;
  Recursive(factory: (self: unknown) => unknown, options?: Record<string, unknown>): unknown;
  Boolean(options?: Record<string, unknown>): unknown;
  Intersect(items: unknown[], options?: Record<string, unknown>): unknown;
  Never(options?: Record<string, unknown>): unknown;
};

export type ValidationOptions = {
  schema?: ValidationSchema;
  z?: unknown;
  ajv?: AjvLike;
  typebox?: TypeBoxLike;
};

export type RequestPrincipal = {
  id: string;
  roles: string[];
  policyVersion?: string;
  scope?: string;
  attr?: Record<string, unknown>;
};

export type RequestResource = {
  id: string;
  kind: string;
  policyVersion?: string;
  scope?: string;
  attr?: Record<string, unknown>;
};

export type BaseRequest = {
  principal: RequestPrincipal;
  P: RequestPrincipal;
  resource: RequestResource;
  R: RequestResource;
  actions: string[];
  reqId?: string;
  callId?: string;
  includeMeta?: boolean;
};

export enum Effect {
  Allow = 'EFFECT_ALLOW',
  Deny = 'EFFECT_DENY',
}

export class ZodSchemas {
  static buildScopeString(z: unknown): unknown;
  static buildRequestPrincipal(z: unknown): unknown;
  static buildRequestResource(z: unknown): unknown;
  static buildRequest(z: unknown): unknown;
}

export class JsonSchemas {
  static buildScopeString(): Record<string, unknown>;
  static buildRequestPrincipal(): Record<string, unknown>;
  static buildRequestResource(): Record<string, unknown>;
  static buildRequest(): Record<string, unknown>;
}

export class TypeBoxSchemas {
  static buildScopeString(typebox: TypeBoxLike): unknown;
  static buildRequestPrincipal(typebox: TypeBoxLike): unknown;
  static buildRequestResource(typebox: TypeBoxLike): unknown;
  static buildRequest(typebox: TypeBoxLike): unknown;
}

type ConstantsSchema = Record<string, unknown>;
type RequestWithConstants = BaseRequest & Partial<{ C: ConstantsSchema; constants: ConstantsSchema }>;
export class Constants {
  constructor(schema: ConstantsSchema, options?: ValidationOptions);
  get(): ConstantsSchema;
}
export class ConstantsZodSchemas {
  static buildShape(z: unknown): unknown;
  static buildRequestWithConstants(z: unknown): unknown;
}
export class ConstantsJsonSchemas {
  static buildShape(): Record<string, unknown>;
  static buildRequestWithConstants(): Record<string, unknown>;
}
export class ConstantsTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
  static buildRequestWithConstants(typebox: TypeBoxLike): unknown;
}

type VariablesSchema = Record<string, (req: RequestWithConstants) => unknown>;
type RequestWithVariables = BaseRequest & Partial<{ V: Record<string, unknown>; variables: Record<string, unknown> }>;
export class Variables {
  constructor(schema: VariablesSchema, options?: ValidationOptions);
  get(req: RequestWithConstants): Record<string, unknown>;
}
export class VariablesZodSchemas {
  static buildShape(z: unknown): unknown;
  static buildRequestWithVariables(z: unknown): unknown;
}
export class VariablesJsonSchemas {
  static buildShape(): Record<string, unknown>;
  static buildRequestWithVariables(): Record<string, unknown>;
}
export class VariablesTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
  static buildRequestWithVariables(typebox: TypeBoxLike): unknown;
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
export type ConditionsSchema = {
  match: ConditionMatch;
};
export class Conditions {
  constructor(schema: ConditionsSchema, options?: ValidationOptions);
  isFulfilled(req: RequestWithConstants & RequestWithVariables, condition?: ConditionMatch): boolean;
}
export class ConditionsZodSchemas {
  static buildShape(z: unknown): unknown;
  static buildFullRequest(z: unknown): unknown;
}
export class ConditionsJsonSchemas {
  static buildShape(): Record<string, unknown>;
  static buildFullRequest(): Record<string, unknown>;
}
export class ConditionsTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
  static buildFullRequest(typebox: TypeBoxLike): unknown;
}

export type OutputsSchema =
  | {
      when: {
        ruleActivated?: (req: RequestWithConstants & RequestWithVariables) => unknown;
        conditionNotMet?: (req: RequestWithConstants & RequestWithVariables) => unknown;
      };
    }
  | ((req: RequestWithConstants & RequestWithVariables) => unknown);
export class Outputs {
  constructor(schema: OutputsSchema, options?: ValidationOptions);
  build(req: RequestWithConstants & RequestWithVariables, isConditionFulfilled: boolean, src: string): {
    src: string;
    val: unknown;
  };
}
export class OutputsZodSchemas {
  static buildShape(z: unknown): unknown;
}
export class OutputsJsonSchemas {
  static buildShape(): Record<string, unknown>;
}
export class OutputsTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
}

export class MetadataZodSchemas {
  static buildActionMetadata(z: unknown): unknown;
  static buildActionsMetadata(z: unknown): unknown;
  static buildShape(z: unknown): unknown;
}
export class MetadataJsonSchemas {
  static buildActionMetadata(): Record<string, unknown>;
  static buildActionsMetadata(): Record<string, unknown>;
  static buildShape(): Record<string, unknown>;
}
export class MetadataTypeBoxSchemas {
  static buildActionMetadata(typebox: TypeBoxLike): unknown;
  static buildActionsMetadata(typebox: TypeBoxLike): unknown;
  static buildShape(typebox: TypeBoxLike): unknown;
}

type DerivedRolesDefinition = {
  name: string;
  parentRoles: [string, ...string[]];
  condition: ConditionsSchema | Conditions;
};
export type DerivedRolesSchema = {
  name: string;
  description?: string;
  variables?: VariablesSchema | Variables;
  constants?: ConstantsSchema | Constants;
  definitions: [DerivedRolesDefinition, ...DerivedRolesDefinition[]];
};
export class DerivedRoles {
  constructor(schema: DerivedRolesSchema, options?: ValidationOptions);
  get(req: BaseRequest): Set<string>;
}
export class DerivedRolesZodSchemas {
  static buildShape(z: unknown): unknown;
}
export class DerivedRolesJsonSchemas {
  static buildShape(): Record<string, unknown>;
}
export class DerivedRolesTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
}

type BaseRule = {
  actions: [string, ...string[]];
  effect: Effect;
  condition?: ConditionsSchema | Conditions;
  output?: OutputsSchema | Outputs;
};
type RuleWithRoles = BaseRule & {
  roles: [string, ...string[]] | ['*'];
};
type RuleWithDerivedRoles = BaseRule & {
  derivedRoles: [string, ...string[]];
};
type Rule = RuleWithRoles | RuleWithDerivedRoles;
export type ResourcePolicySchema = {
  version: string;
  resource: string;
  scope?: string;
  rules: [Rule, ...Rule[]];
  variables?: VariablesSchema | Variables;
  constants?: ConstantsSchema | Constants;
  importDerivedRoles?: [string, ...string[]] | string[];
};
export type ResourcePolicyRootSchema = {
  resourcePolicy: ResourcePolicySchema;
};
export class ResourcePolicy {
  constructor(schema: ResourcePolicyRootSchema, options?: ValidationOptions);
  check(req: BaseRequest, derivedRoles: Set<string>, effectAsBoolean?: boolean): {
    effects: Map<string, Effect | boolean>;
    outputs: Map<string, unknown>;
    meta: {
      actions: Record<string, { matchedPolicy: string; matchedRule?: string; matchedScope?: string }>;
      effectiveDerivedRoles: string[];
    };
  };
}
export class ResourcePolicyZodSchemas {
  static buildShape(z: unknown): unknown;
}
export class ResourcePolicyJsonSchemas {
  static buildShape(): Record<string, unknown>;
}
export class ResourcePolicyTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
}

type PrincipalPolicyActionRuleSchema = {
  name?: string;
  action: string;
  effect: Effect;
  condition?: ConditionsSchema | Conditions;
  output?: OutputsSchema | Outputs;
};
type PrincipalPolicyRuleSchema = {
  resource: string;
  actions: [PrincipalPolicyActionRuleSchema, ...PrincipalPolicyActionRuleSchema[]];
};
export type PrincipalPolicySchema = {
  principal: string;
  version: string;
  scope?: string;
  rules: [PrincipalPolicyRuleSchema, ...PrincipalPolicyRuleSchema[]];
  variables?: VariablesSchema | Variables;
  constants?: ConstantsSchema | Constants;
};
export type PrincipalPolicyRootSchema = {
  principalPolicy: PrincipalPolicySchema;
};
export class PrincipalPolicy {
  constructor(schema: PrincipalPolicyRootSchema, options?: ValidationOptions);
  check(req: BaseRequest, effectAsBoolean?: boolean): {
    effects: Map<string, Effect | boolean>;
    outputs: Map<string, unknown>;
    meta: {
      actions: Record<string, { matchedPolicy: string; matchedRule?: string; matchedScope?: string }>;
      effectiveDerivedRoles: string[];
    };
  };
}
export class PrincipalPolicyZodSchemas {
  static buildShape(z: unknown): unknown;
}
export class PrincipalPolicyJsonSchemas {
  static buildShape(): Record<string, unknown>;
}
export class PrincipalPolicyTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
}

type RolePolicyRuleSchema = {
  name?: string;
  resource: string;
  allowActions: [string, ...string[]];
  condition?: ConditionsSchema | Conditions;
  output?: OutputsSchema | Outputs;
};
export type RolePolicySchema = {
  role: string;
  version: string;
  scope?: string;
  parentRoles?: [string, ...string[]] | string[];
  rules: [RolePolicyRuleSchema, ...RolePolicyRuleSchema[]];
  variables?: VariablesSchema | Variables;
  constants?: ConstantsSchema | Constants;
};
export type RolePolicyRootSchema = {
  rolePolicy: RolePolicySchema;
};
export class RolePolicy {
  constructor(schema: RolePolicyRootSchema, options?: ValidationOptions);
  check(req: BaseRequest, effectAsBoolean?: boolean): {
    effects: Map<string, Effect | boolean>;
    outputs: Map<string, unknown>;
    meta: {
      actions: Record<string, { matchedPolicy: string; matchedRule?: string; matchedScope?: string }>;
    };
  };
}
export class RolePolicyZodSchemas {
  static buildShape(z: unknown): unknown;
}
export class RolePolicyJsonSchemas {
  static buildShape(): Record<string, unknown>;
}
export class RolePolicyTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
}

type KerberosPolicy = ResourcePolicy | ResourcePolicyRootSchema | PrincipalPolicy | PrincipalPolicyRootSchema | RolePolicy | RolePolicyRootSchema;
type KerberosDerivedRoles = DerivedRoles | DerivedRolesSchema;
export type KerberosAuditLogEntry = {
  callId?: string;
  reqId?: string;
  timestamp: string;
  reqKind: string;
  principalId: string;
  principalScope?: string;
  principalPolicyVersion?: string;
  resourceKind: string;
  resourceId: string;
  resourceScope?: string;
  resourcePolicyVersion?: string;
  action: string;
  effect: Effect | boolean | string;
  outputs: unknown[];
  meta?: {
    actions: Record<string, {
      matchedPolicy: string;
      matchedRule?: string;
      matchedScope?: string;
    }>;
    effectiveDerivedRoles: string[];
  } | Record<string, unknown>;
};
export type KerberosMethodLogEntry = {
  event: string;
  reqKind: string;
  callId?: string;
  reqId?: string;
  duration?: number;
  errorName?: string;
  errorMessage?: string;
  stack?: string;
};
export type KerberosConsoleLogger = {
  group?(label?: string): void;
  log?(message?: unknown, ...args: unknown[]): void;
  table?(tabularData?: unknown, properties?: ReadonlyArray<string>): void;
  debug?(message?: unknown, ...args: unknown[]): void;
  error?(message?: unknown, ...args: unknown[]): void;
  groupEnd?(): void;
};
export type KerberosStructuredLogger = {
  child?(bindings: Record<string, unknown>): KerberosStructuredLogger;
  info?(entry: KerberosAuditLogEntry | KerberosMethodLogEntry, message?: string, ...args: unknown[]): void;
  debug?(entry: KerberosAuditLogEntry | KerberosMethodLogEntry, message?: string, ...args: unknown[]): void;
  error?(entry: KerberosAuditLogEntry | KerberosMethodLogEntry, message?: string, ...args: unknown[]): void;
};
export type KerberosLogger = KerberosConsoleLogger | KerberosStructuredLogger;

/**
 * Minimal cache contract. Any caching solution that exposes a `get(key)` method
 * (keyv, cacheable, cache-manager, ...) is accepted. Storage, TTL and multi-host
 * invalidation (CacheSync via qified) are delegated entirely to the cache;
 * Kerberos only ever reads dynamic policies via `get`.
 */
export type CacheLike = {
  get(key: string): unknown | Promise<unknown>;
};

/**
 * Pluggable codec used to (de)serialize dynamic policy documents stored in a
 * remote cache.
 *
 * Three usage modes (controlled by which fields you supply):
 *
 * 1. `{ jsep }` — pass a pre-configured jsep instance; Kerberos uses the
 *    built-in AST allowlist interpreter (no `eval` / `new Function`).
 * 2. `{ deserialize }` — fully custom deserialization function.
 * 3. Omit `codec` entirely — cached values are passed to policy constructors
 *    as-is (no `{ $expr }` transformation; assume plain JSON).
 */
export type PolicyExprDescriptor = { $expr: string };
export type PolicyCodec = {
  /** Pre-configured jsep callable (with plugins already registered). */
  jsep?: (expr: string) => unknown;
  serialize?(policyShape: unknown): unknown;
  deserialize?(jsonSafe: unknown): unknown;
  compileExpr?(expr: string): (ctx: Record<string, unknown>) => unknown;
  isExprDescriptor?(value: unknown): boolean;
};

export class KerberosExprError extends Error {
  name: 'KerberosExprError';
}

/**
 * Creates the built-in security-first policy codec.
 *
 * Requires a pre-configured `jsep` instance (analogous to how `ajv` is
 * passed to `new Kerberos(...)`). The caller is responsible for registering
 * any jsep plugins before passing the instance.
 *
 * ```ts
 * import jsep from 'jsep';
 * import jsepObject from '@jsep-plugin/object';
 * import jsepTernary from '@jsep-plugin/ternary';
 * import jsepNew from '@jsep-plugin/new';
 *
 * jsep.plugins.register(jsepObject, jsepTernary, jsepNew);
 * jsep.addUnaryOp('typeof');
 *
 * const codec = createSafeExprCodec({ jsep });
 * const kerberos = new Kerberos([], [], { cache, codec: { jsep } });
 * ```
 */
export function createSafeExprCodec(options: { jsep: (expr: string) => unknown; roots?: string[] }): PolicyCodec & {
  isExprDescriptor(value: unknown): boolean;
  compileExpr(expr: string): (ctx: Record<string, unknown>) => unknown;
  serialize(policyShape: unknown): unknown;
  deserialize(jsonSafe: unknown): unknown;
};

/**
 * Serializes a policy/derived-roles shape into a JSON-safe document.
 * Throws `KerberosExprError` if any raw JS function is encountered.
 * Pass `{ jsep }` to also validate each `{ $expr }` string via full AST parse.
 */
export function serializePolicy(shape: unknown, options?: { jsep?: (expr: string) => unknown }): unknown;

/**
 * Deserializes a JSON-safe policy/derived-roles document using the provided codec.
 * Requires `codec.deserialize` (e.g. from `createSafeExprCodec({ jsep })`).
 */
export function deserializePolicy(json: unknown, codec: PolicyCodec): unknown;

export type KerberosOptions = ValidationOptions & {
  logger?: KerberosLogger | boolean;
  cache?: CacheLike;
  codec?: PolicyCodec;
  getCallId?: () => string;
};

export class Kerberos {
  constructor(policies: KerberosPolicy[], derivedRoles: KerberosDerivedRoles[], options?: KerberosOptions);
  static generateCallId(): string;
  static normalizeScope(scope?: string): string;
  static getScopeSearchChain(scope?: string): string[];
  isAllowed(args: { principal: RequestPrincipal; resource: RequestResource; action: string }): Promise<boolean>;
  checkResources(
    args: {
      reqId?: string;
      principal: RequestPrincipal;
      resources: { resource: RequestResource; actions: string[] }[];
      includeMeta?: boolean;
    },
    effectAsBoolean?: boolean,
  ): Promise<{
    reqId?: string;
    kerberosCallId: string;
    results: {
      resource: Pick<RequestResource, 'id' | 'kind' | 'policyVersion' | 'scope'>;
      actions: Record<string, Effect | boolean>;
      outputs: unknown[];
      meta?: {
        actions: Record<string, {
          matchedPolicy: string;
          matchedRule?: string;
          matchedScope?: string;
        }>;
        effectiveDerivedRoles: string[];
      };
    }[];
  }>;
}
export class KerberosZodSchemas {
  static buildResourcePolicyInstance(z: unknown): unknown;
  static buildPrincipalPolicyInstance(z: unknown): unknown;
  static buildRolePolicyInstance(z: unknown): unknown;
  static buildDerivedRolesInstance(z: unknown): unknown;
  static buildIsAllowedArgs(z: unknown): unknown;
  static buildCheckResourcesArgs(z: unknown): unknown;
}
export class KerberosJsonSchemas {
  static buildResourcePolicyInstance(): Record<string, unknown>;
  static buildPrincipalPolicyInstance(): Record<string, unknown>;
  static buildRolePolicyInstance(): Record<string, unknown>;
  static buildDerivedRolesInstance(): Record<string, unknown>;
  static buildIsAllowedArgs(): Record<string, unknown>;
  static buildCheckResourcesArgs(): Record<string, unknown>;
}
export class KerberosTypeBoxSchemas {
  static buildResourcePolicyInstance(typebox: TypeBoxLike): unknown;
  static buildPrincipalPolicyInstance(typebox: TypeBoxLike): unknown;
  static buildRolePolicyInstance(typebox: TypeBoxLike): unknown;
  static buildDerivedRolesInstance(typebox: TypeBoxLike): unknown;
  static buildIsAllowedArgs(typebox: TypeBoxLike): unknown;
  static buildCheckResourcesArgs(typebox: TypeBoxLike): unknown;
}

export function registerAjvKeywords(ajv: AjvLike): AjvLike;
export function createAjvAdapter(ajv: AjvLike, schema: Record<string, unknown>): ParseLikeValidator;
export function toValidationAdapter(validator: ValidationSchema): ParseLikeValidator | null;
export function resolveValidationAdapter(options: {
  schema?: ValidationSchema;
  z?: unknown;
  ajv?: AjvLike;
  typebox?: TypeBoxLike;
  buildZod?: (z: unknown) => unknown;
  buildTypeBox?: (typebox: TypeBoxLike) => Record<string, unknown>;
  buildJson?: () => Record<string, unknown>;
}): ParseLikeValidator | null;
export function parseWithValidation(value: unknown, options: {
  schema?: ValidationSchema;
  z?: unknown;
  ajv?: AjvLike;
  typebox?: TypeBoxLike;
  buildZod?: (z: unknown) => unknown;
  buildTypeBox?: (typebox: TypeBoxLike) => Record<string, unknown>;
  buildJson?: () => Record<string, unknown>;
}): unknown;
