/** Non-empty array that accepts both mutable and `as const` readonly literals. */
export type NonEmptyArray<T> = readonly [T, ...readonly T[]];

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

/* -------------------------------------------------------------------------- *
 * Typed authoring
 *
 * Every public policy/request type below is generic over an optional
 * application schema `S` naming the resource kinds, the actions each kind
 * supports, their attribute bags, and the principal's roles/attributes. All
 * parameters default to `AnySchema`, which reproduces the untyped
 * (`string` / `Record<string, unknown>`) surface verbatim — declaring a schema
 * is purely opt-in and changes nothing at runtime.
 *
 * ```ts
 * type AppSchema = {
 *   principal: { roles: 'admin' | 'user'; attr: { department: string } };
 *   resources: {
 *     document: { actions: 'view' | 'edit'; attr: { ownerId: string } };
 *     invoice: { actions: 'view' | 'approve'; attr: { amount: number } };
 *   };
 * };
 *
 * const kerberos = new Kerberos<AppSchema>(policies, derivedRoles);
 * await kerberos.isAllowed({
 *   principal: { id: 'u1', roles: ['admin'], attr: { department: 'eng' } },
 *   resource: { kind: 'document', id: 'd1', attr: { ownerId: 'u1' } },
 *   action: 'view', // ← checked against `document`'s actions, not `invoice`'s
 * });
 * ```
 * -------------------------------------------------------------------------- */

/** One resource kind's contract: the actions it supports and its attribute bag. */
export type KerberosResourceContract = {
  actions?: string;
  attr?: Record<string, unknown>;
};

/** An application's authorization domain — the type argument of {@link Kerberos}. */
export type KerberosSchema = {
  principal?: { roles?: string; attr?: Record<string, unknown> };
  resources?: Record<string, KerberosResourceContract>;
};

/** The permissive default: any resource kind, any action, any attribute. */
export type AnySchema = {
  principal: { roles: string; attr: Record<string, unknown> };
  resources: Record<string, { actions: string; attr: Record<string, unknown> }>;
};

type ResourcesOf<S extends KerberosSchema> = S extends {
  resources: infer R extends Record<string, KerberosResourceContract>;
}
  ? R
  : AnySchema['resources'];

/** Resource kinds declared by the schema (`string` when untyped). */
export type ResourceKindOf<S extends KerberosSchema = AnySchema> = keyof ResourcesOf<S> & string;

/** Actions valid for one resource kind (`string` when untyped). */
export type ActionOf<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = ResourcesOf<S>[K & keyof ResourcesOf<S>] extends { actions: infer A extends string } ? A : string;

/** Attribute bag of one resource kind (`Record<string, unknown>` when untyped). */
export type ResourceAttrOf<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = ResourcesOf<S>[K & keyof ResourcesOf<S>] extends { attr: infer A extends Record<string, unknown> }
  ? A
  : Record<string, unknown>;

/** Roles the schema's principals may carry (`string` when untyped). */
export type PrincipalRoleOf<S extends KerberosSchema = AnySchema> = S extends {
  principal: { roles: infer R extends string };
}
  ? R
  : string;

/** Attribute bag of the schema's principals (`Record<string, unknown>` when untyped). */
export type PrincipalAttrOf<S extends KerberosSchema = AnySchema> = S extends {
  principal: { attr: infer A extends Record<string, unknown> };
}
  ? A
  : Record<string, unknown>;

export type RequestPrincipal<S extends KerberosSchema = AnySchema> = {
  id: string;
  roles: PrincipalRoleOf<S>[];
  policyVersion?: string;
  scope?: string;
  attr?: PrincipalAttrOf<S>;
};

export type RequestResource<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = {
  id: string;
  kind: K;
  policyVersion?: string;
  scope?: string;
  attr?: ResourceAttrOf<S, K>;
};

export type BaseRequest<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = {
  principal: RequestPrincipal<S>;
  P: RequestPrincipal<S>;
  resource: RequestResource<S, K>;
  R: RequestResource<S, K>;
  actions: ActionOf<S, K>[];
  reqId?: string;
  callId?: string;
  includeMeta?: boolean;
};

/**
 * Policy rule effects. Declared as a frozen const object (not a TypeScript
 * `enum`) so that plain JSON policy literals — `effect: 'EFFECT_ALLOW'` — are
 * assignable to the `Effect` type, which is what stored/serialized policies
 * actually contain. `Effect.Allow` keeps working as before.
 */
export declare const Effect: {
  readonly Allow: 'EFFECT_ALLOW';
  readonly Deny: 'EFFECT_DENY';
};
export type Effect = 'EFFECT_ALLOW' | 'EFFECT_DENY';

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
type RequestWithConstants<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = BaseRequest<S, K> & Partial<{ C: ConstantsSchema; constants: ConstantsSchema }>;
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

type VariablesSchema<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = Record<string, (req: RequestWithConstants<S, K>) => unknown>;
type RequestWithVariables<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = BaseRequest<S, K> & Partial<{ V: Record<string, unknown>; variables: Record<string, unknown> }>;
export class Variables<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> {
  constructor(schema: VariablesSchema<S, K>, options?: ValidationOptions);
  get(req: RequestWithConstants<S, K>): Record<string, unknown>;
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

/** The `{ P, R, V, C, ... }` envelope handed to condition/variable/output callbacks. */
export type PolicyEvalRequest<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = RequestWithConstants<S, K> & RequestWithVariables<S, K>;

type ConditionSingleMatchExpression<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = (req: PolicyEvalRequest<S, K>) => boolean;
type ConditionMatch<S extends KerberosSchema = AnySchema, K extends ResourceKindOf<S> = ResourceKindOf<S>> =
  | ConditionSingleMatchExpression<S, K>
  | PolicyExprDescriptor
  | {
      any: NonEmptyArray<ConditionMatch<S, K>>;
    }
  | {
      all: NonEmptyArray<ConditionMatch<S, K>>;
    }
  | {
      none: NonEmptyArray<ConditionMatch<S, K>>;
    };
export type ConditionsSchema<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = {
  match: ConditionMatch<S, K>;
};
export class Conditions<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> {
  constructor(schema: ConditionsSchema<S, K>, options?: ValidationOptions);
  isFulfilled(req: PolicyEvalRequest<S, K>, condition?: ConditionMatch<S, K>): boolean;
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

export type OutputsSchema<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> =
  | {
      when: {
        ruleActivated?: ((req: PolicyEvalRequest<S, K>) => unknown) | PolicyExprDescriptor;
        conditionNotMet?: ((req: PolicyEvalRequest<S, K>) => unknown) | PolicyExprDescriptor;
      };
    }
  | ((req: PolicyEvalRequest<S, K>) => unknown)
  | PolicyExprDescriptor;
export class Outputs<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> {
  constructor(schema: OutputsSchema<S, K>, options?: ValidationOptions);
  build(req: PolicyEvalRequest<S, K>, isConditionFulfilled: boolean, src: string): {
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

/** Classic condition-backed definition: parentRoles and condition required. */
type ConditionDerivedRolesDefinition<S extends KerberosSchema = AnySchema> = {
  name: string;
  parentRoles: NonEmptyArray<PrincipalRoleOf<S> | '*'>;
  condition: ConditionsSchema<S> | Conditions<S>;
};
/**
 * Relation-backed (ReBAC) definition: the role activates when the configured
 * `relations` resolver grants the named relation/permission on the request's
 * resource. `parentRoles` and `condition` become optional synchronous gates.
 */
type RelationDerivedRolesDefinition<S extends KerberosSchema = AnySchema> = {
  name: string;
  relation: string;
  parentRoles?: NonEmptyArray<PrincipalRoleOf<S> | '*'>;
  condition?: ConditionsSchema<S> | Conditions<S>;
};
type DerivedRolesDefinition<S extends KerberosSchema = AnySchema> =
  | ConditionDerivedRolesDefinition<S>
  | RelationDerivedRolesDefinition<S>;
export type DerivedRolesSchema<S extends KerberosSchema = AnySchema> = {
  name: string;
  description?: string;
  variables?: VariablesSchema<S> | Variables<S>;
  constants?: ConstantsSchema | Constants;
  definitions: NonEmptyArray<DerivedRolesDefinition<S>>;
};
export class DerivedRoles<S extends KerberosSchema = AnySchema> {
  constructor(schema: DerivedRolesSchema<S>, options?: ValidationOptions);
  get(req: BaseRequest<S>): Set<string>;
  getRelationCandidates(req: BaseRequest<S>): Array<{ name: string; relation: string }>;
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

type BaseRule<S extends KerberosSchema = AnySchema, K extends ResourceKindOf<S> = ResourceKindOf<S>> = {
  name?: string;
  actions: NonEmptyArray<ActionOf<S, K> | '*'>;
  effect: Effect;
  condition?: ConditionsSchema<S, K> | Conditions<S, K>;
  output?: OutputsSchema<S, K> | Outputs<S, K>;
};
type RuleWithRoles<S extends KerberosSchema = AnySchema, K extends ResourceKindOf<S> = ResourceKindOf<S>> =
  BaseRule<S, K> & {
    roles: NonEmptyArray<PrincipalRoleOf<S> | '*'>;
  };
type RuleWithDerivedRoles<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = BaseRule<S, K> & {
  derivedRoles: NonEmptyArray<string>;
};
type Rule<S extends KerberosSchema = AnySchema, K extends ResourceKindOf<S> = ResourceKindOf<S>> =
  | RuleWithRoles<S, K>
  | RuleWithDerivedRoles<S, K>;
/**
 * One resource policy. When the schema declares resource kinds this is a
 * discriminated union over `resource:` — writing `resource: 'document'`
 * narrows every rule's `actions` and every condition's `R.attr` to that kind.
 */
/** One attribute-schema binding of a resource policy's `schemas:` block. */
export type AttributeSchemaRef = {
  /** Key into the engine's `schemas.definitions` map. */
  ref: string;
  /** Validation is skipped when EVERY requested action matches these globs. */
  ignoreWhen?: { actions: NonEmptyArray<string> | readonly string[] };
};

/** Cerbos-style attribute-schema declarations on a resource policy. */
export type ResourcePolicyAttributeSchemas = {
  principalSchema?: AttributeSchemaRef;
  resourceSchema?: AttributeSchemaRef;
};

export type ResourcePolicySchema<S extends KerberosSchema = AnySchema> = {
  [K in ResourceKindOf<S>]: {
    version: string;
    resource: K;
    scope?: string;
    rules: NonEmptyArray<Rule<S, K>>;
    variables?: VariablesSchema<S, K> | Variables<S, K>;
    constants?: ConstantsSchema | Constants;
    importDerivedRoles?: NonEmptyArray<string> | readonly string[];
    schemas?: ResourcePolicyAttributeSchemas;
  };
}[ResourceKindOf<S>];
export type ResourcePolicyRootSchema<S extends KerberosSchema = AnySchema> = {
  resourcePolicy: ResourcePolicySchema<S>;
};
export class ResourcePolicy<S extends KerberosSchema = AnySchema> {
  constructor(schema: ResourcePolicyRootSchema<S>, options?: ValidationOptions);
  check(req: BaseRequest<S>, derivedRoles: Set<string>, effectAsBoolean?: boolean): {
    effects: Map<string, Effect | boolean>;
    outputs: Map<string, unknown>;
    meta: {
      actions: Record<string, { matchedPolicy?: string; matchedRule?: string; matchedScope?: string; reason?: KerberosDecisionReason }>;
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

type PrincipalPolicyActionRuleSchema<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = {
  name?: string;
  action: ActionOf<S, K> | '*';
  effect: Effect;
  condition?: ConditionsSchema<S, K> | Conditions<S, K>;
  output?: OutputsSchema<S, K> | Outputs<S, K>;
};
/** Discriminated over `resource:` — the kind narrows each entry's `action`. */
type PrincipalPolicyRuleSchema<S extends KerberosSchema = AnySchema> = {
  [K in ResourceKindOf<S>]: {
    resource: K | '*';
    actions: NonEmptyArray<PrincipalPolicyActionRuleSchema<S, K>>;
  };
}[ResourceKindOf<S>];
export type PrincipalPolicySchema<S extends KerberosSchema = AnySchema> = {
  principal: string;
  version: string;
  scope?: string;
  rules: NonEmptyArray<PrincipalPolicyRuleSchema<S>>;
  variables?: VariablesSchema<S> | Variables<S>;
  constants?: ConstantsSchema | Constants;
};
export type PrincipalPolicyRootSchema<S extends KerberosSchema = AnySchema> = {
  principalPolicy: PrincipalPolicySchema<S>;
};
export class PrincipalPolicy<S extends KerberosSchema = AnySchema> {
  constructor(schema: PrincipalPolicyRootSchema<S>, options?: ValidationOptions);
  check(req: BaseRequest<S>, effectAsBoolean?: boolean): {
    effects: Map<string, Effect | boolean>;
    outputs: Map<string, unknown>;
    meta: {
      actions: Record<string, { matchedPolicy?: string; matchedRule?: string; matchedScope?: string; reason?: KerberosDecisionReason }>;
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

/** Discriminated over `resource:` — the kind narrows `allowActions`. */
type RolePolicyRuleSchema<S extends KerberosSchema = AnySchema> = {
  [K in ResourceKindOf<S>]: {
    name?: string;
    resource: K | '*';
    allowActions: NonEmptyArray<ActionOf<S, K> | '*'>;
    condition?: ConditionsSchema<S, K> | Conditions<S, K>;
    output?: OutputsSchema<S, K> | Outputs<S, K>;
  };
}[ResourceKindOf<S>];
export type RolePolicySchema<S extends KerberosSchema = AnySchema> = {
  role: PrincipalRoleOf<S>;
  version: string;
  scope?: string;
  parentRoles?: NonEmptyArray<PrincipalRoleOf<S>> | readonly PrincipalRoleOf<S>[];
  rules: NonEmptyArray<RolePolicyRuleSchema<S>>;
  variables?: VariablesSchema<S> | Variables<S>;
  constants?: ConstantsSchema | Constants;
};
export type RolePolicyRootSchema<S extends KerberosSchema = AnySchema> = {
  rolePolicy: RolePolicySchema<S>;
};
export class RolePolicy<S extends KerberosSchema = AnySchema> {
  constructor(schema: RolePolicyRootSchema<S>, options?: ValidationOptions);
  check(req: BaseRequest<S>, effectAsBoolean?: boolean): {
    effects: Map<string, Effect | boolean>;
    outputs: Map<string, unknown>;
    meta: {
      actions: Record<string, { matchedPolicy?: string; matchedRule?: string; matchedScope?: string; reason?: KerberosDecisionReason }>;
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

export type KerberosPolicy<S extends KerberosSchema = AnySchema> =
  | ResourcePolicy<S>
  | ResourcePolicyRootSchema<S>
  | PrincipalPolicy<S>
  | PrincipalPolicyRootSchema<S>
  | RolePolicy<S>
  | RolePolicyRootSchema<S>;
export type KerberosDerivedRoles<S extends KerberosSchema = AnySchema> = DerivedRoles<S> | DerivedRolesSchema<S>;
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
      matchedPolicy?: string;
      matchedRule?: string;
      matchedScope?: string;
      reason?: KerberosDecisionReason;
      /** Error class name for `'evaluation-error'` fail-closed denials. */
      errorName?: string;
    }>;
    effectiveDerivedRoles: string[];
    resolution?: KerberosResolutionTraceEntry[];
  } | Record<string, unknown>;
};

/**
 * Decision-trace reason recorded for denied actions when `includeMeta` is set:
 * - `'policy-miss'` — no policy source produced a decision at all;
 * - `'rule-miss'` — a policy matched but no rule targeted the action/roles;
 * - `'condition-not-met'` — a rule targeted the action but its condition failed;
 * - `'evaluation-error'` — the resource's evaluation rejected inside a
 *   `checkResources` batch and failed closed (paired with `errorName`).
 */
export type KerberosDecisionReason =
  | 'policy-miss'
  | 'rule-miss'
  | 'condition-not-met'
  | 'evaluation-error'
  | 'invalid-attributes';

/** Relation-resolution record in the decision trace (`meta.resolution`). */
export type KerberosRelationsTraceEntry = {
  source: 'relations';
  /** Derived role name backed by the relation. */
  name: string;
  relation: string;
  matched: boolean;
  /** Present when a relation-backed role could not resolve at all. */
  reason?: 'no-relations-resolver';
};

/** Derived-roles import record in the decision trace (`meta.resolution`). */
export type KerberosDerivedRolesTraceEntry = {
  source: 'derivedRoles';
  /** Imported derived-roles definition set name. */
  name: string;
  /** False when the import resolved nowhere (in memory or cache). */
  matched: boolean;
  /** Present when the set was resolved from the cache instead of memory. */
  origin?: 'cache';
};

/** One policy-lookup record in the decision trace (`meta.resolution`). */
export type KerberosResolutionTraceEntry =
  | {
      source: 'principal' | 'role' | 'resource';
      id: string;
      version: string;
      scopesSearched: string[];
      /** Scope the policy was found at, or null when no policy matched. */
      matchedScope: string | null;
      /** Present when the policy was resolved from the cache instead of memory. */
      origin?: 'cache';
    }
  | KerberosRelationsTraceEntry
  | KerberosDerivedRolesTraceEntry;
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
 * Minimal structural OpenTelemetry contracts. Kerberos never depends on
 * `@opentelemetry/api` (not even as a peer dependency) — following the same
 * delegating philosophy as `logger` and `cache`, the consumer passes either
 * the api module or pre-created tracer/meter instances.
 */
export type KerberosSpan = {
  setAttribute?(key: string, value: unknown): unknown;
  addEvent?(name: string, attributes?: Record<string, unknown>): unknown;
  recordException?(error: unknown): void;
  setStatus?(status: { code: number; message?: string }): unknown;
  end(): void;
};
export type KerberosTracer = {
  startSpan?(name: string, options?: unknown): KerberosSpan;
  startActiveSpan?<T>(name: string, options: unknown, fn: (span: KerberosSpan) => T): T;
};
export type KerberosCounter = { add(value: number, attributes?: Record<string, unknown>): void };
export type KerberosHistogram = { record(value: number, attributes?: Record<string, unknown>): void };
export type KerberosMeter = {
  createCounter(name: string, options?: unknown): KerberosCounter;
  createHistogram(name: string, options?: unknown): KerberosHistogram;
};
export type KerberosTelemetryApi = {
  trace?: { getTracer(name: string, version?: string): KerberosTracer };
  metrics?: { getMeter(name: string, version?: string): KerberosMeter };
};

/**
 * OpenTelemetry integration options.
 *
 * Two usage modes (controlled by which fields you supply):
 *
 * 1. `{ api }` — pass the `@opentelemetry/api` module itself; Kerberos derives
 *    its own tracer and meter with the correct instrumentation scope
 *    (`@alexify/kerberos`). Preferred.
 * 2. `{ tracer, meter }` — pre-created instances (either may be omitted for
 *    tracer-only / meter-only setups).
 *
 * `includeIdentity` (default `true`) controls whether `kerberos.principal.id`
 * and `kerberos.resource.id` are recorded on spans/events — set to `false`
 * when traces are exported to backends where identity data is unwanted.
 */
export type KerberosTelemetryOptions = {
  api?: KerberosTelemetryApi;
  tracer?: KerberosTracer;
  meter?: KerberosMeter;
  includeIdentity?: boolean;
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
  /** Max distinct cached expression ASTs (FIFO eviction). Default 1000. */
  maxCachedExprs?: number;
  /** Max expression string length in characters. Default 4096. */
  maxExprLength?: number;
  /** Max AST nesting depth. Default 32. */
  maxDepth?: number;
  /** Max length of strings BUILT by expressions (repeat/padStart/padEnd). Default 1_000_000; Infinity disables. */
  maxBuiltStringLength?: number;
};

export class KerberosExprError extends Error {
  name: 'KerberosExprError';
}

/** Thrown when a cache backend fails after exhausting the configured retry attempts. */
export class KerberosCacheError extends Error {
  name: 'KerberosCacheError';
}

/** Thrown when a cached policy document cannot be deserialized (corrupt entry → treated as a miss). */
export class KerberosCodecError extends Error {
  name: 'KerberosCodecError';
}

/** Thrown when request arguments fail validation. Always propagates regardless of `onError`. */
export class KerberosValidationError extends Error {
  name: 'KerberosValidationError';
}

/**
 * Thrown for ReBAC relation errors: invalid relation schemas (fail-fast at
 * construction) and runtime guard violations (`maxDepth`, missing
 * reverse-index contract).
 */
export class KerberosRelationsError extends Error {
  name: 'KerberosRelationsError';
}

/**
 * Thrown when a lifecycle hook (`hooks` option) throws, times out
 * (`hooksTimeoutMs` — `timedOut: true`) or returns an invalid replacement for
 * the request arguments (`cause` is then the `KerberosValidationError`).
 * `hook` names the failing hook and `cause` carries the original error. In
 * the engine it follows the `onError` option like any evaluation-phase error;
 * the built-in relations resolver always propagates it. Hooks that run on an
 * already-failed request or resource (`afterRequest` with `success: false`,
 * `afterResource` with a `reason`, `onError`) are swallowed instead and never
 * mask the original error.
 */
export class KerberosHookError extends Error {
  name: 'KerberosHookError';
  hook: KerberosHookName | null;
  /** True when the hook exceeded `hooksTimeoutMs`. */
  timedOut: boolean;
  cause?: unknown;
}

export type KerberosHookName = 'beforeRequest' | 'afterRequest' | 'beforeResource' | 'afterResource' | 'onError';

/** Which public method a hook or event belongs to. */
export type KerberosRequestKind = 'IsAllowed' | 'CheckResources' | 'PlanResources';

/**
 * The context every hook of one request shares — one frozen object: the
 * request kind, the `kerberosCallId` correlation id, the caller's `reqId` and
 * `args`, the VALIDATED arguments the engine evaluates (without a validation
 * backend these are the caller's own objects). After `beforeRequest` returned
 * a replacement, `args` reads the replacement and `enriched` is true.
 * Assigning `ctx.args` throws in strict mode — mutation is not the contract;
 * enrich by returning a replacement. Discriminated on `reqKind`, so
 * `ctx.args` narrows to that method's argument shape.
 */
export type KerberosHookContext<S extends KerberosSchema = AnySchema> =
  | { reqKind: 'IsAllowed'; callId: string; reqId?: string; readonly args: IsAllowedArgs<S>; readonly enriched: boolean }
  | {
      reqKind: 'CheckResources';
      callId: string;
      reqId?: string;
      readonly args: CheckResourcesArgs<S>;
      readonly enriched: boolean;
    }
  | {
      reqKind: 'PlanResources';
      callId: string;
      reqId?: string;
      readonly args: PlanResourcesArgs<S>;
      readonly enriched: boolean;
    };

/** The argument shapes a `beforeRequest` hook may return as a replacement (matching the request's `reqKind`). */
export type KerberosRequestArgs<S extends KerberosSchema = AnySchema> =
  | IsAllowedArgs<S>
  | CheckResourcesArgs<S>
  | PlanResourcesArgs<S>;

/** Outcome handed to `afterRequest`. */
export type KerberosRequestSummary = {
  /** False when the request failed — including when `onError: 'deny'` converted the failure into a fail-closed result. */
  success: boolean;
  durationMs: number;
  /** The evaluation error (on failure). */
  error?: unknown;
  /** Set when the failure was converted into a fail-closed result (`onError: 'deny'`). */
  failClosed?: true;
  /** Set when `beforeRequest` replaced the arguments. */
  enriched?: true;
};

/** Which resource of the request a per-resource hook is firing for. */
export type KerberosResourceHookInfo<S extends KerberosSchema = AnySchema> = {
  /** Zero-based position in the request's resources (always 0 of 1 for `isAllowed`). */
  index: number;
  total: number;
  resource: RequestResource<S>;
  actions: string[];
};

/**
 * Evaluation result handed to `afterResource` — canonical `EFFECT_*` strings,
 * never the `effectAsBoolean` view; frozen (shallow). A resource whose
 * evaluation failed (or whose `beforeResource` threw) still reaches
 * `afterResource` with its fail-closed view: every action `EFFECT_DENY`,
 * `reason: 'evaluation-error'` and the error's `errorName` — the same marker
 * the `decision` event and the audit entry carry.
 */
export type KerberosResourceHookResult = {
  actions: Record<string, Effect>;
  outputs: unknown[];
  validationErrors?: AttributeValidationError[];
  meta?: CheckResourcesResult['meta'];
  reason?: 'evaluation-error';
  errorName?: string;
};

/**
 * Lifecycle hooks — configured up front, AWAITED inside the request flow
 * (sync or async functions). A hook vetoes by throwing: `beforeRequest`,
 * `beforeResource`, `afterResource` and a successful request's
 * `afterRequest` surface as `KerberosHookError` and follow `onError`
 * (`'throw'` propagates, `'deny'` fails closed); inside a `checkResources`
 * batch a throwing per-resource hook only fails THAT resource (all its
 * actions DENY with `reason: 'evaluation-error'`). `onError`, `afterRequest`
 * after a failed request and `afterResource` after a failed resource are
 * swallowed (counted under `kerberos.observability.failures{sink: 'hooks'}`,
 * warned once). `beforeRequest` may ENRICH the request by returning a
 * replacement arguments object (re-validated; evaluated instead of the
 * original; marked `enriched` on the audit entry, the span, the events and
 * the summary) — every other return value is ignored. Malformed arguments
 * (`KerberosValidationError`) fire no hook at all. Unknown keys or
 * non-function values are rejected at construction; `hooksTimeoutMs` bounds
 * every invocation.
 */
export type KerberosHooks<S extends KerberosSchema = AnySchema> = {
  /**
   * Once per request, after argument validation and before any evaluation.
   * Return a replacement arguments object to enrich the request (an invalid
   * one fails the request as `KerberosHookError`); return nothing to keep it.
   */
  beforeRequest?: (
    ctx: KerberosHookContext<S>,
  ) => void | KerberosRequestArgs<S> | Promise<void | KerberosRequestArgs<S>>;
  /** Once per request, on success, failure AND the `onError: 'deny'` fallback path. */
  afterRequest?: (ctx: KerberosHookContext<S>, summary: KerberosRequestSummary) => void | Promise<void>;
  /** Before each resource evaluation (`isAllowed`, `checkResources`; not `planResources`). Forces the async evaluation driver. */
  beforeResource?: (ctx: KerberosHookContext<S>, info: KerberosResourceHookInfo<S>) => void | Promise<void>;
  /** After each resource evaluation — successful (throwing vetoes) or failed (`result.reason`; a throw is swallowed). */
  afterResource?: (
    ctx: KerberosHookContext<S>,
    info: KerberosResourceHookInfo<S>,
    result: KerberosResourceHookResult,
  ) => void | Promise<void>;
  /** When the request fails — receives the error before `afterRequest`. Always swallowed. */
  onError?: (error: unknown, ctx: KerberosHookContext<S>) => void | Promise<void>;
};

/** Identity-only projections carried by event payloads (never the attribute bags). */
export type KerberosEventPrincipal = { id: string; roles: string[] };
export type KerberosEventResource = { kind: string; id: string; scope?: string; policyVersion?: string };

export type KerberosRequestEventBase = { callId: string; reqKind: KerberosRequestKind; reqId?: string };

export type KerberosRequestStartEvent = KerberosRequestEventBase;
export type KerberosRequestErrorEvent = KerberosRequestEventBase & { error: string; errorName?: string };
export type KerberosRequestEndEvent = KerberosRequestEventBase & {
  durationMs: number;
  /** False on failure — also when `onError: 'deny'` returned a fail-closed result. */
  success: boolean;
  error?: string;
  errorName?: string;
  /** Set when a `beforeRequest` hook replaced the arguments. */
  enriched?: true;
};
export type KerberosDecisionEvent = KerberosRequestEventBase & {
  /** Position of the resource in the request. */
  index: number;
  principal: KerberosEventPrincipal;
  resource: KerberosEventResource;
  actions: Record<string, Effect>;
  /** Present for fail-closed decisions (a resource whose evaluation threw). */
  reason?: 'evaluation-error';
  errorName?: string;
  /** Set when a `beforeRequest` hook replaced the arguments (the decision was made on the enriched request). */
  enriched?: true;
};
export type KerberosPlanEvent = KerberosRequestEventBase & {
  principal: KerberosEventPrincipal;
  resource: { kind: string; id?: string; scope?: string; policyVersion?: string };
  actions: string[];
  filterKind: PlanKind;
  opaqueCount: number;
  relationCount: number;
  enriched?: true;
};
export type KerberosRelationsResolvedEvent = {
  callId: string;
  principal: KerberosEventPrincipal;
  resource: KerberosEventResource;
  relations: string[];
  granted: string[];
  /** Which resolver method served the request (`list` when the resolver has one). */
  mode: 'list' | 'check';
  durationMs: number;
};
/** Policy-cache reads carry no `callId`: the lookup path has no request context. */
export type KerberosCacheEvent = { key: string; error?: string; errorName?: string };

/**
 * Events emitted by {@link Kerberos}. Subscribe with `kerberos.on(name, …)` to
 * feed metrics or alerting without parsing audit logs. Emission is
 * synchronous and fire-and-forget: a listener that throws (or returns a
 * rejecting promise) is contained, counted under
 * `kerberos.observability.failures{sink: 'events'}` and warned once — it can
 * never affect a decision. Every request-scoped payload carries the
 * `kerberosCallId` of its request; payloads are fresh plain objects that never
 * contain `Error` instances or attribute bags. There is deliberately no
 * `'error'` event and no public `emit`.
 */
export type KerberosEvents = {
  'request:start': (event: KerberosRequestStartEvent) => void;
  'request:end': (event: KerberosRequestEndEvent) => void;
  'request:error': (event: KerberosRequestErrorEvent) => void;
  /** One per evaluated resource (fail-closed decisions included). */
  decision: (event: KerberosDecisionEvent) => void;
  plan: (event: KerberosPlanEvent) => void;
  'relations:resolved': (event: KerberosRelationsResolvedEvent) => void;
  'cache:hit': (event: KerberosCacheEvent) => void;
  'cache:miss': (event: KerberosCacheEvent) => void;
  'cache:error': (event: KerberosCacheEvent) => void;
};

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
export function createSafeExprCodec(options: {
  jsep: (expr: string) => unknown;
  roots?: string[];
  /** Max distinct cached expression ASTs (FIFO eviction). Default 1000. */
  maxCachedExprs?: number;
  /** Max expression string length in characters. Default 4096. */
  maxExprLength?: number;
  /** Max AST nesting depth. Default 32. */
  maxDepth?: number;
  /** Max length of strings BUILT by expressions (repeat/padStart/padEnd). Default 1_000_000; Infinity disables. */
  maxBuiltStringLength?: number;
}): PolicyCodec & {
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

/**
 * ReBAC delegation contract for the `relations` option. Any object with a
 * `check` method works — a SQL/ORM-backed resolver of your join tables, or the
 * built-in Zanzibar-lite resolver from `@alexify/kerberos/relations`. `list`
 * is an optional batch fast path (called first when present). The `memo` Map
 * is request-scoped and shared across all resources of a `checkResources`
 * batch — resolvers may use it to share subproblems.
 */
export type KerberosRelationsResolver<S extends KerberosSchema = AnySchema> = {
  check(
    args: { principal: RequestPrincipal<S>; resource: RequestResource<S>; relation: string },
    opts?: { memo?: Map<string, unknown> | null; callId?: string | null },
  ): boolean | Promise<boolean>;
  list?(
    args: { principal: RequestPrincipal<S>; resource: RequestResource<S>; relations: string[] },
    opts?: { memo?: Map<string, unknown> | null; callId?: string | null },
  ): Set<string> | string[] | Promise<Set<string> | string[]>;
};

export type KerberosCacheRetry = {
  /** Read attempts per key. Default 3; `attempts: 1` disables retrying. */
  attempts?: number;
  /** Base backoff delay between attempts (exponential, default 25ms); `delayMs: 0` restores immediate retries. */
  delayMs?: number;
  /** Full-jitter randomization of the backoff delay (default true). */
  jitter?: boolean;
  /** Optional bound on each read attempt; a hung `get` counts as a failed attempt. Off by default. */
  timeoutMs?: number;
  /**
   * What to do after the retry budget is exhausted: `'throw'` (default)
   * surfaces `KerberosCacheError` per the `onError` semantics; `'miss'` counts
   * the read as a cache miss so evaluation falls through to the remaining
   * static sources (opt-in degraded mode — a cache outage no longer disables
   * statically-resolvable decisions). Applies to the engine's policy reads
   * only.
   */
  onExhausted?: 'throw' | 'miss';
};

export type KerberosOptions<S extends KerberosSchema = AnySchema> = ValidationOptions & {
  logger?: KerberosLogger | boolean;
  telemetry?: KerberosTelemetryOptions;
  cache?: CacheLike;
  /** Retry/backoff/timeout policy for cache.get failures. Default { attempts: 3, delayMs: 25, jitter: true }. */
  cacheRetry?: KerberosCacheRetry | null;
  /** Prefix prepended to every cache key (policies + derived roles) for per-tenant/per-environment namespacing on shared stores. */
  cacheKeyPrefix?: string;
  codec?: PolicyCodec;
  /** ReBAC resolver used for relation-backed derived roles. */
  relations?: KerberosRelationsResolver<S> | null;
  /** Optional bound on each `relations.check`/`relations.list` call; a hung resolver fails as `KerberosRelationsError` instead of hanging authorization. Off by default. */
  relationsTimeoutMs?: number;
  /**
   * Engine-level audit enrichment. `{ includeMeta: true }` runs decision
   * tracing for every request when a logger is attached, so audit entries
   * carry `meta.resolution` and the `policy-miss` reason regardless of the
   * caller's per-request `includeMeta` flag (the response stays gated on the
   * request flag).
   */
  audit?: { includeMeta?: boolean } | null;
  /**
   * Caps how many resources of a `checkResources` batch evaluate
   * concurrently (each chain issues its own cache reads). Unbounded by
   * default — the historical behavior.
   */
  maxConcurrency?: number;
  /**
   * Evaluation-phase error handling. `'throw'` (default) propagates errors to
   * the caller; `'deny'` converts them to fail-closed results — `isAllowed` →
   * `false`, `checkResources` → one all-DENY result per requested resource
   * (positional parity with the request; entries that cannot be echoed back
   * from malformed arguments are skipped), `planResources` → a
   * `KIND_ALWAYS_DENIED` filter. Malformed arguments always throw
   * `KerberosValidationError` regardless of this option.
   */
  onError?: 'throw' | 'deny';
  /**
   * Attribute-schema enforcement (Cerbos `schemas` parity): maps the schema
   * refs declared by resource policies to actual validators and picks the
   * enforcement level. Absent (or `enforcement: 'none'`) → schema references
   * in policies are inert, matching Cerbos's own default.
   */
  schemas?: KerberosAttributeSchemasOptions | null;
  getCallId?: () => string;
  /**
   * Lifecycle hooks (see {@link KerberosHooks}): awaited user callbacks around
   * every request / resource evaluation. Hook failures follow `onError`;
   * `beforeResource`/`afterResource` switch evaluation to the async driver.
   */
  hooks?: KerberosHooks<S> | null;
  /**
   * Bounds every awaited hook invocation; a hook that neither resolves nor
   * rejects fails as `KerberosHookError` (`timedOut: true`, following the
   * hook's throwing/swallowing rule) instead of hanging authorization. Off by
   * default (`0`), like `relationsTimeoutMs`.
   */
  hooksTimeoutMs?: number | null;
  /**
   * Listener-leak detection for the events façade: the first subscription
   * past this count (per event name) logs one warning — subscribe once at
   * startup, not per request. Never a limit. Default 10; `0` disables.
   */
  maxListeners?: number | null;
};

/** One Cerbos-shaped attribute validation failure. */
export type AttributeValidationError = {
  /** JSON-pointer-ish path of the failing attribute (`'/amount'`; `''` for whole-bag failures). */
  path: string;
  message: string;
  source: 'SOURCE_PRINCIPAL' | 'SOURCE_RESOURCE';
};

/**
 * One attribute-schema definition: a plain JSON Schema object (compiled with
 * the engine's `ajv` option), a Zod-like schema (anything with `safeParse`),
 * or a validator function returning error messages (nothing/empty = valid).
 */
export type AttributeSchemaDefinition =
  | Record<string, unknown>
  | { safeParse(value: unknown): { success: boolean; error?: { issues?: unknown[] } } }
  | ((value: unknown) => void | boolean | Array<string | { path?: string; message?: string }>);

export type KerberosAttributeSchemasOptions = {
  /** `'reject'` (default when the option is set) denies invalid requests; `'warn'` only reports; `'none'` disables. */
  enforcement?: 'none' | 'warn' | 'reject';
  /** Maps the `ref` strings used in policies' `schemas:` blocks to validators. */
  definitions?: Record<string, AttributeSchemaDefinition>;
};

/** Wildcard action token used in policy rules. */
export const ALL_ACTIONS: '*';
/** Wildcard role token used in resource policy rules. */
export const ALL_ROLES: '*';
/** Wildcard resource token used in principal/role policy rules. */
export const ALL_RESOURCES: '*';
/** Default policy version used when a request omits `policyVersion`. */
export const DEFAULT_VERSION: 'default';
/** The base (empty) scope every scope search chain ends with. */
export const BASE_SCOPE: '';

/**
 * Wraps a CacheLike into the internal read-only reader used by Kerberos
 * (retry loop + typed KerberosCacheError). Exposed for advanced composition.
 */
export function createCacheReader(
  cache: CacheLike | false | null | undefined,
  retry?: KerberosCacheRetry | null,
): { enabled: boolean; get(key: string): Promise<unknown> };

/**
 * planResources filter outcome (Cerbos-compatible). Declared as a frozen const
 * object rather than a TypeScript `enum` so that the raw wire strings
 * (`'KIND_CONDITIONAL'`) — which is what a serialized plan actually carries —
 * are assignable to the `PlanKind` type. `PlanKind.Conditional` still works.
 */
export declare const PlanKind: {
  readonly AlwaysAllowed: 'KIND_ALWAYS_ALLOWED';
  readonly AlwaysDenied: 'KIND_ALWAYS_DENIED';
  readonly Conditional: 'KIND_CONDITIONAL';
};
export type PlanKind = 'KIND_ALWAYS_ALLOWED' | 'KIND_ALWAYS_DENIED' | 'KIND_CONDITIONAL';

/**
 * One operand of a planResources condition tree: a literal, a reference to an
 * unknown resource field (`request.resource.id` / `request.resource.attr.*`)
 * or a nested expression. Operators follow the Cerbos vocabulary
 * (`and/or/not/eq/ne/lt/le/gt/ge/in/add/sub/mult/div/mod/index/list`) plus the
 * Kerberos extensions `opaque` (statically unplannable condition — post-filter
 * required) and `relation` (ReBAC dependency — see expandRelationOperands).
 */
export type PlanExpressionOperand =
  | { value: unknown }
  | { variable: string }
  | { expression: { operator: string; operands: PlanExpressionOperand[] } };

export type PlanFilter = {
  kind: PlanKind;
  /** Present only for KIND_CONDITIONAL. */
  condition?: PlanExpressionOperand;
};

/** planResources plans over a resource KIND: no `id`, `attr` = KNOWN fields. */
export type RequestPlanResource<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = {
  kind: K;
  policyVersion?: string;
  scope?: string;
  attr?: Partial<ResourceAttrOf<S, K>>;
};

export type PlanResourcesArgs<
  S extends KerberosSchema = AnySchema,
  K extends ResourceKindOf<S> = ResourceKindOf<S>,
> = {
  reqId?: string;
  principal: RequestPrincipal<S>;
  resource: RequestPlanResource<S, K>;
  /** Exactly one of `action` / `actions` must be provided. */
  action?: ActionOf<S, K>;
  /** Multiple actions plan the conjunction (Cerbos AND semantics). */
  actions?: ActionOf<S, K>[];
  includeMeta?: boolean;
};

export type PlanResourcesResponse<S extends KerberosSchema = AnySchema> = {
  reqId?: string;
  kerberosCallId: string;
  /** Echo of the request form: `action` for single-action requests… */
  action?: ActionOf<S>;
  /** …or `actions` for multi-action requests. */
  actions?: ActionOf<S>[];
  resourceKind: ResourceKindOf<S>;
  policyVersion: string;
  filter: PlanFilter;
  meta?: {
    /** Human-readable s-expression rendering of the condition. */
    filterDebug: string;
    matchedScopes: {
      principal: string | null;
      resource: string | null;
      roles: Record<string, string | null>;
    };
    resolution: KerberosResolutionTraceEntry[];
  };
};

/**
 * Replaces every `relation` operand of a plan with
 * `in(request.resource.id, [ids])` via the supplied lookup (typically backed
 * by `RelationResolver.lookupResources` from `@alexify/kerberos/relations`),
 * then re-normalizes the filter. Returns a new response object.
 */
export function expandRelationOperands<S extends KerberosSchema = AnySchema>(
  planResponse: PlanResourcesResponse<S>,
  lookup: (args: { name: string; relation: string }) => Promise<Iterable<string>> | Iterable<string>,
): Promise<PlanResourcesResponse<S>>;

/** One entry of a `checkResources` batch — the kind narrows its `actions`. */

/** A query plan in the `@cerbos/core` SDK encoding (flattened operands) that the official Cerbos ORM adapters accept. */
export type CerbosSdkQueryPlan = {
  kind: PlanKind;
  condition?: unknown;
};

/**
 * Converts a `planResources` response (or its `filter`) from the HTTP-API
 * operand encoding Kerberos emits into the flattened `@cerbos/core` SDK
 * encoding consumed by `@cerbos/orm-prisma` / `@cerbos/orm-drizzle`.
 * Kerberos-only operators are rejected: materialize `relation` operands with
 * `expandRelationOperands` first; `opaque` plans need post-filtering.
 */
export declare function toCerbosQueryPlan(planOrFilter: {
  filter?: unknown;
  kind?: string;
  condition?: unknown;
}): CerbosSdkQueryPlan;
export type CheckResourcesEntry<S extends KerberosSchema = AnySchema> = {
  [K in ResourceKindOf<S>]: { resource: RequestResource<S, K>; actions: ActionOf<S, K>[] };
}[ResourceKindOf<S>];

export type IsAllowedArgs<S extends KerberosSchema = AnySchema, K extends ResourceKindOf<S> = ResourceKindOf<S>> = {
  reqId?: string;
  principal: RequestPrincipal<S>;
  resource: RequestResource<S, K>;
  action: ActionOf<S, K>;
  includeMeta?: boolean;
};

export type CheckResourcesArgs<S extends KerberosSchema = AnySchema> = {
  reqId?: string;
  principal: RequestPrincipal<S>;
  resources: CheckResourcesEntry<S>[];
  includeMeta?: boolean;
};

/** `E` is `Effect` by default and `boolean` when `effectAsBoolean` is set. */
export type CheckResourcesResult<S extends KerberosSchema = AnySchema, E = Effect> = {
  resource: Pick<RequestResource<S>, 'id' | 'kind' | 'policyVersion' | 'scope'>;
  actions: Record<ActionOf<S>, E>;
  outputs: unknown[];
  /**
   * Attribute-schema validation failures (`schemas` engine option). Present —
   * regardless of `includeMeta` — whenever validation ran and failed: under
   * `enforcement: 'reject'` the actions are all denied, under `'warn'` the
   * decision is unaffected.
   */
  validationErrors?: AttributeValidationError[];
  meta?: {
    actions: Record<string, {
      matchedPolicy?: string;
      matchedRule?: string;
      matchedScope?: string;
      reason?: KerberosDecisionReason;
      /** Error class name for `'evaluation-error'` fail-closed denials. */
      errorName?: string;
    }>;
    effectiveDerivedRoles: string[];
    resolution?: KerberosResolutionTraceEntry[];
  };
};

export type CheckResourcesResponse<S extends KerberosSchema = AnySchema, E = Effect> = {
  reqId?: string;
  kerberosCallId: string;
  results: CheckResourcesResult<S, E>[];
};

export class Kerberos<S extends KerberosSchema = AnySchema> {
  constructor(policies: KerberosPolicy<S>[], derivedRoles: KerberosDerivedRoles<S>[], options?: KerberosOptions<S>);
  static generateCallId(): string;
  static normalizeScope(scope?: string): string;
  static getScopeSearchChain(scope?: string): string[];
  /** Parses/validates one policy shape or instance with the configured backend. */
  static parsePolicy(policy: unknown, options?: ValidationOptions & { schema?: unknown; resourceSchema?: unknown; principalSchema?: unknown; roleSchema?: unknown }): ResourcePolicy | PrincipalPolicy | RolePolicy;
  /** Parses/validates one derived-roles shape or instance with the configured backend. */
  static parseDerivedRoles(roles: unknown, options?: ValidationOptions & { schema?: unknown }): DerivedRoles;
  /** Builds and validates the internal request envelope (external-caller seam; the engine validates arguments once at the public-method boundary instead). */
  static parseRequest(request: { principal: RequestPrincipal; resource: RequestResource; actions: string[]; reqId?: string; callId?: string; includeMeta?: boolean }, options?: ValidationOptions & { schema?: unknown }): Record<string, unknown>;
  /** Validates `isAllowed` arguments with the configured backend. */
  static parseIsAllowedArgs(args: unknown, options?: ValidationOptions & { schema?: unknown }): Record<string, unknown>;
  /** Validates `checkResources` arguments with the configured backend. */
  static parseCheckResourcesArgs(args: unknown, options?: ValidationOptions & { schema?: unknown }): Record<string, unknown>;
  /** Validates `planResources` arguments with the configured backend. */
  static parsePlanResourcesArgs(args: unknown, options?: ValidationOptions & { schema?: unknown }): Record<string, unknown>;
  isAllowed<K extends ResourceKindOf<S>>(args: IsAllowedArgs<S, K>): Promise<boolean>;
  /** Subscribes to a lifecycle event (see {@link KerberosEvents}). Chainable; unknown event names are type errors (and a `TypeError` at runtime). */
  on<E extends keyof KerberosEvents>(event: E, listener: KerberosEvents[E]): this;
  once<E extends keyof KerberosEvents>(event: E, listener: KerberosEvents[E]): this;
  off<E extends keyof KerberosEvents>(event: E, listener: KerberosEvents[E]): this;
  removeAllListeners(event?: keyof KerberosEvents): this;
  listenerCount(event: keyof KerberosEvents): number;
  checkResources(args: CheckResourcesArgs<S>, effectAsBoolean: true): Promise<CheckResourcesResponse<S, boolean>>;
  checkResources(args: CheckResourcesArgs<S>, effectAsBoolean?: false): Promise<CheckResourcesResponse<S, Effect>>;
  checkResources(
    args: CheckResourcesArgs<S>,
    effectAsBoolean?: boolean,
  ): Promise<CheckResourcesResponse<S, Effect | boolean>>;
  planResources<K extends ResourceKindOf<S>>(args: PlanResourcesArgs<S, K>): Promise<PlanResourcesResponse<S>>;
}
export class KerberosZodSchemas {
  static buildResourcePolicyInstance(z: unknown): unknown;
  static buildPrincipalPolicyInstance(z: unknown): unknown;
  static buildRolePolicyInstance(z: unknown): unknown;
  static buildDerivedRolesInstance(z: unknown): unknown;
  static buildIsAllowedArgs(z: unknown): unknown;
  static buildCheckResourcesArgs(z: unknown): unknown;
  static buildPlanResourcesArgs(z: unknown): unknown;
}
export class KerberosJsonSchemas {
  static buildResourcePolicyInstance(): Record<string, unknown>;
  static buildPrincipalPolicyInstance(): Record<string, unknown>;
  static buildRolePolicyInstance(): Record<string, unknown>;
  static buildDerivedRolesInstance(): Record<string, unknown>;
  static buildIsAllowedArgs(): Record<string, unknown>;
  static buildCheckResourcesArgs(): Record<string, unknown>;
  static buildPlanResourcesArgs(): Record<string, unknown>;
}
export class KerberosTypeBoxSchemas {
  static buildResourcePolicyInstance(typebox: TypeBoxLike): unknown;
  static buildPrincipalPolicyInstance(typebox: TypeBoxLike): unknown;
  static buildRolePolicyInstance(typebox: TypeBoxLike): unknown;
  static buildDerivedRolesInstance(typebox: TypeBoxLike): unknown;
  static buildIsAllowedArgs(typebox: TypeBoxLike): unknown;
  static buildCheckResourcesArgs(typebox: TypeBoxLike): unknown;
  static buildPlanResourcesArgs(typebox: TypeBoxLike): unknown;
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
