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
      any: NonEmptyArray<ConditionMatch>;
    }
  | {
      all: NonEmptyArray<ConditionMatch>;
    }
  | {
      none: NonEmptyArray<ConditionMatch>;
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

/** Classic condition-backed definition: parentRoles and condition required. */
type ConditionDerivedRolesDefinition = {
  name: string;
  parentRoles: NonEmptyArray<string>;
  condition: ConditionsSchema | Conditions;
};
/**
 * Relation-backed (ReBAC) definition: the role activates when the configured
 * `relations` resolver grants the named relation/permission on the request's
 * resource. `parentRoles` and `condition` become optional synchronous gates.
 */
type RelationDerivedRolesDefinition = {
  name: string;
  relation: string;
  parentRoles?: NonEmptyArray<string>;
  condition?: ConditionsSchema | Conditions;
};
type DerivedRolesDefinition = ConditionDerivedRolesDefinition | RelationDerivedRolesDefinition;
export type DerivedRolesSchema = {
  name: string;
  description?: string;
  variables?: VariablesSchema | Variables;
  constants?: ConstantsSchema | Constants;
  definitions: NonEmptyArray<DerivedRolesDefinition>;
};
export class DerivedRoles {
  constructor(schema: DerivedRolesSchema, options?: ValidationOptions);
  get(req: BaseRequest): Set<string>;
  getRelationCandidates(req: BaseRequest): Array<{ name: string; relation: string }>;
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
  actions: NonEmptyArray<string>;
  effect: Effect;
  condition?: ConditionsSchema | Conditions;
  output?: OutputsSchema | Outputs;
};
type RuleWithRoles = BaseRule & {
  roles: NonEmptyArray<string> | readonly ['*'];
};
type RuleWithDerivedRoles = BaseRule & {
  derivedRoles: NonEmptyArray<string>;
};
type Rule = RuleWithRoles | RuleWithDerivedRoles;
export type ResourcePolicySchema = {
  version: string;
  resource: string;
  scope?: string;
  rules: NonEmptyArray<Rule>;
  variables?: VariablesSchema | Variables;
  constants?: ConstantsSchema | Constants;
  importDerivedRoles?: NonEmptyArray<string> | readonly string[];
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

type PrincipalPolicyActionRuleSchema = {
  name?: string;
  action: string;
  effect: Effect;
  condition?: ConditionsSchema | Conditions;
  output?: OutputsSchema | Outputs;
};
type PrincipalPolicyRuleSchema = {
  resource: string;
  actions: NonEmptyArray<PrincipalPolicyActionRuleSchema>;
};
export type PrincipalPolicySchema = {
  principal: string;
  version: string;
  scope?: string;
  rules: NonEmptyArray<PrincipalPolicyRuleSchema>;
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

type RolePolicyRuleSchema = {
  name?: string;
  resource: string;
  allowActions: NonEmptyArray<string>;
  condition?: ConditionsSchema | Conditions;
  output?: OutputsSchema | Outputs;
};
export type RolePolicySchema = {
  role: string;
  version: string;
  scope?: string;
  parentRoles?: NonEmptyArray<string> | readonly string[];
  rules: NonEmptyArray<RolePolicyRuleSchema>;
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

export type KerberosPolicy =
  | ResourcePolicy
  | ResourcePolicyRootSchema
  | PrincipalPolicy
  | PrincipalPolicyRootSchema
  | RolePolicy
  | RolePolicyRootSchema;
export type KerberosDerivedRoles = DerivedRoles | DerivedRolesSchema;
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
export type KerberosDecisionReason = 'policy-miss' | 'rule-miss' | 'condition-not-met' | 'evaluation-error';

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
export type KerberosRelationsResolver = {
  check(
    args: { principal: RequestPrincipal; resource: RequestResource; relation: string },
    opts?: { memo?: Map<string, unknown> | null; callId?: string | null },
  ): boolean | Promise<boolean>;
  list?(
    args: { principal: RequestPrincipal; resource: RequestResource; relations: string[] },
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

export type KerberosOptions = ValidationOptions & {
  logger?: KerberosLogger | boolean;
  telemetry?: KerberosTelemetryOptions;
  cache?: CacheLike;
  /** Retry/backoff/timeout policy for cache.get failures. Default { attempts: 3, delayMs: 25, jitter: true }. */
  cacheRetry?: KerberosCacheRetry | null;
  /** Prefix prepended to every cache key (policies + derived roles) for per-tenant/per-environment namespacing on shared stores. */
  cacheKeyPrefix?: string;
  codec?: PolicyCodec;
  /** ReBAC resolver used for relation-backed derived roles. */
  relations?: KerberosRelationsResolver | null;
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
   * the caller; `'deny'` converts them to fail-closed results (`isAllowed` →
   * false, `checkResources` → empty results). Malformed arguments always throw
   * `KerberosValidationError` regardless of this option.
   */
  onError?: 'throw' | 'deny';
  getCallId?: () => string;
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

/** planResources filter outcome (Cerbos-compatible). */
export enum PlanKind {
  AlwaysAllowed = 'KIND_ALWAYS_ALLOWED',
  AlwaysDenied = 'KIND_ALWAYS_DENIED',
  Conditional = 'KIND_CONDITIONAL',
}

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
export type RequestPlanResource = {
  kind: string;
  policyVersion?: string;
  scope?: string;
  attr?: Record<string, unknown>;
};

export type PlanResourcesArgs = {
  reqId?: string;
  principal: RequestPrincipal;
  resource: RequestPlanResource;
  /** Exactly one of `action` / `actions` must be provided. */
  action?: string;
  /** Multiple actions plan the conjunction (Cerbos AND semantics). */
  actions?: string[];
  includeMeta?: boolean;
};

export type PlanResourcesResponse = {
  reqId?: string;
  kerberosCallId: string;
  /** Echo of the request form: `action` for single-action requests… */
  action?: string;
  /** …or `actions` for multi-action requests. */
  actions?: string[];
  resourceKind: string;
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
export function expandRelationOperands(
  planResponse: PlanResourcesResponse,
  lookup: (args: { name: string; relation: string }) => Promise<Iterable<string>> | Iterable<string>,
): Promise<PlanResourcesResponse>;

export class Kerberos {
  constructor(policies: KerberosPolicy[], derivedRoles: KerberosDerivedRoles[], options?: KerberosOptions);
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
  isAllowed(args: {
    reqId?: string;
    principal: RequestPrincipal;
    resource: RequestResource;
    action: string;
    includeMeta?: boolean;
  }): Promise<boolean>;
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
          matchedPolicy?: string;
          matchedRule?: string;
          matchedScope?: string;
          reason?: KerberosDecisionReason;
        }>;
        effectiveDerivedRoles: string[];
        resolution?: KerberosResolutionTraceEntry[];
      };
    }[];
  }>;
  planResources(args: PlanResourcesArgs): Promise<PlanResourcesResponse>;
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
