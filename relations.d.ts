import type {
  CacheLike,
  Conditions,
  ConditionsSchema,
  KerberosLogger,
  KerberosTelemetryOptions,
  PolicyCodec,
  RequestPrincipal,
  RequestResource,
  TypeBoxLike,
  ValidationOptions,
} from './index.js';

/** Which public resolver method a hook or event belongs to. */
export type RelationRequestKind = 'check' | 'list' | 'lookupSubjects' | 'lookupResources';

/**
 * Context shared by every hook of one resolver call — one frozen object: the
 * method, the correlation id (the engine's `kerberosCallId` when called
 * through the `relations` seam, a generated one for standalone calls) and the
 * VALIDATED arguments object. After `beforeRequest` returned a replacement,
 * `args` reads the replacement and `enriched` is true.
 */
export type RelationHookContext = {
  kind: RelationRequestKind;
  callId: string;
  readonly args: Record<string, unknown>;
  readonly enriched: boolean;
};

export type RelationRequestSummary = { success: boolean; durationMs: number; error?: unknown; enriched?: true };

/**
 * Resolver lifecycle hooks (request-level only — see the engine's
 * `KerberosHooks` for the contract). The resolver has no `onError` option, so
 * a throwing `beforeRequest` / successful-call `afterRequest` always
 * propagates as `KerberosHookError`; `onError` and a failed call's
 * `afterRequest` are swallowed. `beforeRequest` may return a replacement
 * arguments object (re-validated; resolved instead of the original).
 * Validated at construction with a `TypeError` (unknown keys, non-function
 * values), like the engine's option; `hooksTimeoutMs` bounds every call.
 */
export type RelationResolverHooks = {
  beforeRequest?: (
    ctx: RelationHookContext,
  ) => void | Record<string, unknown> | Promise<void | Record<string, unknown>>;
  afterRequest?: (ctx: RelationHookContext, summary: RelationRequestSummary) => void | Promise<void>;
  onError?: (error: unknown, ctx: RelationHookContext) => void | Promise<void>;
};

export type RelationRequestEventBase = { callId: string; kind: RelationRequestKind };
export type RelationRequestEndEvent = RelationRequestEventBase & {
  durationMs: number;
  success: boolean;
  error?: string;
  errorName?: string;
  /** Set when a `beforeRequest` hook replaced the arguments. */
  enriched?: true;
};
export type RelationRequestErrorEvent = RelationRequestEventBase & { error: string; errorName?: string };
export type RelationCheckedEvent = RelationRequestEventBase & {
  resource: { kind: string; id: string };
  relation: string;
  /** Canonical subject string (`'user:u1'`, `'group:eng#member'`). */
  subject: string;
  allowed: boolean;
  enriched?: true;
};
/** Tuple-document cache reads; `callId` correlates them with the resolver call (null when none). */
export type RelationCacheEvent = {
  key: string;
  kind: 'relation';
  callId: string | null;
  error?: string;
  errorName?: string;
};

/**
 * Events emitted by {@link RelationResolver} — same contract as the engine's
 * events: synchronous, listener failures contained and counted, no `'error'`
 * event, no public `emit`.
 */
export type RelationResolverEvents = {
  'request:start': (event: RelationRequestEventBase) => void;
  'request:end': (event: RelationRequestEndEvent) => void;
  'request:error': (event: RelationRequestErrorEvent) => void;
  /** One per relation/permission check (`check`; once per name for `list`). */
  'relation:checked': (event: RelationCheckedEvent) => void;
  'cache:hit': (event: RelationCacheEvent) => void;
  'cache:miss': (event: RelationCacheEvent) => void;
  'cache:error': (event: RelationCacheEvent) => void;
};

type NonEmptyArray<T> = [T, ...T[]];

/**
 * Allowed subject type of a relation:
 * - `'user'` — direct subjects of that definition;
 * - `'user:*'` — the type-wide wildcard subject;
 * - `'group#member'` — a subject relation (userset);
 * - object form additionally binds a caveat: `{ type: 'user', caveat: 'valid_ip' }`.
 */
export type RelationSubjectRef =
  | string
  | { type: string; relation?: string; wildcard?: boolean; caveat?: string };

/**
 * Permission expression (SpiceDB userset-rewrite algebra):
 * - `'viewer'` — reference to a relation or permission of the same definition;
 * - `{ via: 'parent', permission: 'view' }` — arrow (tuple-to-userset);
 *   `all: true` makes it an intersection arrow (`.all`);
 * - `{ anyOf: [...] }` — union; `{ allOf: [...] }` — intersection;
 * - `{ exclude: { base, subtract } }` — exclusion (order-sensitive).
 */
export type RelationPermissionExpr =
  | string
  | { via: string; permission: string; all?: boolean }
  | { anyOf: NonEmptyArray<RelationPermissionExpr> }
  | { allOf: NonEmptyArray<RelationPermissionExpr> }
  | { exclude: { base: RelationPermissionExpr; subtract: NonEmptyArray<RelationPermissionExpr> } };

/**
 * Caveat definition: a Kerberos condition evaluated against `{ P, ctx }`
 * (principal + merged context; written tuple context takes precedence over
 * check-time context). JSON-authored caveats use `{ match: { $expr } }` and
 * require a `codec` (e.g. `createSafeExprCodec({ jsep, roots: ['P', 'ctx'] })`).
 */
export type RelationCaveatSchema = ConditionsSchema | Conditions | { match: { $expr: string } };

export type RelationDefinitionSchema = {
  relations?: Record<string, NonEmptyArray<RelationSubjectRef>>;
  permissions?: Record<string, RelationPermissionExpr>;
};

export type RelationSchemaShape = {
  relationSchema: {
    description?: string;
    caveats?: Record<string, RelationCaveatSchema>;
    definitions: Record<string, RelationDefinitionSchema>;
  };
};

/**
 * A relationship tuple: the canonical SpiceDB string form
 * (`resourceType:id#relation@subjectType:id[#subjectRelation]`) or the object
 * form with an optional caveat binding.
 */
export type RelationTuple =
  | string
  | {
      resource: string;
      relation: string;
      subject: string;
      caveat?: { name: string; context?: Record<string, unknown> };
    };

export type RelationSchemaOptions = ValidationOptions & { codec?: PolicyCodec };

/** Compiled relation schema (definitions, rewrite trees, caveat registry). */
export class RelationSchema {
  constructor(shape: RelationSchemaShape, options?: RelationSchemaOptions);
  static parseShape(shape: unknown, options?: RelationSchemaOptions): unknown;
  static parseCaveat(name: string, def: unknown, options?: RelationSchemaOptions): Conditions;
  get shape(): unknown;
  get definitions(): Map<
    string,
    { relations: Map<string, { refs: unknown[]; admission: Set<string> }>; permissions: Map<string, unknown> }
  >;
  get caveats(): Map<string, Conditions>;
  hasDefinition(type: string): boolean;
  getRelationSubjects(
    type: string,
    name: string,
  ): Array<{ type: string; relation: string | null; wildcard: boolean; caveat: string | null }> | undefined;
  /** Precomputed O(1) admission-key Set of a relation (see `buildAdmissionKey`). */
  getRelationAdmission(type: string, name: string): Set<string> | undefined;
  getPermissionNode(type: string, name: string): unknown;
  isCheckable(type: string, name: string): boolean;
  getCaveat(name: string): Conditions | undefined;
}

/** Canonical admission key of an allowed-subject shape. */
export function buildAdmissionKey(
  type: string,
  relation: string | null,
  wildcard: boolean,
  caveat: string | null,
): string;

export function parseObjectRef(ref: string, label?: string): { type: string; id: string };
export function parseSubjectRef(ref: string): { type: string; id: string; relation: string | null };
export function parseTuple(raw: RelationTuple): {
  resource: { type: string; id: string };
  relation: string;
  subject: { type: string; id: string; relation: string | null };
  caveat: { name: string; context: Record<string, unknown> | null } | null;
};

export type RelationResolverOptions = ValidationOptions & {
  schema: RelationSchemaShape | RelationSchema;
  /** Static tuples — indexed in both directions at construction (zero IO). */
  tuples?: RelationTuple[];
  /** Dynamic tuples: read-only fallback keyed `rel:<type>:<id>:<relation>`. */
  cache?: CacheLike;
  /** Retry/backoff/timeout policy (same shape as the engine's `cacheRetry`, minus `onExhausted` — relation reads never degrade to a miss, since "not found" would widen access in exclusion positions). */
  cacheRetry?: { attempts?: number; delayMs?: number; jitter?: boolean; timeoutMs?: number } | null;
  /** Compiles `{ $expr }` caveat conditions (eval-free). */
  codec?: PolicyCodec;
  logger?: KerberosLogger | boolean;
  /**
   * OpenTelemetry delegation (same shapes as the Kerberos option): one span
   * per public call plus `kerberos.relations.checks` and
   * `kerberos.cache.requests` (kind `relation`) metrics. Guarded — telemetry
   * can never affect resolution.
   */
  telemetry?: KerberosTelemetryOptions | null;
  /** Subject type used when mapping a Kerberos principal (default 'user'). */
  subjectType?: string;
  mapPrincipal?: (principal: RequestPrincipal) => string;
  mapResource?: (resource: RequestResource) => string;
  /**
   * Opt-in reverse-index contract: the backend maintains
   * `rel:rev:<subjectKey>` documents so `lookupResources` works over
   * cache-backed tuples.
   */
  reverseIndex?: boolean;
  /** Recursion guard (SpiceDB semantics — no visited-set). Default 50. */
  maxDepth?: number;
  /**
   * Lookup result cap for `lookupSubjects`/`lookupResources`. Default 1000.
   * The cap bounds the RESPONSE only — see `onTruncated` for what happens
   * when it is exceeded.
   */
  maxResults?: number;
  /**
   * What to do when a lookup result exceeds `maxResults`: `'ignore'` (default)
   * returns the first `maxResults` entries silently (historical behavior);
   * `'throw'` raises `KerberosRelationsError` instead — recommended whenever
   * lookup results feed a query-plan filter, where a silently narrowed list
   * would drop authorized rows. Truncation is always recorded on the call's
   * telemetry span as `kerberos.result.truncated`.
   */
  onTruncated?: 'ignore' | 'throw';
  /**
   * Caps the concurrent candidate-verification checks of `lookupResources`
   * (the fan-out that scales with tuple volume). Unbounded by default.
   */
  maxConcurrency?: number;
  /** Lifecycle hooks around every public call (see {@link RelationResolverHooks}). */
  hooks?: RelationResolverHooks | null;
  /** Bounds every awaited hook invocation (`KerberosHookError`, `timedOut: true`). Off by default. */
  hooksTimeoutMs?: number | null;
  /** Listener-leak warning threshold per event name (default 10; `0` disables). Never a limit. */
  maxListeners?: number | null;
};

/**
 * Per-call options. `memo` is a session Map shared across calls to reuse
 * document reads and decision subproblems. Sharing one Map is safe by
 * construction: every entry is scoped by resolver instance, and decision
 * entries are additionally scoped by the IDENTITY of the `principal`/`context`
 * object references — reuse the same object references to maximize sharing
 * (the Kerberos engine does exactly that across a checkResources batch).
 */
export type RelationCallOptions = {
  memo?: Map<string, unknown> | null;
  /** Correlation id stamped on the call's telemetry span as `kerberos.call_id` — the engine passes its kerberosCallId through the relations seam automatically. */
  callId?: string | null;
};

export type RelationCheckArgs = {
  resource: string | RequestResource;
  subject?: string;
  principal?: RequestPrincipal;
  permission?: string;
  relation?: string;
  /** Check-time caveat context (written tuple context wins on collisions). */
  context?: Record<string, unknown>;
};

export type RelationLookupSubjectsResult = Array<string | { subject: string; exclusions: string[] }>;

/**
 * The built-in in-process "Zanzibar-lite" relation resolver. It implements
 * the Kerberos `relations` delegation contract (pass an instance as the
 * `relations` constructor option) and additionally exposes the standalone
 * SpiceDB-flavoured `check` / `lookupSubjects` / `lookupResources` API.
 */
export class RelationResolver {
  constructor(options: RelationResolverOptions);
  get schema(): RelationSchema;
  check(args: RelationCheckArgs, opts?: RelationCallOptions): Promise<boolean>;
  list(
    args: {
      resource: string | RequestResource;
      subject?: string;
      principal?: RequestPrincipal;
      relations: string[];
      context?: Record<string, unknown>;
    },
    opts?: RelationCallOptions,
  ): Promise<Set<string>>;
  lookupSubjects(
    args: {
      resource: string | RequestResource;
      permission?: string;
      relation?: string;
      subjectType?: string;
      context?: Record<string, unknown>;
    },
    opts?: RelationCallOptions,
  ): Promise<RelationLookupSubjectsResult>;
  lookupResources(
    args: {
      subject?: string;
      principal?: RequestPrincipal;
      permission?: string;
      relation?: string;
      resourceType: string;
      context?: Record<string, unknown>;
    },
    opts?: RelationCallOptions,
  ): Promise<string[]>;
  /** Subscribes to a resolver event (see {@link RelationResolverEvents}). Chainable; unknown event names are type errors (and a `TypeError` at runtime). */
  on<E extends keyof RelationResolverEvents>(event: E, listener: RelationResolverEvents[E]): this;
  once<E extends keyof RelationResolverEvents>(event: E, listener: RelationResolverEvents[E]): this;
  off<E extends keyof RelationResolverEvents>(event: E, listener: RelationResolverEvents[E]): this;
  removeAllListeners(event?: keyof RelationResolverEvents): this;
  listenerCount(event: keyof RelationResolverEvents): number;
}

export class RelationsZodSchemas {
  static buildShape(z: unknown): unknown;
  static buildTupleShape(z: unknown): unknown;
  static buildCheckArgs(z: unknown): unknown;
  static buildLookupSubjectsArgs(z: unknown): unknown;
  static buildLookupResourcesArgs(z: unknown): unknown;
}
export class RelationsJsonSchemas {
  static buildShape(): Record<string, unknown>;
  static buildTupleShape(): Record<string, unknown>;
  static buildCheckArgs(): Record<string, unknown>;
  static buildLookupSubjectsArgs(): Record<string, unknown>;
  static buildLookupResourcesArgs(): Record<string, unknown>;
}
export class RelationsTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
  static buildTupleShape(typebox: TypeBoxLike): unknown;
  static buildCheckArgs(typebox: TypeBoxLike): unknown;
  static buildLookupSubjectsArgs(typebox: TypeBoxLike): unknown;
  static buildLookupResourcesArgs(typebox: TypeBoxLike): unknown;
}

export function parseRelationSchemaShape(shape: unknown, options?: RelationSchemaOptions): unknown;
