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
} from '@alexify/kerberos';

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
  cacheRetry?: { attempts?: number } | null;
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
  /** Lookup result cap. Default 1000. */
  maxResults?: number;
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
  check(args: RelationCheckArgs, opts?: { memo?: Map<string, unknown> | null }): Promise<boolean>;
  list(
    args: {
      resource: string | RequestResource;
      subject?: string;
      principal?: RequestPrincipal;
      relations: string[];
      context?: Record<string, unknown>;
    },
    opts?: { memo?: Map<string, unknown> | null },
  ): Promise<Set<string>>;
  lookupSubjects(
    args: {
      resource: string | RequestResource;
      permission?: string;
      relation?: string;
      subjectType?: string;
      context?: Record<string, unknown>;
    },
    opts?: { memo?: Map<string, unknown> | null },
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
    opts?: { memo?: Map<string, unknown> | null },
  ): Promise<string[]>;
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
