const {
  RelationSchema,
  buildAdmissionKey,
  parseObjectRef,
  parseSubjectRef,
  parseTuple,
} = require('./RelationSchema.js');
const { RelationsJsonSchemas, RelationsTypeBoxSchemas, RelationsZodSchemas } = require('./schemas/index.js');

const { createCacheReader } = require('../caching/cache.js');
const { createLoggerWriter } = require('../logging.js');
const { createTelemetryWriter } = require('../telemetry.js');
const { KerberosCodecError, KerberosRelationsError } = require('../errors.js');
const { resolveValidationAdapter } = require('../validation');
// Platform runtime: bundlers swap this for `./runtime/browser.js` via the
// package.json `browser` field map when targeting the browser.
const { getNow } = require('../runtime/node.js');

// SpiceDB uses the same default: depth is the only recursion guard — a
// visited-set is deliberately NOT used because it is semantically unsound in
// the presence of exclusions.
const DEFAULT_MAX_DEPTH = 50;
const DEFAULT_MAX_RESULTS = 1000;

const SUBJECT_WILDCARD_ID = '*';

const CACHE_KIND_RELATION = 'relation';

const EMPTY_ENTRIES = Object.freeze([]);
// Shared resolved promise for static-only misses — avoids allocating a new
// promise per empty read on the hot path.
const EMPTY_ENTRIES_PROMISE = Promise.resolve(EMPTY_ENTRIES);
const EMPTY_CONTEXT = Object.freeze({});

/**
 * Builds a prototype-less dispatch table so lookups can never resolve to
 * inherited members and stay O(1) (same pattern as the codec's
 * NODE_EVALUATORS strategy tables).
 */
function createDispatch(entries) {
  return Object.assign(Object.create(null), entries);
}

function subjectToString(subject) {
  const base = `${subject.type}:${subject.id}`;
  return subject.relation === null ? base : `${base}#${subject.relation}`;
}

function subjectAdmissionKey(subject, caveat) {
  const isWildcard = subject.relation === null && subject.id === SUBJECT_WILDCARD_ID;
  return buildAdmissionKey(subject.type, subject.relation, isWildcard, caveat ? caveat.name : null);
}

const RESERVED_REF_CHARS = /[\s:#@*|]/;

// 'user:emilia' | { subject, caveat? } → { subject, caveat }
function parseDocumentEntry(raw) {
  if (typeof raw === 'string') return { subject: parseSubjectRef(raw), caveat: null };
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    let caveat = null;
    if (raw.caveat !== undefined && raw.caveat !== null) {
      if (typeof raw.caveat !== 'object' || typeof raw.caveat.name !== 'string') {
        throw new KerberosRelationsError('Invalid relation document caveat — expected { name, context? }');
      }
      caveat = { name: raw.caveat.name, context: raw.caveat.context ?? null };
    }
    return { subject: parseSubjectRef(raw.subject), caveat };
  }
  throw new KerberosRelationsError(
    'Invalid relation document entry — expected a subject string or { subject, caveat? }',
  );
}

// 'document:readme#viewer' | { resource: 'document:readme', relation, caveat? }
function parseReverseEntry(raw) {
  if (typeof raw === 'string') {
    const hash = raw.indexOf('#');
    if (hash === -1) throw new KerberosRelationsError(`Invalid reverse entry "${raw}" — expected "type:id#relation"`);
    return { resource: parseObjectRef(raw.slice(0, hash), 'resource'), relation: raw.slice(hash + 1), caveat: null };
  }
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    let caveat = null;
    if (raw.caveat !== undefined && raw.caveat !== null) {
      if (typeof raw.caveat !== 'object' || typeof raw.caveat.name !== 'string') {
        throw new KerberosRelationsError('Invalid reverse entry caveat — expected { name, context? }');
      }
      caveat = { name: raw.caveat.name, context: raw.caveat.context ?? null };
    }
    return { resource: parseObjectRef(raw.resource, 'resource'), relation: raw.relation, caveat };
  }
  throw new KerberosRelationsError('Invalid reverse entry — expected "type:id#relation" or { resource, relation }');
}

/**
 * allSettled with the engine's error rule: every sibling settles (no
 * unawaited rejection — memoized promises stay handled), then the FIRST
 * rejection reason is rethrown; otherwise the fulfilled values are returned
 * in input order.
 */
async function settleAll(promises) {
  const settled = await Promise.allSettled(promises);
  const values = new Array(settled.length);
  let firstError = null;
  for (let i = 0; i < settled.length; i++) {
    if (settled[i].status === 'rejected') {
      if (!firstError) firstError = settled[i].reason;
      continue;
    }
    values[i] = settled[i].value;
  }
  if (firstError) throw firstError instanceof Error ? firstError : new Error(String(firstError));
  return values;
}

// ---------------------------------------------------------------------------
// Subject-set algebra for lookupSubjects, keyed per type:
//   { concrete: Map<type, Set<id>>, wildcards: Map<type, Set<excluded id>> }
// Per-type Maps make wildcard coverage and subtraction O(1) per id instead of
// slicing/`startsWith`-scanning composite string keys. Caveated tuples are
// INCLUDED (results are an upper bound for them) — use check() for
// per-subject certainty.
// ---------------------------------------------------------------------------

function emptySubjectSet() {
  return { concrete: new Map(), wildcards: new Map() };
}

function cloneSubjectSet(set) {
  const clone = emptySubjectSet();
  for (const [type, ids] of set.concrete) clone.concrete.set(type, new Set(ids));
  for (const [type, exclusions] of set.wildcards) clone.wildcards.set(type, new Set(exclusions));
  return clone;
}

function addConcrete(set, type, id) {
  let ids = set.concrete.get(type);
  if (!ids) {
    ids = new Set();
    set.concrete.set(type, ids);
  }
  ids.add(id);
}

function wildcardCovers(set, type, id) {
  const exclusions = set.wildcards.get(type);
  return exclusions !== undefined && !exclusions.has(id);
}

function normalizeSubjectSet(set) {
  // An exclusion that is also independently a concrete member is void.
  for (const [type, exclusions] of set.wildcards) {
    const ids = set.concrete.get(type);
    if (!ids) continue;
    for (const id of exclusions) if (ids.has(id)) exclusions.delete(id);
  }
  return set;
}

function unionSubjectSets(target, other) {
  for (const [type, ids] of other.concrete) {
    let targetIds = target.concrete.get(type);
    if (!targetIds) {
      targetIds = new Set();
      target.concrete.set(type, targetIds);
    }
    for (const id of ids) targetIds.add(id);
  }
  for (const [type, otherExclusions] of other.wildcards) {
    const existing = target.wildcards.get(type);
    if (existing === undefined) {
      target.wildcards.set(type, new Set(otherExclusions));
      continue;
    }
    // Excluded from the union only if excluded on both sides. Deleting the
    // current entry during Set iteration is safe per spec.
    for (const id of existing) if (!otherExclusions.has(id)) existing.delete(id);
  }
  return normalizeSubjectSet(target);
}

function intersectSubjectSets(a, b) {
  const result = emptySubjectSet();
  for (const [type, ids] of a.concrete) {
    const bIds = b.concrete.get(type);
    for (const id of ids) {
      if ((bIds !== undefined && bIds.has(id)) || wildcardCovers(b, type, id)) addConcrete(result, type, id);
    }
  }
  for (const [type, ids] of b.concrete) {
    for (const id of ids) {
      if (wildcardCovers(a, type, id)) addConcrete(result, type, id);
    }
  }
  for (const [type, aExclusions] of a.wildcards) {
    const bExclusions = b.wildcards.get(type);
    if (bExclusions === undefined) continue;
    const merged = new Set(aExclusions);
    for (const id of bExclusions) merged.add(id);
    result.wildcards.set(type, merged);
  }
  return normalizeSubjectSet(result);
}

function subtractSubjectSets(target, other) {
  for (const [type, ids] of target.concrete) {
    const otherIds = other.concrete.get(type);
    for (const id of ids) {
      if ((otherIds !== undefined && otherIds.has(id)) || wildcardCovers(other, type, id)) ids.delete(id);
    }
    if (!ids.size) target.concrete.delete(type);
  }
  for (const [type, exclusions] of target.wildcards) {
    const otherExclusions = other.wildcards.get(type);
    if (otherExclusions !== undefined) {
      // `type:* - type:*` removes the wildcard; the subtrahend's exclusions
      // survive (they were not subtracted) unless excluded here too.
      target.wildcards.delete(type);
      for (const id of otherExclusions) if (!exclusions.has(id)) addConcrete(target, type, id);
      continue;
    }
    const otherIds = other.concrete.get(type);
    if (otherIds !== undefined) for (const id of otherIds) exclusions.add(id);
  }
  return normalizeSubjectSet(target);
}

/**
 * The built-in in-process "Zanzibar-lite" relation resolver.
 *
 * Implements the Kerberos `relations` delegation contract (`check`/`list`
 * taking `principal`/`resource` objects) plus a standalone SpiceDB-flavoured
 * API (`check` with `subject`/`permission` strings, `lookupSubjects`,
 * `lookupResources`). Static tuples are indexed in memory (zero IO); dynamic
 * tuples are read through the same read-only cache fallback used for policies
 * — storage, TTL, invalidation and reverse documents are fully owned by the
 * backend. Optional OpenTelemetry via the `telemetry` option (spans per
 * public call + `kerberos.relations.checks` / `kerberos.cache.requests`
 * metrics), guarded so telemetry can never affect resolution.
 */
// Monotonic id per resolver instance — part of the decision-memo scope key so
// one caller-provided memo Map can never leak decisions across two resolvers
// (e.g. two tenants with different schemas but identical type/name strings).
let resolverSeq = 0;

class RelationResolver {
  /** @type {RelationSchema} */
  #schema;

  #reader;

  #log;

  #telemetry;

  #includeIdentity = true;

  // Decision-memo scoping (see #createSession): caveat outcomes depend on the
  // principal and check-time context, so `check|`/`lr|` memo entries are keyed
  // by identity tokens of the exact principal/context object references. Same
  // reference → same token → full sharing (the engine reuses one principal
  // object across a whole checkResources batch); different references →
  // isolated entries instead of stale reuse.
  #resolverToken = (resolverSeq += 1);

  // Precomputed outer-memo key for this resolver's shared inner map.
  #sharedKey = `@@r${this.#resolverToken}`;

  // One-slot cache for the decisions key: the engine reuses the same
  // principal object (and no context) across every call of a batch, so a
  // reference-equality hit replaces the token lookups and template build.
  #lastPrincipal = undefined;

  #lastContext = undefined;

  #lastDecisionsKey = '';

  /** @type {WeakMap<object, number>} */
  #identityTokens = new WeakMap();

  #identitySeq = 0;

  #limits;

  #subjectType;

  #mapPrincipal = null;

  #mapResource = null;

  #reverseIndex = false;

  /** @type {Map<string, Array<{ subject: object, caveat: object | null }>>} */
  #forwardIndex = new Map();

  /** @type {Map<string, Array<{ resource: { type: string, id: string }, relation: string, caveat: object | null }>>} */
  #reverseStaticIndex = new Map();

  // Structural reachability analyses per `${type}#${name}` — instance-scoped
  // and bounded by schema size, so a plain Map (not WeakMap) is the right
  // structure; session memos are request-scoped Maps owned by the caller.
  #reachabilityMemo = new Map();

  // Kinds validated once per resolver (bounded by the schema's type count) so
  // the hot object-form path skips the reserved-char regex after first sight.
  #validKinds = new Set();

  // Argument validators are resolved ONCE here (mirroring Kerberos'
  // constructor-precompiled validators) instead of re-resolving the backend on
  // every public call.
  #checkArgsValidator = null;

  #listArgsValidator = null;

  #lookupSubjectsArgsValidator = null;

  #lookupResourcesArgsValidator = null;

  // O(1) strategy tables over rewrite-node kinds (prototype-less, built once).
  #rewriteEvaluators;

  #subjectCollectors;

  #reachabilityCollectors;

  /**
   * @param {object} options
   */
  constructor(options = {}) {
    const {
      schema,
      tuples,
      cache,
      cacheRetry,
      codec,
      logger,
      telemetry,
      subjectType = 'user',
      mapPrincipal,
      mapResource,
      reverseIndex = false,
      maxDepth,
      maxResults,
      z,
      ajv,
      typebox,
    } = options;

    this.#schema = schema instanceof RelationSchema ? schema : new RelationSchema(schema, { z, ajv, typebox, codec });
    this.#limits = {
      maxDepth: maxDepth ?? DEFAULT_MAX_DEPTH,
      maxResults: maxResults ?? DEFAULT_MAX_RESULTS,
    };
    this.#reader = createCacheReader(cache, cacheRetry);
    this.#log = createLoggerWriter(logger);
    this.#telemetry = createTelemetryWriter(telemetry);
    this.#includeIdentity = telemetry?.includeIdentity !== false;
    this.#subjectType = subjectType;
    if (typeof mapPrincipal === 'function') this.#mapPrincipal = mapPrincipal;
    if (typeof mapResource === 'function') this.#mapResource = mapResource;
    this.#reverseIndex = reverseIndex === true;

    this.#checkArgsValidator = resolveValidationAdapter({
      z,
      ajv,
      typebox,
      buildJson: () => RelationsJsonSchemas.buildCheckArgs(),
      buildTypeBox: (t) => RelationsTypeBoxSchemas.buildCheckArgs(t),
      buildZod: (zed) => RelationsZodSchemas.buildCheckArgs(zed),
    });
    this.#listArgsValidator = resolveValidationAdapter({
      z,
      ajv,
      typebox,
      buildJson: () => RelationsJsonSchemas.buildListArgs(),
      buildTypeBox: (t) => RelationsTypeBoxSchemas.buildListArgs(t),
      buildZod: (zed) => RelationsZodSchemas.buildListArgs(zed),
    });
    this.#lookupSubjectsArgsValidator = resolveValidationAdapter({
      z,
      ajv,
      typebox,
      buildJson: () => RelationsJsonSchemas.buildLookupSubjectsArgs(),
      buildTypeBox: (t) => RelationsTypeBoxSchemas.buildLookupSubjectsArgs(t),
      buildZod: (zed) => RelationsZodSchemas.buildLookupSubjectsArgs(zed),
    });
    this.#lookupResourcesArgsValidator = resolveValidationAdapter({
      z,
      ajv,
      typebox,
      buildJson: () => RelationsJsonSchemas.buildLookupResourcesArgs(),
      buildTypeBox: (t) => RelationsTypeBoxSchemas.buildLookupResourcesArgs(t),
      buildZod: (zed) => RelationsZodSchemas.buildLookupResourcesArgs(zed),
    });

    if (tuples !== undefined && tuples !== null) {
      if (!Array.isArray(tuples)) throw new KerberosRelationsError('"tuples" must be an array of relationship tuples');
      for (const raw of tuples) this.#indexStaticTuple(raw);
    }

    // Strategy tables (dispatch on node.kind). Sequential-vs-parallel choices
    // are deliberate per handler: `check` keeps short-circuiting sequential
    // (the first ALLOW/DENY skips the remaining branches AND their cache
    // reads); `collect` needs every branch, so children resolve as one
    // allSettled wave.
    this.#rewriteEvaluators = createDispatch({
      ref: (node, resource, subject, session, depth) =>
        this.#checkInternal(resource, node.name, subject, session, depth - 1),
      union: async (node, resource, subject, session, depth) => {
        for (const child of node.children) {
          if (await this.#evalRewrite(child, resource, subject, session, depth)) return true;
        }
        return false;
      },
      intersection: async (node, resource, subject, session, depth) => {
        for (const child of node.children) {
          if (!(await this.#evalRewrite(child, resource, subject, session, depth))) return false;
        }
        return true;
      },
      exclusion: async (node, resource, subject, session, depth) => {
        // Base first (order-sensitive); an empty base short-circuits.
        if (!(await this.#evalRewrite(node.base, resource, subject, session, depth))) return false;
        for (const subtracted of node.subtract) {
          if (await this.#evalRewrite(subtracted, resource, subject, session, depth)) return false;
        }
        return true;
      },
      arrow: async (node, resource, subject, session, depth) => {
        const entries = await this.#readRelationEntries(resource.type, resource.id, node.via, session);
        // Compile guarantees tupleset entries are direct object refs; a false
        // caveat removes the tuple, shrinking the reached object set.
        const objects = [];
        for (const entry of entries) {
          if (entry.caveat && !this.#evaluateCaveat(entry.caveat, session)) continue;
          objects.push(entry.subject);
        }
        if (node.all) {
          // Intersection arrow (`.all`): every reached object must grant the
          // target; zero reached objects yield false (SpiceDB semantics).
          if (!objects.length) return false;
          for (const object of objects) {
            const matched = await this.#checkInternal(
              { type: object.type, id: object.id },
              node.target,
              subject,
              session,
              depth - 1,
            );
            if (!matched) return false;
          }
          return true;
        }
        for (const object of objects) {
          const matched = await this.#checkInternal(
            { type: object.type, id: object.id },
            node.target,
            subject,
            session,
            depth - 1,
          );
          if (matched) return true;
        }
        return false;
      },
    });

    this.#subjectCollectors = createDispatch({
      ref: (node, resource, session, depth) => this.#collectSubjectsInternal(resource, node.name, session, depth - 1),
      union: async (node, resource, session, depth) => {
        const waves = [];
        for (const child of node.children) waves.push(this.#collectRewriteSubjects(child, resource, session, depth));
        const collected = await settleAll(waves);
        const result = emptySubjectSet();
        for (const set of collected) unionSubjectSets(result, set);
        return result;
      },
      intersection: async (node, resource, session, depth) => {
        const waves = [];
        for (const child of node.children) waves.push(this.#collectRewriteSubjects(child, resource, session, depth));
        const collected = await settleAll(waves);
        let result = collected[0];
        for (let i = 1; i < collected.length; i++) result = intersectSubjectSets(result, collected[i]);
        return result;
      },
      exclusion: async (node, resource, session, depth) => {
        const waves = [this.#collectRewriteSubjects(node.base, resource, session, depth)];
        for (const subtracted of node.subtract) {
          waves.push(this.#collectRewriteSubjects(subtracted, resource, session, depth));
        }
        const collected = await settleAll(waves);
        // The base may be an object stored in the session memo (`subjects|…`);
        // subtractSubjectSets mutates its target in place, so subtract from a
        // CLONE — otherwise later lookups reusing the memo would read a
        // corrupted base set.
        const result = cloneSubjectSet(collected[0]);
        for (let i = 1; i < collected.length; i++) subtractSubjectSets(result, collected[i]);
        return result;
      },
      arrow: async (node, resource, session, depth) => {
        const entries = await this.#readRelationEntries(resource.type, resource.id, node.via, session);
        const waves = [];
        for (const entry of entries) {
          const object = entry.subject;
          waves.push(
            this.#collectSubjectsInternal({ type: object.type, id: object.id }, node.target, session, depth - 1),
          );
        }
        if (node.all) {
          if (!waves.length) return emptySubjectSet();
          const collected = await settleAll(waves);
          let result = collected[0];
          for (let i = 1; i < collected.length; i++) result = intersectSubjectSets(result, collected[i]);
          return result;
        }
        const collected = await settleAll(waves);
        const result = emptySubjectSet();
        for (const set of collected) unionSubjectSets(result, set);
        return result;
      },
    });

    this.#reachabilityCollectors = createDispatch({
      ref: (node, type, analysis, visited) => this.#collectReachability(type, node.name, analysis, visited),
      union: (node, type, analysis, visited) => {
        for (const child of node.children) this.#collectReachabilityNode(type, child, analysis, visited);
      },
      intersection: (node, type, analysis, visited) => {
        // Candidates from the first branch suffice (a member must be in all);
        // verification filters the superset.
        analysis.needsCheck = true;
        this.#collectReachabilityNode(type, node.children[0], analysis, visited);
      },
      exclusion: (node, type, analysis, visited) => {
        // Only the base produces candidates; subtraction is verification-only.
        analysis.needsCheck = true;
        this.#collectReachabilityNode(type, node.base, analysis, visited);
      },
      arrow: (node, type, analysis) => {
        if (node.all) analysis.needsCheck = true;
        for (const ref of this.#schema.getRelationSubjects(type, node.via)) {
          if (ref.caveat) analysis.needsCheck = true;
          const edgeKey = `${node.via}|${ref.type}|${node.target}`;
          if (!analysis.arrowEdgeKeys.has(edgeKey)) {
            analysis.arrowEdgeKeys.add(edgeKey);
            analysis.arrowEdges.push({ via: node.via, objectType: ref.type, target: node.target });
          }
        }
      },
    });
  }

  get schema() {
    return this.#schema;
  }

  /**
   * Checks whether a subject holds a relation/permission on a resource.
   * Accepts both the engine-contract form (`{ principal, resource, relation }`
   * with objects) and the standalone form (`{ resource: 'type:id', permission,
   * subject: 'type:id', context? }`).
   *
   * @param {Record<string, unknown>} args
   * @param {{ memo?: Map<string, unknown> | null }} [opts]
   * @returns {Promise<boolean>}
   */
  async check(args, opts = {}) {
    // Validation runs INSIDE the instrumented scope so argument errors get an
    // error span and a duration sample too.
    return this.#runInstrumented('RelationsCheck', async (otel) => {
      if (!args || typeof args !== 'object') throw new KerberosRelationsError('check requires an arguments object');
      const parsed = this.#parseArgs(this.#checkArgsValidator, 'Invalid check arguments', args);

      const name = resolveName(parsed, 'check');
      const resource = this.#normalizeResource(parsed.resource);
      const subject = this.#normalizeSubject(parsed);
      this.#assertCheckable(resource.type, name, 'check');

      const session = this.#createSession(parsed, opts);
      const allowed = await this.#checkInternal(resource, name, subject, session, this.#limits.maxDepth);
      this.#telemetry.recordRelationCheck(allowed);
      this.#setSpanAttributes(otel, resource.type, name, {
        'kerberos.allowed': allowed,
        subjectKey: subjectToString(subject),
        resourceId: resource.id,
      });
      return allowed;
    });
  }

  /**
   * Resolves which of the requested relations/permissions the subject holds
   * on the resource. Sequential on purpose: the shared session memo lets
   * later names reuse the subproblems (and cache reads) of earlier ones.
   *
   * @param {Record<string, unknown>} args
   * @param {{ memo?: Map<string, unknown> | null }} [opts]
   * @returns {Promise<Set<string>>}
   */
  async list(args, opts = {}) {
    return this.#runInstrumented('RelationsList', async (otel) => {
      if (!args || typeof args !== 'object') throw new KerberosRelationsError('list requires an arguments object');
      const parsed = this.#parseArgs(this.#listArgsValidator, 'Invalid list arguments', args);
      const names = parsed.relations;
      if (!Array.isArray(names) || !names.length) {
        throw new KerberosRelationsError('list requires a non-empty "relations" array');
      }

      const resource = this.#normalizeResource(parsed.resource);
      const subject = this.#normalizeSubject(parsed);
      for (const name of names) this.#assertCheckable(resource.type, name, 'list');

      const session = this.#createSession(parsed, opts);
      const granted = new Set();
      for (const name of names) {
        const allowed = await this.#checkInternal(resource, name, subject, session, this.#limits.maxDepth);
        this.#telemetry.recordRelationCheck(allowed);
        if (allowed) granted.add(name);
      }
      this.#setSpanAttributes(otel, resource.type, null, {
        'kerberos.relations.requested': names.length,
        'kerberos.relations.granted': granted.size,
        subjectKey: subjectToString(subject),
        resourceId: resource.id,
      });
      return granted;
    });
  }

  /**
   * "Who can access `resource#permission`?" — expands the permission tree to
   * terminal subjects (auto-recursive through groups). Wildcards come back as
   * `'type:*'` strings, or `{ subject: 'type:*', exclusions: [...] }` under
   * exclusions.
   *
   * @param {Record<string, unknown>} args
   * @param {{ memo?: Map<string, unknown> | null }} [opts]
   * @returns {Promise<Array<string | { subject: string, exclusions: string[] }>>}
   */
  async lookupSubjects(args, opts = {}) {
    return this.#runInstrumented('RelationsLookupSubjects', async (otel) => {
      if (!args || typeof args !== 'object') {
        throw new KerberosRelationsError('lookupSubjects requires an arguments object');
      }
      const parsed = this.#parseArgs(this.#lookupSubjectsArgsValidator, 'Invalid lookupSubjects arguments', args);

      const name = resolveName(parsed, 'lookupSubjects');
      const resource = this.#normalizeResource(parsed.resource);
      this.#assertCheckable(resource.type, name, 'lookupSubjects');

      const session = this.#createSession(parsed, opts);
      const collected = await this.#collectSubjectsInternal(resource, name, session, this.#limits.maxDepth);

      const subjectTypeFilter = typeof parsed.subjectType === 'string' ? parsed.subjectType : null;
      const results = [];
      for (const [type, ids] of collected.concrete) {
        if (subjectTypeFilter && type !== subjectTypeFilter) continue;
        const exclusions = collected.wildcards.get(type);
        for (const id of ids) {
          // A concrete subject already covered by an unexcluded wildcard of
          // the same type is redundant in the result.
          if (exclusions !== undefined && !exclusions.has(id)) continue;
          results.push(`${type}:${id}`);
        }
      }
      for (const [type, exclusions] of collected.wildcards) {
        if (subjectTypeFilter && type !== subjectTypeFilter) continue;
        if (exclusions.size) {
          const excluded = [];
          for (const id of exclusions) excluded.push(`${type}:${id}`);
          excluded.sort();
          results.push({ subject: `${type}:*`, exclusions: excluded });
        } else {
          results.push(`${type}:*`);
        }
      }
      results.sort(compareSubjectResults);
      const limited = results.length > this.#limits.maxResults ? results.slice(0, this.#limits.maxResults) : results;
      this.#setSpanAttributes(otel, resource.type, name, {
        'kerberos.result.count': limited.length,
        resourceId: resource.id,
      });
      return limited;
    });
  }

  /**
   * "Which resources of `resourceType` can the subject access?" — reachability
   * entrypoints over the reverse index plus candidate verification for
   * intersection/exclusion/caveat paths (SpiceDB's LookupResources2 pattern).
   *
   * @param {Record<string, unknown>} args
   * @param {{ memo?: Map<string, unknown> | null }} [opts]
   * @returns {Promise<string[]>}
   */
  async lookupResources(args, opts = {}) {
    return this.#runInstrumented('RelationsLookupResources', async (otel) => {
      if (!args || typeof args !== 'object') {
        throw new KerberosRelationsError('lookupResources requires an arguments object');
      }
      const parsed = this.#parseArgs(this.#lookupResourcesArgsValidator, 'Invalid lookupResources arguments', args);

      const name = resolveName(parsed, 'lookupResources');
      const subject = this.#normalizeSubject(parsed);
      const resourceType = parsed.resourceType;
      this.#assertCheckable(resourceType, name, 'lookupResources');

      // Cache-backed tuples make the static reverse index incomplete: the
      // backend must opt in by maintaining `rel:rev:<subject>` documents.
      if (this.#reader.enabled && !this.#reverseIndex) {
        throw new KerberosRelationsError(
          'lookupResources over cache-backed tuples requires reverseIndex: true and backend-maintained "rel:rev:<subject>" reverse documents',
        );
      }

      const session = this.#createSession(parsed, opts);
      const ids = await this.#lookupResourcesInternal(subject, resourceType, name, session, this.#limits.maxDepth);
      const sortedIds = [...ids].sort();
      const limitedIds =
        sortedIds.length > this.#limits.maxResults ? sortedIds.slice(0, this.#limits.maxResults) : sortedIds;
      const results = [];
      for (const id of limitedIds) results.push(`${resourceType}:${id}`);
      this.#setSpanAttributes(otel, resourceType, name, {
        'kerberos.result.count': results.length,
        subjectKey: subjectToString(subject),
      });
      return results;
    });
  }

  // -------------------------------------------------------------------------
  // Telemetry plumbing — every call is guarded; a broken tracer/meter must
  // never affect resolution, and with telemetry disabled the public methods
  // run the handler directly (zero instrumentation overhead).
  // -------------------------------------------------------------------------

  #runInstrumented(reqKind, handler) {
    if (!this.#telemetry.enabled) return handler(null);

    const startedAt = getNow();
    return this.#telemetry.withRequestSpan(reqKind, null, null, async (otel) => {
      try {
        return await handler(otel);
      } catch (error) {
        this.#telemetry.recordError(otel, error);
        throw error;
      } finally {
        this.#telemetry.endRequest(otel, reqKind, getNow() - startedAt);
      }
    });
  }

  // `subjectKey`/`resourceId` are identity attributes, gated on the same
  // `includeIdentity` flag as the engine writer; the rest is applied as-is.
  #setSpanAttributes(otel, resourceKind, name, attributes) {
    const span = otel?.span;
    if (!span) return;
    try {
      span.setAttribute?.('kerberos.resource.kind', resourceKind);
      if (name) span.setAttribute?.('kerberos.relations.name', name);
      for (const key of Object.keys(attributes)) {
        if (key === 'subjectKey' || key === 'resourceId') continue;
        span.setAttribute?.(key, attributes[key]);
      }
      if (this.#includeIdentity) {
        if (attributes.subjectKey) span.setAttribute?.('kerberos.relations.subject', attributes.subjectKey);
        if (attributes.resourceId) span.setAttribute?.('kerberos.resource.id', attributes.resourceId);
      }
    } catch {
      // Telemetry must never break resolution.
    }
  }

  // -------------------------------------------------------------------------
  // Argument normalization
  // -------------------------------------------------------------------------

  #parseArgs(validator, label, args) {
    if (!validator) return args;
    try {
      return validator.parse(args);
    } catch (error) {
      throw new KerberosRelationsError(`${label}: ${error.message}`, { cause: error });
    }
  }

  // Object-form resources bypass the string-reference grammar, so their parts
  // are checked here: a `#`/`:` inside an id (or reserved chars in a kind)
  // would make memo keys ambiguous.
  #checkedObjectRef(ref, label) {
    if (!this.#validKinds.has(ref.type)) {
      if (RESERVED_REF_CHARS.test(ref.type)) {
        throw new KerberosRelationsError(
          `Invalid ${label} kind "${ref.type}" — kinds must not contain whitespace, ":", "#", "@", "*" or "|"`,
        );
      }
      this.#validKinds.add(ref.type);
    }
    const id = ref.id;
    if (id.indexOf(':') !== -1 || id.indexOf('#') !== -1) {
      throw new KerberosRelationsError(`Invalid ${label} id "${id}" — ids must not contain ":" or "#"`);
    }
    return ref;
  }

  #normalizeResource(input) {
    if (typeof input === 'string') return this.#checkedObjectRef(parseObjectRef(input, 'resource'), 'resource');
    if (input && typeof input === 'object') {
      if (this.#mapResource) {
        return this.#checkedObjectRef(parseObjectRef(this.#mapResource(input), 'resource'), 'resource');
      }
      if (typeof input.kind === 'string' && typeof input.id === 'string') {
        return this.#checkedObjectRef({ type: input.kind, id: input.id }, 'resource');
      }
      if (typeof input.type === 'string' && typeof input.id === 'string') {
        return this.#checkedObjectRef({ type: input.type, id: input.id }, 'resource');
      }
    }
    throw new KerberosRelationsError('A resource is required — pass a "type:id" string or a { kind, id } object');
  }

  #normalizeSubject(args) {
    if (typeof args.subject === 'string') return parseSubjectRef(args.subject);
    if (args.principal && typeof args.principal === 'object') {
      if (this.#mapPrincipal) return parseSubjectRef(this.#mapPrincipal(args.principal));
      if (typeof args.principal.id === 'string') {
        const id = args.principal.id;
        // Reference-grammar characters in a principal id would make memo keys
        // ambiguous, and a literal '*' id would silently match wildcard
        // tuples — reject instead of guessing.
        if (id === SUBJECT_WILDCARD_ID || id.indexOf(':') !== -1 || id.indexOf('#') !== -1) {
          throw new KerberosRelationsError(`Invalid principal id "${id}" — ids must not be "*" or contain ":" / "#"`);
        }
        return { type: this.#subjectType, id, relation: null };
      }
    }
    throw new KerberosRelationsError('A subject is required — pass a "subject" string or a "principal" object');
  }

  #assertCheckable(resourceType, name, label) {
    if (!this.#schema.isCheckable(resourceType, name)) {
      throw new KerberosRelationsError(`${label}: "${name}" is not a relation or permission of "${resourceType}"`);
    }
  }

  #identityToken(value) {
    if (!value) return 0;
    let token = this.#identityTokens.get(value);
    if (!token) {
      token = this.#identitySeq += 1;
      this.#identityTokens.set(value, token);
    }
    return token;
  }

  // The caller-provided memo is a two-level structure: the outer Map is keyed
  // by SCOPE strings (resolved once per session, never per subproblem) and
  // holds inner Maps with short unscoped keys.
  //
  // - `session.shared` (scope = resolver token) holds IO reads and
  //   caveat-independent walks (`doc|`/`rev|`/`closure|`/`subjects|`): one
  //   memo Map shared with a DIFFERENT resolver instance can never leak its
  //   documents.
  // - `session.decisions` (scope = resolver + principal/context identity
  //   tokens) holds `check|`/`lr|` results, whose caveat outcomes depend on
  //   the principal and check-time context.
  //
  // Same object references → same identity tokens → full sharing (the engine
  // reuses one principal object and one memo across a whole checkResources
  // batch); different references → isolated inner Maps instead of stale reuse.
  #createSession(args, opts) {
    const principal = args.principal && typeof args.principal === 'object' ? args.principal : null;
    const context = args.context && typeof args.context === 'object' ? args.context : null;

    const memo = opts?.memo;
    if (!(memo instanceof Map)) {
      // Private session (no caller-provided memo): nothing can be shared
      // across calls, so skip the scope bookkeeping entirely — hot path for
      // standalone one-shot checks. One Map serves both roles: the namespaced
      // key prefixes (`check|`/`doc|`/...) already keep entries apart, and a
      // private session has exactly one resolver/principal/context.
      const single = new Map();
      return { shared: single, decisions: single, principal, context };
    }

    let shared = memo.get(this.#sharedKey);
    if (!shared) {
      shared = new Map();
      memo.set(this.#sharedKey, shared);
    }

    let decisionsKey;
    if (principal === this.#lastPrincipal && context === this.#lastContext) {
      decisionsKey = this.#lastDecisionsKey;
    } else {
      decisionsKey = `${this.#sharedKey}:p${this.#identityToken(principal)}:c${this.#identityToken(context)}`;
      this.#lastPrincipal = principal;
      this.#lastContext = context;
      this.#lastDecisionsKey = decisionsKey;
    }
    let decisions = memo.get(decisionsKey);
    if (!decisions) {
      decisions = new Map();
      memo.set(decisionsKey, decisions);
    }

    return { shared, decisions, principal, context };
  }

  // -------------------------------------------------------------------------
  // Diagnostics (fail-open logging; early return avoids the timestamp/object
  // allocations entirely when no logger is configured)
  // -------------------------------------------------------------------------

  #logDebug(entry, message) {
    if (!this.#log.enabled) return;
    try {
      this.#log.debug({ timestamp: new Date().toISOString(), ...entry }, message);
    } catch {
      // Diagnostics must never affect resolution.
    }
  }

  #logError(entry, message) {
    if (!this.#log.enabled) return;
    try {
      this.#log.error({ timestamp: new Date().toISOString(), ...entry }, message);
    } catch {
      // Diagnostics must never affect resolution.
    }
  }

  // -------------------------------------------------------------------------
  // Tuple storage — static indexes + cache-backed documents
  // -------------------------------------------------------------------------

  #indexStaticTuple(raw) {
    const tuple = parseTuple(raw);
    const admission = this.#schema.getRelationAdmission(tuple.resource.type, tuple.relation);
    if (!admission) {
      throw new KerberosRelationsError(
        `Invalid tuple — "${tuple.relation}" is not a relation of "${tuple.resource.type}"`,
      );
    }
    if (!admission.has(subjectAdmissionKey(tuple.subject, tuple.caveat))) {
      throw new KerberosRelationsError(
        `Invalid tuple — subject "${subjectToString(tuple.subject)}"${tuple.caveat ? ` with caveat "${tuple.caveat.name}"` : ''} is not allowed on "${tuple.resource.type}#${tuple.relation}"`,
      );
    }

    const forwardKey = `${tuple.resource.type}:${tuple.resource.id}#${tuple.relation}`;
    let entries = this.#forwardIndex.get(forwardKey);
    if (!entries) {
      entries = [];
      this.#forwardIndex.set(forwardKey, entries);
    }
    entries.push({ subject: tuple.subject, caveat: tuple.caveat });

    const reverseKey = subjectToString(tuple.subject);
    let reverseEntries = this.#reverseStaticIndex.get(reverseKey);
    if (!reverseEntries) {
      reverseEntries = [];
      this.#reverseStaticIndex.set(reverseKey, reverseEntries);
    }
    reverseEntries.push({ resource: tuple.resource, relation: tuple.relation, caveat: tuple.caveat });
  }

  async #readCachedEntries(type, id, relation) {
    const key = `rel:${type}:${id}:${relation}`;
    let value;
    try {
      // A transient backend failure surfaces as KerberosCacheError (after the
      // reader's retry loop) and propagates to the caller.
      value = await this.#reader.get(key);
    } catch (error) {
      this.#telemetry.recordCacheRequest('error', CACHE_KIND_RELATION);
      throw error;
    }
    if (value === undefined || value === null) {
      this.#telemetry.recordCacheRequest('miss', CACHE_KIND_RELATION);
      return EMPTY_ENTRIES;
    }

    try {
      const doc = typeof value === 'string' ? JSON.parse(value) : value;
      if (!Array.isArray(doc)) {
        throw new KerberosRelationsError('relation document must be a JSON array of subject entries');
      }
      const admission = this.#schema.getRelationAdmission(type, relation);
      const entries = [];
      for (const raw of doc) {
        const entry = parseDocumentEntry(raw);
        // Entries the schema does not admit are data problems, not crashes:
        // skip them fail-closed and leave a trace for the operator.
        if (!admission.has(subjectAdmissionKey(entry.subject, entry.caveat))) {
          this.#logDebug(
            { event: 'Relations.entrySkipped', key },
            `Kerberos.js relations: skipped subject entry not allowed by schema on "${type}#${relation}"`,
          );
          continue;
        }
        entries.push(entry);
      }
      this.#telemetry.recordCacheRequest('hit', CACHE_KIND_RELATION);
      return entries;
    } catch (error) {
      // A corrupt document THROWS (typed) instead of resolving as empty: in
      // the subtract position of an exclusion an "empty" read would silently
      // WIDEN access (a real editor gains read_only when the editor document
      // fails to parse). Errors are never read as an answer — they propagate
      // per the engine's onError semantics. Genuine absence (miss) stays empty.
      this.#telemetry.recordCacheRequest('error', CACHE_KIND_RELATION);
      this.#logError(
        { event: 'Relations.corruptDocument', key, errorMessage: error.message },
        `Kerberos.js relations: corrupt relation document for "${key}"`,
      );
      throw new KerberosCodecError(`Corrupt relation document for "${key}": ${error.message}`, { cause: error });
    }
  }

  // Doc-level fallback mirrors policy resolution: a static key wins and the
  // cache is only consulted on a full static miss — sources for the SAME
  // (resource, relation) key are never merged.
  //
  // The memo stores the read PROMISE, not the resolved value: a batched
  // checkResources evaluates resources concurrently, so identical document
  // reads can start before the first one settles — memoizing the promise is
  // the in-process equivalent of SpiceDB's singleflight coalescing. (Check
  // subproblems memoize completed values only — an in-flight promise there
  // would deadlock on cyclic data instead of hitting the depth guard.)
  #readRelationEntries(type, id, relation, session) {
    const docKey = `doc|${type}:${id}#${relation}`;
    let promise = session.shared.get(docKey);
    if (!promise) {
      const staticEntries = this.#forwardIndex.get(`${type}:${id}#${relation}`);
      if (staticEntries) promise = Promise.resolve(staticEntries);
      else promise = this.#reader.enabled ? this.#readCachedEntries(type, id, relation) : EMPTY_ENTRIES_PROMISE;
      session.shared.set(docKey, promise);
    }
    return promise;
  }

  async #loadReverseEntries(subjectKey) {
    const staticEntries = this.#reverseStaticIndex.get(subjectKey) ?? EMPTY_ENTRIES;
    if (!this.#reader.enabled || !this.#reverseIndex) return staticEntries;

    // Reverse documents are keyed by the canonical subject string; unlike the
    // forward direction, static and cached entries are UNIONED — a subject can
    // legitimately appear in both static tuples and backend-maintained docs.
    const key = `rel:rev:${subjectKey}`;
    let value;
    try {
      value = await this.#reader.get(key);
    } catch (error) {
      this.#telemetry.recordCacheRequest('error', CACHE_KIND_RELATION);
      throw error;
    }
    if (value === undefined || value === null) {
      this.#telemetry.recordCacheRequest('miss', CACHE_KIND_RELATION);
      return staticEntries;
    }

    try {
      const doc = typeof value === 'string' ? JSON.parse(value) : value;
      if (!Array.isArray(doc)) {
        throw new KerberosRelationsError('reverse document must be a JSON array of entries');
      }
      const entries = staticEntries.length ? [] : null;
      const parsed = [];
      for (const raw of doc) {
        const entry = parseReverseEntry(raw);
        // A reverse entry pointing at a name that is not a relation of the
        // resource type is a data problem — skip it fail-closed.
        if (!this.#schema.getRelationSubjects(entry.resource.type, entry.relation)) {
          this.#logDebug(
            { event: 'Relations.entrySkipped', key },
            `Kerberos.js relations: skipped reverse entry with unknown relation "${entry.resource.type}#${entry.relation}"`,
          );
          continue;
        }
        parsed.push(entry);
      }
      this.#telemetry.recordCacheRequest('hit', CACHE_KIND_RELATION);
      if (!staticEntries.length) return parsed;
      for (const entry of staticEntries) entries.push(entry);
      for (const entry of parsed) entries.push(entry);
      return entries;
    } catch (error) {
      // Same rule as forward documents: corrupt data throws instead of
      // silently narrowing the reverse index (which would drop candidates).
      this.#telemetry.recordCacheRequest('error', CACHE_KIND_RELATION);
      this.#logError(
        { event: 'Relations.corruptDocument', key, errorMessage: error.message },
        `Kerberos.js relations: corrupt reverse document for "${key}"`,
      );
      throw new KerberosCodecError(`Corrupt reverse document for "${key}": ${error.message}`, { cause: error });
    }
  }

  // Promise-memoized like forward documents (reverse reads never recurse).
  #readReverseEntries(subjectKey, session) {
    const memoKey = `rev|${subjectKey}`;
    let promise = session.shared.get(memoKey);
    if (!promise) {
      promise = this.#loadReverseEntries(subjectKey);
      session.shared.set(memoKey, promise);
    }
    return promise;
  }

  // -------------------------------------------------------------------------
  // Caveats — conditions see `{ P, ctx }`, deliberately NOT the resource:
  // SpiceDB caveats only receive context, and keeping R out of scope is what
  // makes memoized subproblems safely shareable across a batch of resources.
  // Written (tuple) context takes precedence over check-time context.
  // -------------------------------------------------------------------------

  #evaluateCaveat(caveat, session) {
    const condition = this.#schema.getCaveat(caveat.name);
    if (!condition) return false;

    // The condition always receives a COPY (or the shared frozen empty
    // object): a mutating raw-function caveat must never poison the stored
    // tuple context or the caller's context object.
    const written = caveat.context;
    const checkTime = session.context;
    let ctx;
    if (written && checkTime) ctx = { ...checkTime, ...written };
    else if (written) ctx = { ...written };
    else if (checkTime) ctx = { ...checkTime };
    else ctx = EMPTY_CONTEXT;

    try {
      return condition.isFulfilled({ P: session.principal, ctx, context: ctx }) === true;
    } catch (error) {
      // A THROWING caveat is an evaluation error, not a "no" — treating it as
      // not-matched would widen access in exclusion subtract positions. It
      // propagates (typed) per the engine's onError semantics; a caveat that
      // EVALUATES to false still simply does not match.
      this.#logError(
        { event: 'Relations.caveatError', caveat: caveat.name, errorMessage: error.message },
        `Kerberos.js relations: caveat "${caveat.name}" threw during evaluation`,
      );
      throw new KerberosRelationsError(`Caveat "${caveat.name}" threw during evaluation: ${error.message}`, {
        cause: error,
      });
    }
  }

  // -------------------------------------------------------------------------
  // Check engine
  // -------------------------------------------------------------------------

  // Single pass over the document: terminal matches (exact subjects,
  // including userset subjects, and type-wide wildcards) resolve immediately
  // and stay ahead of recursion; userset entries are gathered and redispatched
  // only after every cheap terminal candidate has been ruled out.
  async #checkDirect(resource, relation, subject, session, depth) {
    const entries = await this.#readRelationEntries(resource.type, resource.id, relation, session);

    let usersets = null;
    for (const entry of entries) {
      const es = entry.subject;
      const exact = es.type === subject.type && es.id === subject.id && es.relation === subject.relation;
      const wildcard =
        es.relation === null && es.id === SUBJECT_WILDCARD_ID && subject.relation === null && es.type === subject.type;
      if (exact || wildcard) {
        if (!entry.caveat || this.#evaluateCaveat(entry.caveat, session)) return true;
        continue;
      }
      if (es.relation !== null) (usersets ??= []).push(entry);
    }

    if (usersets) {
      // Sequential on purpose: the first match wins, so parallel redispatch
      // would only waste cache reads. A caveat on the userset tuple gates the
      // whole traversal.
      for (const entry of usersets) {
        if (entry.caveat && !this.#evaluateCaveat(entry.caveat, session)) continue;
        const es = entry.subject;
        const matched = await this.#checkInternal(
          { type: es.type, id: es.id },
          es.relation,
          subject,
          session,
          depth - 1,
        );
        if (matched) return true;
      }
    }

    return false;
  }

  #evalRewrite(node, resource, subject, session, depth) {
    const evaluator = this.#rewriteEvaluators[node.kind];
    if (!evaluator) throw new KerberosRelationsError(`Unsupported rewrite node "${node.kind}"`);
    return evaluator(node, resource, subject, session, depth);
  }

  async #checkInternal(resource, name, subject, session, depth) {
    if (depth <= 0) {
      throw new KerberosRelationsError(
        `Relation check exceeded the maximum depth of ${this.#limits.maxDepth} — the relationship graph is recursive or too deep`,
      );
    }

    // Identity: a userset subject trivially contains itself.
    if (subject.relation === name && subject.type === resource.type && subject.id === resource.id) return true;

    // Decisions live in the principal/context-scoped inner map (see
    // #createSession): caveat outcomes depend on them, so a shared memo must
    // never replay a decision computed under a different principal or context.
    const key = `check|${resource.type}:${resource.id}#${name}@${subjectToString(subject)}`;
    if (session.decisions.has(key)) return session.decisions.get(key);

    let result;
    if (this.#schema.getRelationSubjects(resource.type, name)) {
      result = await this.#checkDirect(resource, name, subject, session, depth);
    } else {
      const node = this.#schema.getPermissionNode(resource.type, name);
      // A type or name outside the schema simply resolves to no access.
      result = node ? await this.#evalRewrite(node, resource, subject, session, depth) : false;
    }

    session.decisions.set(key, result);
    return result;
  }

  // -------------------------------------------------------------------------
  // Reachability analysis (structural, memoized per resolver; the memo entry
  // is seeded before the walk so recursive schemas converge) — which
  // relations ON the type can contribute candidates, which arrows jump to
  // other objects, and whether candidates must be re-verified with check()
  // (intersections, exclusions, `.all` arrows or caveated refs on the path —
  // SpiceDB's "optimized vs full entrypoints" distinction).
  // -------------------------------------------------------------------------

  #collectReachabilityNode(type, node, analysis, visited) {
    const collector = this.#reachabilityCollectors[node.kind];
    if (!collector) throw new KerberosRelationsError(`Unsupported rewrite node "${node.kind}"`);
    collector(node, type, analysis, visited);
  }

  #collectReachability(type, name, analysis, visited) {
    const visitKey = `${type}#${name}`;
    if (visited.has(visitKey)) return;
    visited.add(visitKey);

    const refs = this.#schema.getRelationSubjects(type, name);
    if (refs) {
      analysis.entryRelations.add(name);
      for (const ref of refs) if (ref.caveat) analysis.needsCheck = true;
      return;
    }
    const node = this.#schema.getPermissionNode(type, name);
    if (node) this.#collectReachabilityNode(type, node, analysis, visited);
  }

  #analyzeReachability(type, name) {
    const key = `${type}#${name}`;
    let analysis = this.#reachabilityMemo.get(key);
    if (!analysis) {
      analysis = { entryRelations: new Set(), arrowEdges: [], arrowEdgeKeys: new Set(), needsCheck: false };
      this.#reachabilityMemo.set(key, analysis);
      this.#collectReachability(type, name, analysis, new Set());
    }
    return analysis;
  }

  // -------------------------------------------------------------------------
  // Reverse lookups
  // -------------------------------------------------------------------------

  // The membership closure of a subject: every userset (`type:id#relation`)
  // the subject transitively belongs to via direct tuples, plus the type-wide
  // wildcard key. BFS proceeds level by level with each level's reverse reads
  // fired as one settled wave (reads are independent and all needed).
  // `caveated` reports whether any traversed tuple carried a caveat —
  // candidates found through it must then be verified with check().
  #subjectClosure(subject, session) {
    const memoKey = `closure|${subjectToString(subject)}`;
    let promise = session.shared.get(memoKey);
    if (promise) return promise;

    promise = (async () => {
      const members = new Set();
      let caveated = false;
      let level = [subjectToString(subject)];
      if (subject.relation === null && subject.id !== SUBJECT_WILDCARD_ID) level.push(`${subject.type}:*`);
      const seen = new Set(level);

      while (level.length) {
        const reads = [];
        for (const memberKey of level) {
          members.add(memberKey);
          reads.push(this.#readReverseEntries(memberKey, session));
        }
        const entryLists = await settleAll(reads);

        const next = [];
        for (const entries of entryLists) {
          for (const entry of entries) {
            if (entry.caveat) caveated = true;
            // Every tuple `res#rel@member` makes the subject a member of the
            // userset `res#rel`, which may itself appear as a subject elsewhere.
            const usersetKey = `${entry.resource.type}:${entry.resource.id}#${entry.relation}`;
            if (!seen.has(usersetKey)) {
              seen.add(usersetKey);
              next.push(usersetKey);
            }
          }
        }
        level = next;
      }
      return { members, caveated };
    })();
    session.shared.set(memoKey, promise);
    return promise;
  }

  async #lookupResourcesInternal(subject, type, name, session, depth) {
    if (depth <= 0) {
      throw new KerberosRelationsError(
        `Relation lookup exceeded the maximum depth of ${this.#limits.maxDepth} — the relationship graph is recursive or too deep`,
      );
    }

    // Lives with `check|` decisions — verified candidate sets embed caveat outcomes.
    const memoKey = `lr|${type}#${name}@${subjectToString(subject)}`;
    if (session.decisions.has(memoKey)) return session.decisions.get(memoKey);

    const analysis = this.#analyzeReachability(type, name);
    const closure = await this.#subjectClosure(subject, session);
    const candidates = new Set();

    // Entrypoint candidates: reverse entries of any closure member that hit a
    // contributing relation of the target type. All reads fire as one wave
    // (independent, all needed), then a synchronous scan collects candidates.
    const memberReads = [];
    for (const member of closure.members) memberReads.push(this.#readReverseEntries(member, session));
    const memberEntryLists = await settleAll(memberReads);
    for (const entries of memberEntryLists) {
      for (const entry of entries) {
        if (entry.resource.type === type && analysis.entryRelations.has(entry.relation)) {
          candidates.add(entry.resource.id);
        }
      }
    }

    // Arrow candidates. Cross-type arrows recurse in parallel (independent
    // subtrees, all needed); same-type arrows (recursive hierarchies like
    // folder→parent→folder) are resolved as a fixpoint BFS over the candidate
    // set instead of recursing on an identical subproblem.
    const sameTypeEdges = [];
    const crossEdges = [];
    for (const edge of analysis.arrowEdges) {
      if (edge.objectType === type && edge.target === name) sameTypeEdges.push(edge);
      else crossEdges.push(edge);
    }
    if (crossEdges.length) {
      const recursions = [];
      for (const edge of crossEdges) {
        recursions.push(this.#lookupResourcesInternal(subject, edge.objectType, edge.target, session, depth - 1));
      }
      const objectSets = await settleAll(recursions);

      // One wave of reverse reads over every reached object, then a scan.
      const objectReads = [];
      const objectEdges = [];
      for (let i = 0; i < crossEdges.length; i++) {
        const edge = crossEdges[i];
        for (const objectId of objectSets[i]) {
          objectEdges.push(edge);
          objectReads.push(this.#readReverseEntries(`${edge.objectType}:${objectId}`, session));
        }
      }
      const objectEntryLists = await settleAll(objectReads);
      for (let i = 0; i < objectEntryLists.length; i++) {
        const edge = objectEdges[i];
        for (const entry of objectEntryLists[i]) {
          if (entry.resource.type === type && entry.relation === edge.via) candidates.add(entry.resource.id);
        }
      }
    }
    if (sameTypeEdges.length) {
      // Fixpoint BFS in waves: each frontier's reverse reads settle together.
      let frontier = [...candidates];
      while (frontier.length) {
        const reads = [];
        for (const id of frontier) reads.push(this.#readReverseEntries(`${type}:${id}`, session));
        const entryLists = await settleAll(reads);

        const next = [];
        for (const entries of entryLists) {
          for (const entry of entries) {
            if (entry.resource.type !== type || candidates.has(entry.resource.id)) continue;
            for (const edge of sameTypeEdges) {
              if (entry.relation !== edge.via) continue;
              candidates.add(entry.resource.id);
              next.push(entry.resource.id);
              break;
            }
          }
        }
        frontier = next;
      }
    }

    // Verification (SpiceDB LookupResources2 pattern): candidate sets reached
    // through intersections, exclusions, `.all` arrows or caveats are a
    // superset — filter them through the check engine as one settled wave
    // (all results needed, no short-circuit; document reads coalesce through
    // the promise memo).
    let ids = candidates;
    if (analysis.needsCheck || closure.caveated) {
      const candidateList = [];
      const checks = [];
      for (const id of candidates) {
        candidateList.push(id);
        checks.push(this.#checkInternal({ type, id }, name, subject, session, depth - 1));
      }
      const outcomes = await settleAll(checks);
      ids = new Set();
      for (let i = 0; i < outcomes.length; i++) {
        if (outcomes[i] === true) ids.add(candidateList[i]);
      }
    }

    session.decisions.set(memoKey, ids);
    return ids;
  }

  // -------------------------------------------------------------------------
  // lookupSubjects collection
  // -------------------------------------------------------------------------

  async #collectRelationSubjects(resource, relation, session, depth) {
    const result = emptySubjectSet();
    const entries = await this.#readRelationEntries(resource.type, resource.id, relation, session);

    // Single pass: terminal subjects land directly in the set, userset
    // expansions are gathered and resolved as one settled wave (collect needs
    // every branch — there is no short-circuit to preserve).
    let waves = null;
    for (const entry of entries) {
      const es = entry.subject;
      if (es.relation !== null) {
        (waves ??= []).push(
          this.#collectSubjectsInternal({ type: es.type, id: es.id }, es.relation, session, depth - 1),
        );
        continue;
      }
      if (es.id === SUBJECT_WILDCARD_ID) {
        if (!result.wildcards.has(es.type)) result.wildcards.set(es.type, new Set());
        continue;
      }
      addConcrete(result, es.type, es.id);
    }

    if (waves) {
      const expanded = await settleAll(waves);
      for (const set of expanded) unionSubjectSets(result, set);
    }
    return normalizeSubjectSet(result);
  }

  #collectRewriteSubjects(node, resource, session, depth) {
    const collector = this.#subjectCollectors[node.kind];
    if (!collector) throw new KerberosRelationsError(`Unsupported rewrite node "${node.kind}"`);
    return collector(node, resource, session, depth);
  }

  async #collectSubjectsInternal(resource, name, session, depth) {
    if (depth <= 0) {
      throw new KerberosRelationsError(
        `Relation lookup exceeded the maximum depth of ${this.#limits.maxDepth} — the relationship graph is recursive or too deep`,
      );
    }

    // Value-memo (completed results only) — an in-flight promise here would
    // deadlock on cyclic data instead of hitting the depth guard.
    const memoKey = `subjects|${resource.type}:${resource.id}#${name}`;
    if (session.shared.has(memoKey)) return session.shared.get(memoKey);

    let result;
    if (this.#schema.getRelationSubjects(resource.type, name)) {
      result = await this.#collectRelationSubjects(resource, name, session, depth);
    } else {
      const node = this.#schema.getPermissionNode(resource.type, name);
      result = node ? await this.#collectRewriteSubjects(node, resource, session, depth) : emptySubjectSet();
    }

    session.shared.set(memoKey, result);
    return result;
  }
}

function resolveName(args, label) {
  const relation = args.relation ?? args.permission;
  if (typeof relation !== 'string' || !relation.length) {
    throw new KerberosRelationsError(`${label} requires a "relation" or "permission" name`);
  }
  if (args.relation != null && args.permission != null && args.relation !== args.permission) {
    throw new KerberosRelationsError(`${label} received both "relation" and "permission" with different values`);
  }
  return relation;
}

function compareSubjectResults(left, right) {
  const a = typeof left === 'string' ? left : left.subject;
  const b = typeof right === 'string' ? right : right.subject;
  return a < b ? -1 : a > b ? 1 : 0;
}

module.exports = {
  RelationResolver,
};
