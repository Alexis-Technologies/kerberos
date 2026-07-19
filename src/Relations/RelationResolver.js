const { RelationSchema, parseObjectRef, parseSubjectRef, parseTuple } = require('./RelationSchema.js');
const { RelationsJsonSchemas, RelationsTypeBoxSchemas, RelationsZodSchemas } = require('./schemas/index.js');

const { createCacheReader } = require('../caching/cache.js');
const { createLoggerWriter } = require('../logging.js');
const { KerberosRelationsError } = require('../errors.js');
const { parseWithValidation } = require('../validation');

// SpiceDB uses the same default: depth is the only recursion guard — a
// visited-set is deliberately NOT used because it is semantically unsound in
// the presence of exclusions.
const DEFAULT_MAX_DEPTH = 50;
const DEFAULT_MAX_RESULTS = 1000;

const SUBJECT_WILDCARD_ID = '*';

const EMPTY_ENTRIES = Object.freeze([]);

function subjectToString(subject) {
  const base = `${subject.type}:${subject.id}`;
  return subject.relation === null ? base : `${base}#${subject.relation}`;
}

/**
 * Whether a subject entry (with an optional caveat) is admitted by the
 * relation's allowed subject-type refs. Mirrors SpiceDB write-time validation:
 * a concrete subject needs a non-wildcard ref, a `type:*` subject needs the
 * wildcard ref, and a caveated entry needs a ref declaring that exact caveat.
 */
function matchesAllowedRefs(refs, subject, caveat) {
  const caveatName = caveat ? caveat.name : null;
  const isWildcardSubject = subject.relation === null && subject.id === SUBJECT_WILDCARD_ID;
  for (const ref of refs) {
    if (ref.type !== subject.type) continue;
    if (ref.relation !== subject.relation) continue;
    if (ref.wildcard !== isWildcardSubject) continue;
    if (ref.caveat !== caveatName) continue;
    return true;
  }
  return false;
}

/**
 * Creates the built-in in-process "Zanzibar-lite" relation resolver.
 *
 * Implements the Kerberos `relations` delegation contract (`check`/`list`
 * taking `principal`/`resource` objects) plus a standalone SpiceDB-flavoured
 * API (`check` with `subject`/`permission` strings). Static tuples are indexed
 * in memory (zero IO); dynamic tuples are read through the same read-only
 * cache fallback used for policies — storage, TTL, invalidation and reverse
 * documents are fully owned by the backend.
 *
 * @param {object} [options]
 * @returns {{
 *   schema: RelationSchema,
 *   check: (args: Record<string, unknown>, opts?: { memo?: Map<string, unknown> }) => Promise<boolean>,
 *   list: (args: Record<string, unknown>, opts?: { memo?: Map<string, unknown> }) => Promise<Set<string>>,
 * }}
 */
function createRelationResolver(options = {}) {
  const {
    schema,
    tuples,
    cache,
    cacheRetry,
    codec,
    logger,
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

  const compiled = schema instanceof RelationSchema ? schema : new RelationSchema(schema, { z, ajv, typebox, codec });
  const limits = {
    maxDepth: maxDepth ?? DEFAULT_MAX_DEPTH,
    maxResults: maxResults ?? DEFAULT_MAX_RESULTS,
  };
  const reader = createCacheReader(cache, cacheRetry);
  const log = createLoggerWriter(logger);
  const validationOptions = { z, ajv, typebox };

  // Static tuple indexes — both directions are built at construction, so
  // static data supports checks AND reverse lookups with zero IO.
  /** @type {Map<string, Array<{ subject: object, caveat: object | null }>>} */
  const forwardIndex = new Map();
  /** @type {Map<string, Array<{ resource: { type: string, id: string }, relation: string, caveat: object | null }>>} */
  const reverseStaticIndex = new Map();

  function logDebug(entry, message) {
    try {
      log.debug({ timestamp: new Date().toISOString(), ...entry }, message);
    } catch {
      // Diagnostics must never affect resolution.
    }
  }

  function logError(entry, message) {
    try {
      log.error({ timestamp: new Date().toISOString(), ...entry }, message);
    } catch {
      // Diagnostics must never affect resolution.
    }
  }

  function indexStaticTuple(raw) {
    const tuple = parseTuple(raw);
    const refs = compiled.getRelationSubjects(tuple.resource.type, tuple.relation);
    if (!refs) {
      throw new KerberosRelationsError(
        `Invalid tuple — "${tuple.relation}" is not a relation of "${tuple.resource.type}"`,
      );
    }
    if (!matchesAllowedRefs(refs, tuple.subject, tuple.caveat)) {
      throw new KerberosRelationsError(
        `Invalid tuple — subject "${subjectToString(tuple.subject)}"${tuple.caveat ? ` with caveat "${tuple.caveat.name}"` : ''} is not allowed on "${tuple.resource.type}#${tuple.relation}"`,
      );
    }

    const forwardKey = `${tuple.resource.type}:${tuple.resource.id}#${tuple.relation}`;
    let entries = forwardIndex.get(forwardKey);
    if (!entries) {
      entries = [];
      forwardIndex.set(forwardKey, entries);
    }
    entries.push({ subject: tuple.subject, caveat: tuple.caveat });

    const reverseKey = subjectToString(tuple.subject);
    let reverseEntries = reverseStaticIndex.get(reverseKey);
    if (!reverseEntries) {
      reverseEntries = [];
      reverseStaticIndex.set(reverseKey, reverseEntries);
    }
    reverseEntries.push({ resource: tuple.resource, relation: tuple.relation, caveat: tuple.caveat });
  }

  if (tuples !== undefined && tuples !== null) {
    if (!Array.isArray(tuples)) throw new KerberosRelationsError('"tuples" must be an array of relationship tuples');
    for (const raw of tuples) indexStaticTuple(raw);
  }

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

  async function readCachedEntries(type, id, relation) {
    const key = `rel:${type}:${id}:${relation}`;
    // A transient backend failure surfaces as KerberosCacheError (after the
    // reader's retry loop) and propagates to the caller.
    const value = await reader.get(key);
    if (value === undefined || value === null) return EMPTY_ENTRIES;

    try {
      const doc = typeof value === 'string' ? JSON.parse(value) : value;
      if (!Array.isArray(doc)) {
        throw new KerberosRelationsError('relation document must be a JSON array of subject entries');
      }
      const refs = compiled.getRelationSubjects(type, relation);
      const entries = [];
      for (const raw of doc) {
        const entry = parseDocumentEntry(raw);
        // Entries the schema does not admit are data problems, not crashes:
        // skip them fail-closed and leave a trace for the operator.
        if (!matchesAllowedRefs(refs, entry.subject, entry.caveat)) {
          logDebug(
            { event: 'Relations.entrySkipped', key },
            `Kerberos.js relations: skipped subject entry not allowed by schema on "${type}#${relation}"`,
          );
          continue;
        }
        entries.push(entry);
      }
      return entries;
    } catch (error) {
      // A corrupt document is deterministic (retrying cannot help) — treat it
      // as empty instead of failing the check.
      logError(
        { event: 'Relations.corruptDocument', key, errorMessage: error.message },
        `Kerberos.js relations: corrupt relation document for "${key}"`,
      );
      return EMPTY_ENTRIES;
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
  function readRelationEntries(type, id, relation, session) {
    const docKey = `doc|${type}:${id}#${relation}`;
    let promise = session.memo.get(docKey);
    if (!promise) {
      const staticEntries = forwardIndex.get(`${type}:${id}#${relation}`);
      if (staticEntries) promise = Promise.resolve(staticEntries);
      else promise = reader.enabled ? readCachedEntries(type, id, relation) : Promise.resolve(EMPTY_ENTRIES);
      session.memo.set(docKey, promise);
    }
    return promise;
  }

  // Caveat conditions see `{ P, ctx }` — deliberately NOT the resource:
  // SpiceDB caveats only receive context, and keeping R out of scope is what
  // makes memoized subproblems safely shareable across a batch of resources.
  // Written (tuple) context takes precedence over check-time context.
  function evaluateCaveat(caveat, session) {
    const condition = compiled.getCaveat(caveat.name);
    if (!condition) return false;
    const ctx = { ...(session.context ?? {}), ...(caveat.context ?? {}) };
    try {
      return condition.isFulfilled({ P: session.principal, ctx, context: ctx }) === true;
    } catch (error) {
      // A throwing caveat fails closed — the tuple simply does not match.
      logError(
        { event: 'Relations.caveatError', caveat: caveat.name, errorMessage: error.message },
        `Kerberos.js relations: caveat "${caveat.name}" threw and was treated as not matched`,
      );
      return false;
    }
  }

  async function checkDirect(resource, relation, subject, session, depth) {
    const entries = await readRelationEntries(resource.type, resource.id, relation, session);

    // Pass 1: terminal matches — exact subjects (including userset subjects)
    // and type-wide wildcards. Cheap, no recursion.
    for (const entry of entries) {
      const es = entry.subject;
      const exact = es.type === subject.type && es.id === subject.id && es.relation === subject.relation;
      const wildcard =
        es.relation === null && es.id === SUBJECT_WILDCARD_ID && subject.relation === null && es.type === subject.type;
      if (!exact && !wildcard) continue;
      if (entry.caveat && !evaluateCaveat(entry.caveat, session)) continue;
      return true;
    }

    // Pass 2: userset subjects (`group:eng#member`) redispatch recursively. A
    // caveat on the userset tuple gates the whole traversal.
    for (const entry of entries) {
      const es = entry.subject;
      if (es.relation === null) continue;
      if (es.type === subject.type && es.id === subject.id && es.relation === subject.relation) continue;
      if (entry.caveat && !evaluateCaveat(entry.caveat, session)) continue;
      const matched = await checkInternal({ type: es.type, id: es.id }, es.relation, subject, session, depth - 1);
      if (matched) return true;
    }

    return false;
  }

  async function evalRewrite(node, resource, subject, session, depth) {
    switch (node.kind) {
      case 'ref':
        return checkInternal(resource, node.name, subject, session, depth - 1);
      case 'union': {
        // Sequential with short-circuit: the first ALLOW wins and later
        // branches (and their cache reads) are skipped entirely.
        for (const child of node.children) {
          if (await evalRewrite(child, resource, subject, session, depth)) return true;
        }
        return false;
      }
      case 'intersection': {
        for (const child of node.children) {
          if (!(await evalRewrite(child, resource, subject, session, depth))) return false;
        }
        return true;
      }
      case 'exclusion': {
        // Base first (order-sensitive); an empty base short-circuits.
        if (!(await evalRewrite(node.base, resource, subject, session, depth))) return false;
        for (const subtracted of node.subtract) {
          if (await evalRewrite(subtracted, resource, subject, session, depth)) return false;
        }
        return true;
      }
      case 'arrow': {
        const entries = await readRelationEntries(resource.type, resource.id, node.via, session);
        // Compile guarantees tupleset entries are direct object refs; a false
        // caveat removes the tuple, shrinking the reached object set.
        const objects = [];
        for (const entry of entries) {
          if (entry.caveat && !evaluateCaveat(entry.caveat, session)) continue;
          objects.push(entry.subject);
        }
        if (node.all) {
          // Intersection arrow (`.all`): every reached object must grant the
          // target; zero reached objects yield false (SpiceDB semantics).
          if (!objects.length) return false;
          for (const object of objects) {
            const matched = await checkInternal(
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
          const matched = await checkInternal(
            { type: object.type, id: object.id },
            node.target,
            subject,
            session,
            depth - 1,
          );
          if (matched) return true;
        }
        return false;
      }
      default:
        throw new KerberosRelationsError(`Unsupported rewrite node "${node.kind}"`);
    }
  }

  async function checkInternal(resource, name, subject, session, depth) {
    if (depth <= 0) {
      throw new KerberosRelationsError(
        `Relation check exceeded the maximum depth of ${limits.maxDepth} — the relationship graph is recursive or too deep`,
      );
    }

    // Identity: a userset subject trivially contains itself.
    if (subject.relation === name && subject.type === resource.type && subject.id === resource.id) return true;

    const key = `check|${resource.type}:${resource.id}#${name}@${subjectToString(subject)}`;
    if (session.memo.has(key)) return session.memo.get(key);

    let result;
    const relationRefs = compiled.getRelationSubjects(resource.type, name);
    if (relationRefs) {
      result = await checkDirect(resource, name, subject, session, depth);
    } else {
      const node = compiled.getPermissionNode(resource.type, name);
      if (!node) {
        // A type or name outside the schema simply resolves to no access.
        result = false;
      } else {
        result = await evalRewrite(node, resource, subject, session, depth);
      }
    }

    session.memo.set(key, result);
    return result;
  }

  function parseArgs(label, value, build) {
    try {
      return parseWithValidation(value, { ...validationOptions, ...build });
    } catch (error) {
      throw new KerberosRelationsError(`${label}: ${error.message}`, { cause: error });
    }
  }

  function normalizeResource(input) {
    if (typeof input === 'string') return parseObjectRef(input, 'resource');
    if (input && typeof input === 'object') {
      if (typeof mapResource === 'function') return parseObjectRef(mapResource(input), 'resource');
      if (typeof input.kind === 'string' && typeof input.id === 'string') return { type: input.kind, id: input.id };
      if (typeof input.type === 'string' && typeof input.id === 'string') return { type: input.type, id: input.id };
    }
    throw new KerberosRelationsError('A resource is required — pass a "type:id" string or a { kind, id } object');
  }

  function normalizeSubject(args) {
    if (typeof args.subject === 'string') return parseSubjectRef(args.subject);
    if (args.principal && typeof args.principal === 'object') {
      if (typeof mapPrincipal === 'function') return parseSubjectRef(mapPrincipal(args.principal));
      if (typeof args.principal.id === 'string') return { type: subjectType, id: args.principal.id, relation: null };
    }
    throw new KerberosRelationsError('A subject is required — pass a "subject" string or a "principal" object');
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

  function createSession(args, opts) {
    return {
      memo: opts?.memo instanceof Map ? opts.memo : new Map(),
      principal: args.principal && typeof args.principal === 'object' ? args.principal : null,
      context: args.context && typeof args.context === 'object' ? args.context : null,
    };
  }

  function assertCheckable(resourceType, name, label) {
    if (!compiled.isCheckable(resourceType, name)) {
      throw new KerberosRelationsError(`${label}: "${name}" is not a relation or permission of "${resourceType}"`);
    }
  }

  async function check(args, opts = {}) {
    if (!args || typeof args !== 'object') throw new KerberosRelationsError('check requires an arguments object');
    const parsed = parseArgs('Invalid check arguments', args, {
      buildJson: () => RelationsJsonSchemas.buildCheckArgs(),
      buildTypeBox: (t) => RelationsTypeBoxSchemas.buildCheckArgs(t),
      buildZod: (zed) => RelationsZodSchemas.buildCheckArgs(zed),
    });

    const name = resolveName(parsed, 'check');
    const resource = normalizeResource(parsed.resource);
    const subject = normalizeSubject(parsed);
    assertCheckable(resource.type, name, 'check');

    const session = createSession(parsed, opts);
    return checkInternal(resource, name, subject, session, limits.maxDepth);
  }

  async function list(args, opts = {}) {
    if (!args || typeof args !== 'object') throw new KerberosRelationsError('list requires an arguments object');
    const names = args.relations;
    if (!Array.isArray(names) || !names.length) {
      throw new KerberosRelationsError('list requires a non-empty "relations" array');
    }

    const resource = normalizeResource(args.resource);
    const subject = normalizeSubject(args);
    for (const name of names) assertCheckable(resource.type, name, 'list');

    // Sequential on purpose: a shared memo lets later names reuse the
    // subproblems (and cache reads) of earlier ones, and single-threaded JS
    // has no singleflight to dedupe concurrent identical walks.
    const session = createSession(args, opts);
    const granted = new Set();
    for (const name of names) {
      if (await checkInternal(resource, name, subject, session, limits.maxDepth)) granted.add(name);
    }
    return granted;
  }

  // --------------------------------------------------------------------------
  // Reverse APIs — lookupSubjects ("who can access?") and lookupResources
  // ("what can the subject access?"), modeled on SpiceDB's LookupSubjects and
  // LookupResources2 (reachability entrypoints + candidate verification).
  // --------------------------------------------------------------------------

  // Structural reachability analysis per (type, name): which relations ON the
  // type can contribute candidates, which arrows jump to other objects, and
  // whether candidates must be re-verified with check() (any intersection,
  // exclusion, `.all` arrow or caveated ref on the path — SpiceDB's
  // "optimized vs full entrypoints" distinction). Memoized per resolver; the
  // memo entry is seeded before the walk so recursive schemas converge.
  const reachabilityMemo = new Map();

  function collectReachabilityNode(type, node, analysis, visited) {
    switch (node.kind) {
      case 'ref':
        collectReachability(type, node.name, analysis, visited);
        return;
      case 'union':
        for (const child of node.children) collectReachabilityNode(type, child, analysis, visited);
        return;
      case 'intersection':
        // Candidates from the first branch suffice (a member must be in all);
        // verification filters the superset.
        analysis.needsCheck = true;
        collectReachabilityNode(type, node.children[0], analysis, visited);
        return;
      case 'exclusion':
        // Only the base produces candidates; subtraction is verification-only.
        analysis.needsCheck = true;
        collectReachabilityNode(type, node.base, analysis, visited);
        return;
      case 'arrow': {
        if (node.all) analysis.needsCheck = true;
        for (const ref of compiled.getRelationSubjects(type, node.via)) {
          if (ref.caveat) analysis.needsCheck = true;
          const edgeKey = `${node.via}|${ref.type}|${node.target}`;
          if (!analysis.arrowEdgeKeys.has(edgeKey)) {
            analysis.arrowEdgeKeys.add(edgeKey);
            analysis.arrowEdges.push({ via: node.via, objectType: ref.type, target: node.target });
          }
        }
        return;
      }
      default:
        throw new KerberosRelationsError(`Unsupported rewrite node "${node.kind}"`);
    }
  }

  function collectReachability(type, name, analysis, visited) {
    const visitKey = `${type}#${name}`;
    if (visited.has(visitKey)) return;
    visited.add(visitKey);

    const refs = compiled.getRelationSubjects(type, name);
    if (refs) {
      analysis.entryRelations.add(name);
      for (const ref of refs) if (ref.caveat) analysis.needsCheck = true;
      return;
    }
    const node = compiled.getPermissionNode(type, name);
    if (node) collectReachabilityNode(type, node, analysis, visited);
  }

  function analyzeReachability(type, name) {
    const key = `${type}#${name}`;
    let analysis = reachabilityMemo.get(key);
    if (!analysis) {
      analysis = { entryRelations: new Set(), arrowEdges: [], arrowEdgeKeys: new Set(), needsCheck: false };
      reachabilityMemo.set(key, analysis);
      collectReachability(type, name, analysis, new Set());
    }
    return analysis;
  }

  function parseReverseEntry(raw) {
    // 'document:readme#viewer' | { resource: 'document:readme', relation, caveat? }
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

  async function loadReverseEntries(subjectKey) {
    const staticEntries = reverseStaticIndex.get(subjectKey) ?? EMPTY_ENTRIES;
    if (!reader.enabled || !reverseIndex) return staticEntries;

    // Reverse documents are keyed by the canonical subject string; unlike the
    // forward direction, static and cached entries are UNIONED — a subject can
    // legitimately appear in both static tuples and backend-maintained docs.
    const key = `rel:rev:${subjectKey}`;
    const value = await reader.get(key);
    if (value === undefined || value === null) return staticEntries;

    try {
      const doc = typeof value === 'string' ? JSON.parse(value) : value;
      if (!Array.isArray(doc)) {
        throw new KerberosRelationsError('reverse document must be a JSON array of entries');
      }
      const entries = [];
      for (const raw of doc) {
        const entry = parseReverseEntry(raw);
        // A reverse entry pointing at a name that is not a relation of the
        // resource type is a data problem — skip it fail-closed.
        if (!compiled.getRelationSubjects(entry.resource.type, entry.relation)) {
          logDebug(
            { event: 'Relations.entrySkipped', key },
            `Kerberos.js relations: skipped reverse entry with unknown relation "${entry.resource.type}#${entry.relation}"`,
          );
          continue;
        }
        entries.push(entry);
      }
      return staticEntries.length ? [...staticEntries, ...entries] : entries;
    } catch (error) {
      logError(
        { event: 'Relations.corruptDocument', key, errorMessage: error.message },
        `Kerberos.js relations: corrupt reverse document for "${key}"`,
      );
      return staticEntries;
    }
  }

  // Promise-memoized like forward documents (reverse reads never recurse).
  function readReverseEntries(subjectKey, session) {
    const memoKey = `rev|${subjectKey}`;
    let promise = session.memo.get(memoKey);
    if (!promise) {
      promise = loadReverseEntries(subjectKey);
      session.memo.set(memoKey, promise);
    }
    return promise;
  }

  // The membership closure of a subject: every userset (`type:id#relation`)
  // the subject transitively belongs to via direct tuples, plus the type-wide
  // wildcard key. `caveated` reports whether any traversed tuple carried a
  // caveat — candidates found through it must then be verified with check().
  async function subjectClosure(subject, session) {
    const memoKey = `closure|${subjectToString(subject)}`;
    let promise = session.memo.get(memoKey);
    if (promise) return promise;

    promise = (async () => {
      const members = new Set();
      let caveated = false;
      const queue = [subjectToString(subject)];
      if (subject.relation === null && subject.id !== SUBJECT_WILDCARD_ID) queue.push(`${subject.type}:*`);
      const seen = new Set(queue);

      while (queue.length) {
        const memberKey = queue.shift();
        members.add(memberKey);
        for (const entry of await readReverseEntries(memberKey, session)) {
          if (entry.caveat) caveated = true;
          // Every tuple `res#rel@member` makes the subject a member of the
          // userset `res#rel`, which may itself appear as a subject elsewhere.
          const usersetKey = `${entry.resource.type}:${entry.resource.id}#${entry.relation}`;
          if (!seen.has(usersetKey)) {
            seen.add(usersetKey);
            queue.push(usersetKey);
          }
        }
      }
      return { members, caveated };
    })();
    session.memo.set(memoKey, promise);
    return promise;
  }

  async function lookupResourcesInternal(subject, type, name, session, depth) {
    if (depth <= 0) {
      throw new KerberosRelationsError(
        `Relation lookup exceeded the maximum depth of ${limits.maxDepth} — the relationship graph is recursive or too deep`,
      );
    }

    const memoKey = `lr|${type}#${name}@${subjectToString(subject)}`;
    if (session.memo.has(memoKey)) return session.memo.get(memoKey);

    const analysis = analyzeReachability(type, name);
    const closure = await subjectClosure(subject, session);
    const candidates = new Set();

    // Entrypoint candidates: reverse entries of any closure member that hit a
    // contributing relation of the target type.
    for (const member of closure.members) {
      for (const entry of await readReverseEntries(member, session)) {
        if (entry.resource.type === type && analysis.entryRelations.has(entry.relation)) {
          candidates.add(entry.resource.id);
        }
      }
    }

    // Arrow candidates. Cross-type arrows recurse (find objects granting the
    // target, then resources referencing them through the tupleset relation);
    // same-type arrows (recursive hierarchies like folder→parent→folder) are
    // resolved as a fixpoint BFS over the candidate set instead of recursing
    // on an identical subproblem.
    const sameTypeEdges = [];
    for (const edge of analysis.arrowEdges) {
      if (edge.objectType === type && edge.target === name) {
        sameTypeEdges.push(edge);
        continue;
      }
      const objects = await lookupResourcesInternal(subject, edge.objectType, edge.target, session, depth - 1);
      for (const objectId of objects) {
        for (const entry of await readReverseEntries(`${edge.objectType}:${objectId}`, session)) {
          if (entry.resource.type === type && entry.relation === edge.via) candidates.add(entry.resource.id);
        }
      }
    }
    if (sameTypeEdges.length) {
      const queue = [...candidates];
      while (queue.length) {
        const id = queue.shift();
        for (const entry of await readReverseEntries(`${type}:${id}`, session)) {
          if (entry.resource.type !== type || candidates.has(entry.resource.id)) continue;
          for (const edge of sameTypeEdges) {
            if (entry.relation !== edge.via) continue;
            candidates.add(entry.resource.id);
            queue.push(entry.resource.id);
            break;
          }
        }
      }
    }

    // Verification (SpiceDB LookupResources2 pattern): candidate sets reached
    // through intersections, exclusions, `.all` arrows or caveats are a
    // superset — filter them through the check engine (shared memo).
    let ids = candidates;
    if (analysis.needsCheck || closure.caveated) {
      ids = new Set();
      for (const id of candidates) {
        if (await checkInternal({ type, id }, name, subject, session, depth - 1)) ids.add(id);
      }
    }

    session.memo.set(memoKey, ids);
    return ids;
  }

  async function lookupResources(args, opts = {}) {
    if (!args || typeof args !== 'object') {
      throw new KerberosRelationsError('lookupResources requires an arguments object');
    }
    const parsed = parseArgs('Invalid lookupResources arguments', args, {
      buildJson: () => RelationsJsonSchemas.buildLookupResourcesArgs(),
      buildTypeBox: (t) => RelationsTypeBoxSchemas.buildLookupResourcesArgs(t),
      buildZod: (zed) => RelationsZodSchemas.buildLookupResourcesArgs(zed),
    });

    const name = resolveName(parsed, 'lookupResources');
    const subject = normalizeSubject(parsed);
    const resourceType = parsed.resourceType;
    assertCheckable(resourceType, name, 'lookupResources');

    // Cache-backed tuples make the static reverse index incomplete: the
    // backend must opt in by maintaining `rel:rev:<subject>` documents.
    if (reader.enabled && !reverseIndex) {
      throw new KerberosRelationsError(
        'lookupResources over cache-backed tuples requires reverseIndex: true and backend-maintained "rel:rev:<subject>" reverse documents',
      );
    }

    const session = createSession(parsed, opts);
    const ids = await lookupResourcesInternal(subject, resourceType, name, session, limits.maxDepth);
    const sortedIds = [...ids].sort().slice(0, limits.maxResults);
    const results = [];
    for (const id of sortedIds) results.push(`${resourceType}:${id}`);
    return results;
  }

  // --- lookupSubjects ------------------------------------------------------
  // Collected subject sets track concrete subjects plus type-wide wildcards
  // with exclusions (`user:* - {user:anne}`), mirroring SpiceDB's
  // LookupSubjects results. Caveated tuples are INCLUDED (the result is an
  // upper bound for them) — use check() for per-subject certainty.

  function emptySubjectSet() {
    return { concrete: new Set(), wildcards: new Map() };
  }

  function normalizeSubjectSet(set) {
    // An exclusion that is also independently a concrete member is void.
    for (const exclusions of set.wildcards.values()) {
      for (const key of exclusions) if (set.concrete.has(key)) exclusions.delete(key);
    }
    return set;
  }

  function wildcardCovers(set, key) {
    const type = key.slice(0, key.indexOf(':'));
    const exclusions = set.wildcards.get(type);
    return exclusions !== undefined && !exclusions.has(key);
  }

  function unionSubjectSets(target, other) {
    for (const key of other.concrete) target.concrete.add(key);
    for (const [type, otherExclusions] of other.wildcards) {
      const existing = target.wildcards.get(type);
      if (existing === undefined) {
        target.wildcards.set(type, new Set(otherExclusions));
        continue;
      }
      // Excluded from the union only if excluded on both sides.
      for (const key of existing) if (!otherExclusions.has(key)) existing.delete(key);
    }
    return normalizeSubjectSet(target);
  }

  function intersectSubjectSets(a, b) {
    const result = emptySubjectSet();
    for (const key of a.concrete) {
      if (b.concrete.has(key) || wildcardCovers(b, key)) result.concrete.add(key);
    }
    for (const key of b.concrete) {
      if (wildcardCovers(a, key)) result.concrete.add(key);
    }
    for (const [type, aExclusions] of a.wildcards) {
      const bExclusions = b.wildcards.get(type);
      if (bExclusions === undefined) continue;
      result.wildcards.set(type, new Set([...aExclusions, ...bExclusions]));
    }
    return normalizeSubjectSet(result);
  }

  function subtractSubjectSets(target, other) {
    for (const key of [...target.concrete]) {
      if (other.concrete.has(key) || wildcardCovers(other, key)) target.concrete.delete(key);
    }
    for (const [type, exclusions] of [...target.wildcards]) {
      const otherExclusions = other.wildcards.get(type);
      if (otherExclusions !== undefined) {
        // `type:* - type:*` removes the wildcard; the subtrahend's exclusions
        // survive (they were not subtracted) unless excluded here too.
        target.wildcards.delete(type);
        for (const key of otherExclusions) if (!exclusions.has(key)) target.concrete.add(key);
        continue;
      }
      for (const key of other.concrete) {
        if (key.startsWith(`${type}:`)) exclusions.add(key);
      }
    }
    return normalizeSubjectSet(target);
  }

  async function collectRelationSubjects(resource, relation, session, depth) {
    const result = emptySubjectSet();
    for (const entry of await readRelationEntries(resource.type, resource.id, relation, session)) {
      const es = entry.subject;
      if (es.relation !== null) {
        // Userset — expand recursively; SpiceDB's LookupSubjects is
        // auto-recursive through groups.
        const expanded = await collectSubjectsInternal({ type: es.type, id: es.id }, es.relation, session, depth - 1);
        unionSubjectSets(result, expanded);
        continue;
      }
      if (es.id === SUBJECT_WILDCARD_ID) {
        if (!result.wildcards.has(es.type)) result.wildcards.set(es.type, new Set());
        continue;
      }
      result.concrete.add(`${es.type}:${es.id}`);
    }
    return normalizeSubjectSet(result);
  }

  async function collectRewriteSubjects(node, resource, session, depth) {
    switch (node.kind) {
      case 'ref':
        return collectSubjectsInternal(resource, node.name, session, depth - 1);
      case 'union': {
        const result = emptySubjectSet();
        for (const child of node.children) {
          unionSubjectSets(result, await collectRewriteSubjects(child, resource, session, depth));
        }
        return result;
      }
      case 'intersection': {
        let result = await collectRewriteSubjects(node.children[0], resource, session, depth);
        for (let i = 1; i < node.children.length; i++) {
          result = intersectSubjectSets(
            result,
            await collectRewriteSubjects(node.children[i], resource, session, depth),
          );
        }
        return result;
      }
      case 'exclusion': {
        const result = await collectRewriteSubjects(node.base, resource, session, depth);
        for (const subtracted of node.subtract) {
          subtractSubjectSets(result, await collectRewriteSubjects(subtracted, resource, session, depth));
        }
        return result;
      }
      case 'arrow': {
        const entries = await readRelationEntries(resource.type, resource.id, node.via, session);
        const objects = [];
        for (const entry of entries) objects.push(entry.subject);
        if (node.all) {
          if (!objects.length) return emptySubjectSet();
          let result = await collectSubjectsInternal(
            { type: objects[0].type, id: objects[0].id },
            node.target,
            session,
            depth - 1,
          );
          for (let i = 1; i < objects.length; i++) {
            result = intersectSubjectSets(
              result,
              await collectSubjectsInternal(
                { type: objects[i].type, id: objects[i].id },
                node.target,
                session,
                depth - 1,
              ),
            );
          }
          return result;
        }
        const result = emptySubjectSet();
        for (const object of objects) {
          unionSubjectSets(
            result,
            await collectSubjectsInternal({ type: object.type, id: object.id }, node.target, session, depth - 1),
          );
        }
        return result;
      }
      default:
        throw new KerberosRelationsError(`Unsupported rewrite node "${node.kind}"`);
    }
  }

  async function collectSubjectsInternal(resource, name, session, depth) {
    if (depth <= 0) {
      throw new KerberosRelationsError(
        `Relation lookup exceeded the maximum depth of ${limits.maxDepth} — the relationship graph is recursive or too deep`,
      );
    }

    // Value-memo (completed results only) — an in-flight promise here would
    // deadlock on cyclic data instead of hitting the depth guard.
    const memoKey = `subjects|${resource.type}:${resource.id}#${name}`;
    if (session.memo.has(memoKey)) return session.memo.get(memoKey);

    let result;
    if (compiled.getRelationSubjects(resource.type, name)) {
      result = await collectRelationSubjects(resource, name, session, depth);
    } else {
      const node = compiled.getPermissionNode(resource.type, name);
      result = node ? await collectRewriteSubjects(node, resource, session, depth) : emptySubjectSet();
    }

    session.memo.set(memoKey, result);
    return result;
  }

  async function lookupSubjects(args, opts = {}) {
    if (!args || typeof args !== 'object') {
      throw new KerberosRelationsError('lookupSubjects requires an arguments object');
    }
    const parsed = parseArgs('Invalid lookupSubjects arguments', args, {
      buildJson: () => RelationsJsonSchemas.buildLookupSubjectsArgs(),
      buildTypeBox: (t) => RelationsTypeBoxSchemas.buildLookupSubjectsArgs(t),
      buildZod: (zed) => RelationsZodSchemas.buildLookupSubjectsArgs(zed),
    });

    const name = resolveName(parsed, 'lookupSubjects');
    const resource = normalizeResource(parsed.resource);
    assertCheckable(resource.type, name, 'lookupSubjects');

    const session = createSession(parsed, opts);
    const collected = await collectSubjectsInternal(resource, name, session, limits.maxDepth);

    const subjectType = typeof parsed.subjectType === 'string' ? parsed.subjectType : null;
    const results = [];
    for (const key of collected.concrete) {
      if (subjectType && !key.startsWith(`${subjectType}:`)) continue;
      results.push(key);
    }
    for (const [type, exclusions] of collected.wildcards) {
      if (subjectType && type !== subjectType) continue;
      if (exclusions.size) results.push({ subject: `${type}:*`, exclusions: [...exclusions].sort() });
      else results.push(`${type}:*`);
    }
    results.sort((left, right) => {
      const a = typeof left === 'string' ? left : left.subject;
      const b = typeof right === 'string' ? right : right.subject;
      return a < b ? -1 : a > b ? 1 : 0;
    });
    return results.slice(0, limits.maxResults);
  }

  return {
    schema: compiled,
    check,
    list,
    lookupSubjects,
    lookupResources,
  };
}

module.exports = {
  createRelationResolver,
};
