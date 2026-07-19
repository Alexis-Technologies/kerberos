const { parseRelationSchemaShape } = require('./validation');

const { Conditions } = require('../Conditions');
const { KerberosRelationsError } = require('../errors.js');

// Characters reserved by the tuple/reference grammar. Names (definition,
// relation, permission, caveat) must never contain them, so string references
// like `document:readme#viewer@user:emilia` always parse unambiguously.
const RESERVED_NAME_CHARS = /[\s:#@*]/;

const SUBJECT_WILDCARD_ID = '*';

function assertName(kind, name) {
  if (typeof name !== 'string' || !name.length || RESERVED_NAME_CHARS.test(name)) {
    throw new KerberosRelationsError(
      `Invalid ${kind} name "${name}" — names must be non-empty and must not contain whitespace, ":", "#", "@" or "*"`,
    );
  }
  return name;
}

/**
 * Canonical key of an allowed-subject shape. Each relation precomputes the Set
 * of admissible keys at compile time, turning per-entry admission checks (one
 * per tuple/document entry) into a single O(1) Set lookup.
 *
 * @param {string} type
 * @param {string | null} relation
 * @param {boolean} wildcard
 * @param {string | null} caveat
 * @returns {string}
 */
function buildAdmissionKey(type, relation, wildcard, caveat) {
  return `${type}|${relation ?? ''}|${wildcard ? '*' : ''}|${caveat ?? ''}`;
}

/**
 * Parses an object reference string (`type:id`) into its parts.
 *
 * @param {string} ref
 * @param {string} [label]
 * @returns {{ type: string, id: string }}
 */
function parseObjectRef(ref, label = 'object') {
  if (typeof ref !== 'string') {
    throw new KerberosRelationsError(`Invalid ${label} reference — expected a "type:id" string`);
  }
  const separator = ref.indexOf(':');
  if (separator <= 0 || separator === ref.length - 1) {
    throw new KerberosRelationsError(`Invalid ${label} reference "${ref}" — expected "type:id"`);
  }
  return { type: ref.slice(0, separator), id: ref.slice(separator + 1) };
}

/**
 * Parses a subject reference string (`type:id`, `type:*` or `type:id#relation`)
 * into its parts. A `*` id denotes the type-wide wildcard subject.
 *
 * @param {string} ref
 * @returns {{ type: string, id: string, relation: string | null }}
 */
function parseSubjectRef(ref) {
  if (typeof ref !== 'string') {
    throw new KerberosRelationsError('Invalid subject reference — expected a "type:id" string');
  }
  let base = ref;
  let relation = null;
  const hash = ref.indexOf('#');
  if (hash !== -1) {
    relation = ref.slice(hash + 1);
    base = ref.slice(0, hash);
    if (!relation) throw new KerberosRelationsError(`Invalid subject reference "${ref}" — empty subject relation`);
  }
  const { type, id } = parseObjectRef(base, 'subject');
  if (relation !== null && id === SUBJECT_WILDCARD_ID) {
    throw new KerberosRelationsError(`Invalid subject reference "${ref}" — a wildcard subject cannot have a relation`);
  }
  return { type, id, relation };
}

/**
 * Parses a relationship tuple in either the canonical string form
 * (`resourceType:id#relation@subjectType:id[#subjectRelation]`) or the object
 * form (`{ resource, relation, subject, caveat? }`).
 *
 * @param {unknown} raw
 * @returns {{
 *   resource: { type: string, id: string },
 *   relation: string,
 *   subject: { type: string, id: string, relation: string | null },
 *   caveat: { name: string, context: Record<string, unknown> | null } | null,
 * }}
 */
function parseTuple(raw) {
  if (typeof raw === 'string') {
    // Resource ids must not contain `#`/`@` so the first `#` and the first `@`
    // after it are unambiguous separators (subject ids may still contain `@`,
    // e.g. email-like ids).
    const hash = raw.indexOf('#');
    const at = hash === -1 ? -1 : raw.indexOf('@', hash + 1);
    if (hash === -1 || at === -1) {
      throw new KerberosRelationsError(
        `Invalid tuple "${raw}" — expected "resourceType:id#relation@subjectType:id[#subjectRelation]"`,
      );
    }
    return {
      resource: parseObjectRef(raw.slice(0, hash), 'resource'),
      relation: assertName('relation', raw.slice(hash + 1, at)),
      subject: parseSubjectRef(raw.slice(at + 1)),
      caveat: null,
    };
  }

  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    let caveat = null;
    if (raw.caveat !== undefined && raw.caveat !== null) {
      if (typeof raw.caveat !== 'object' || typeof raw.caveat.name !== 'string') {
        throw new KerberosRelationsError('Invalid tuple caveat — expected { name, context? }');
      }
      caveat = { name: raw.caveat.name, context: raw.caveat.context ?? null };
    }
    return {
      resource: parseObjectRef(raw.resource, 'resource'),
      relation: assertName('relation', raw.relation),
      subject: parseSubjectRef(raw.subject),
      caveat,
    };
  }

  throw new KerberosRelationsError(
    'Invalid tuple — expected a canonical string or a { resource, relation, subject } object',
  );
}

/**
 * Compiled ReBAC schema: definitions with relations (allowed subject types)
 * and permissions (userset-rewrite trees), plus a caveat registry.
 *
 * The compiled representation mirrors SpiceDB's `core.UsersetRewrite` algebra:
 * permission expressions lower to `{ kind: 'ref' | 'arrow' | 'union' |
 * 'intersection' | 'exclusion' }` nodes. All cross-references are validated
 * fail-fast at construction — an invalid schema must never make it into a
 * running resolver.
 */
class RelationSchema {
  /**
   * Parses a relation schema shape with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parseRelationSchemaShape(shape, options);
  }

  /**
   * Builds the caveat condition for a definition. JSON-authored caveats use
   * `{ match: { $expr } }` descriptors and require a codec to compile — the
   * same eval-free path used for dynamic policies.
   *
   * @param {string} name
   * @param {unknown} def
   * @param {object} [options]
   * @returns {Conditions}
   */
  static parseCaveat(name, def, options = {}) {
    if (def instanceof Conditions) return def;
    if (!def || typeof def !== 'object' || !Object.prototype.hasOwnProperty.call(def, 'match')) {
      throw new KerberosRelationsError(`Caveat "${name}" must define a "match" condition`);
    }

    let shape = def;
    const match = def.match;
    if (match && typeof match === 'object' && Object.prototype.hasOwnProperty.call(match, '$expr')) {
      if (typeof options.codec?.deserialize !== 'function') {
        throw new KerberosRelationsError(
          `Caveat "${name}" uses an { $expr } descriptor — provide a codec ` +
            "(e.g. createSafeExprCodec({ jsep, roots: ['P', 'ctx'] })) to compile it",
        );
      }
      try {
        shape = options.codec.deserialize(def);
      } catch (error) {
        throw new KerberosRelationsError(`Failed to compile caveat "${name}": ${error.message}`, { cause: error });
      }
    }

    // `schema`/`codec` are relation-schema options and must not leak into the
    // Conditions parser (an explicit schema there would validate the wrong shape).
    const { schema, codec, ...conditionOptions } = options;
    return new Conditions(shape, conditionOptions);
  }

  #shape = null;

  /** @type {Map<string, Conditions>} */
  #caveats = new Map();

  /** @type {Map<string, { relations: Map<string, unknown[]>, permissions: Map<string, unknown> }>} */
  #definitions = new Map();

  /**
   * @param {unknown} shape
   * @param {object} [options]
   */
  constructor(shape, options = {}) {
    this.#shape = RelationSchema.parseShape(shape, options);
    const root = this.#shape?.relationSchema;
    if (!root || typeof root !== 'object') {
      throw new KerberosRelationsError('A relation schema must define a "relationSchema" object');
    }
    this.#compileCaveats(root.caveats, options);
    this.#compileDefinitions(root.definitions);
  }

  get shape() {
    return this.#shape;
  }

  get definitions() {
    return this.#definitions;
  }

  get caveats() {
    return this.#caveats;
  }

  hasDefinition(type) {
    return this.#definitions.has(type);
  }

  /**
   * Returns the normalized allowed-subject refs of a relation, or undefined.
   *
   * @param {string} type
   * @param {string} name
   * @returns {Array<{ type: string, relation: string | null, wildcard: boolean, caveat: string | null }> | undefined}
   */
  getRelationSubjects(type, name) {
    return this.#definitions.get(type)?.relations.get(name)?.refs;
  }

  /**
   * Returns the precomputed admission-key Set of a relation (see
   * `buildAdmissionKey`), or undefined when `name` is not a relation.
   *
   * @param {string} type
   * @param {string} name
   * @returns {Set<string> | undefined}
   */
  getRelationAdmission(type, name) {
    return this.#definitions.get(type)?.relations.get(name)?.admission;
  }

  /**
   * Returns the compiled rewrite node of a permission, or undefined.
   *
   * @param {string} type
   * @param {string} name
   * @returns {unknown}
   */
  getPermissionNode(type, name) {
    return this.#definitions.get(type)?.permissions.get(name);
  }

  /**
   * Whether `name` is checkable on `type` (declared as a relation or a permission).
   *
   * @param {string} type
   * @param {string} name
   * @returns {boolean}
   */
  isCheckable(type, name) {
    const definition = this.#definitions.get(type);
    return Boolean(definition && (definition.relations.has(name) || definition.permissions.has(name)));
  }

  getCaveat(name) {
    return this.#caveats.get(name);
  }

  #compileCaveats(caveats, options) {
    if (caveats === undefined || caveats === null) return;
    if (typeof caveats !== 'object' || Array.isArray(caveats)) {
      throw new KerberosRelationsError('relationSchema.caveats must be an object of named caveats');
    }
    for (const [name, def] of Object.entries(caveats)) {
      assertName('caveat', name);
      this.#caveats.set(name, RelationSchema.parseCaveat(name, def, options));
    }
  }

  #compileDefinitions(definitions) {
    if (!definitions || typeof definitions !== 'object' || Array.isArray(definitions)) {
      throw new KerberosRelationsError('relationSchema.definitions must be a non-empty object');
    }
    const entries = Object.entries(definitions);
    if (!entries.length) {
      throw new KerberosRelationsError('relationSchema.definitions must declare at least one definition');
    }

    // Pass 1: register every definition with raw members so cross-definition
    // references validate in pass 2 regardless of declaration order.
    for (const [type, def] of entries) {
      assertName('definition', type);
      if (!def || typeof def !== 'object' || Array.isArray(def)) {
        throw new KerberosRelationsError(`Definition "${type}" must be an object`);
      }
      const relations = new Map(Object.entries(def.relations ?? {}));
      const permissions = new Map(Object.entries(def.permissions ?? {}));
      for (const name of relations.keys()) assertName('relation', name);
      for (const name of permissions.keys()) {
        assertName('permission', name);
        if (relations.has(name)) {
          throw new KerberosRelationsError(
            `Definition "${type}" declares "${name}" as both a relation and a permission`,
          );
        }
      }
      this.#definitions.set(type, { relations, permissions });
    }

    // Pass 2: normalize subject refs (building both the ref list and the
    // O(1) admission-key Set in the same pass), then compile permission
    // expressions. Relations are normalized before permissions so arrow
    // validation can rely on the normalized tupleset refs of the same
    // definition.
    for (const [type, compiled] of this.#definitions) {
      for (const [name, refs] of compiled.relations) {
        if (!Array.isArray(refs) || !refs.length) {
          throw new KerberosRelationsError(
            `Relation "${type}#${name}" must declare a non-empty array of subject types`,
          );
        }
        const normalizedRefs = [];
        const admission = new Set();
        for (const ref of refs) {
          const normalized = this.#normalizeSubjectTypeRef(ref, `${type}#${name}`);
          normalizedRefs.push(normalized);
          admission.add(
            buildAdmissionKey(normalized.type, normalized.relation, normalized.wildcard, normalized.caveat),
          );
        }
        compiled.relations.set(name, { refs: normalizedRefs, admission });
      }
      for (const [name, expr] of compiled.permissions) {
        compiled.permissions.set(name, this.#compilePermissionExpr(type, name, expr));
      }
    }
  }

  // 'user' | 'user:*' | 'group#member' | { type, relation?, wildcard?, caveat? }
  #normalizeSubjectTypeRef(raw, where) {
    let type;
    let relation = null;
    let wildcard = false;
    let caveat = null;

    if (typeof raw === 'string') {
      type = raw;
      if (type.endsWith(':*')) {
        wildcard = true;
        type = type.slice(0, -2);
      } else {
        const hash = type.indexOf('#');
        if (hash !== -1) {
          relation = type.slice(hash + 1);
          type = type.slice(0, hash);
        }
      }
    } else if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
      type = raw.type;
      relation = raw.relation ?? null;
      wildcard = raw.wildcard === true;
      caveat = raw.caveat ?? null;
    } else {
      throw new KerberosRelationsError(`Relation "${where}" has an invalid subject type reference`);
    }

    assertName('subject type', type);
    if (relation !== null) assertName('subject relation', relation);
    if (caveat !== null) assertName('caveat', caveat);
    if (wildcard && relation !== null) {
      throw new KerberosRelationsError(`Relation "${where}" — a wildcard subject type cannot have a subject relation`);
    }
    if (!this.#definitions.has(type)) {
      throw new KerberosRelationsError(`Relation "${where}" references unknown definition "${type}"`);
    }
    if (relation !== null && !this.isCheckable(type, relation)) {
      throw new KerberosRelationsError(`Relation "${where}" references unknown subject relation "${type}#${relation}"`);
    }
    if (caveat !== null && !this.#caveats.has(caveat)) {
      throw new KerberosRelationsError(`Relation "${where}" references unknown caveat "${caveat}"`);
    }

    return { type, relation, wildcard, caveat };
  }

  #compileChildren(type, permName, children, operator) {
    if (!Array.isArray(children) || !children.length) {
      throw new KerberosRelationsError(`Permission "${type}#${permName}" — "${operator}" must be a non-empty array`);
    }
    const compiledChildren = [];
    for (const child of children) compiledChildren.push(this.#compilePermissionExpr(type, permName, child));
    return compiledChildren;
  }

  #compilePermissionExpr(type, permName, expr) {
    const where = `${type}#${permName}`;

    if (typeof expr === 'string') {
      if (!this.isCheckable(type, expr)) {
        throw new KerberosRelationsError(`Permission "${where}" references unknown relation or permission "${expr}"`);
      }
      return { kind: 'ref', name: expr };
    }

    if (!expr || typeof expr !== 'object' || Array.isArray(expr)) {
      throw new KerberosRelationsError(`Permission "${where}" has an invalid expression`);
    }

    // Own-property checks only: a prototype-injected operator key must not be
    // able to steer which branch compiles (mirrors Kerberos.parsePolicy).
    const has = (key) => Object.prototype.hasOwnProperty.call(expr, key);
    const operators = ['via', 'anyOf', 'allOf', 'exclude'].filter(has);
    if (operators.length !== 1) {
      throw new KerberosRelationsError(
        `Permission "${where}" must use exactly one of "via", "anyOf", "allOf" or "exclude"`,
      );
    }

    if (has('anyOf')) return { kind: 'union', children: this.#compileChildren(type, permName, expr.anyOf, 'anyOf') };
    if (has('allOf')) {
      return { kind: 'intersection', children: this.#compileChildren(type, permName, expr.allOf, 'allOf') };
    }
    if (has('exclude')) {
      const exclude = expr.exclude;
      if (!exclude || typeof exclude !== 'object' || !Object.prototype.hasOwnProperty.call(exclude, 'base')) {
        throw new KerberosRelationsError(`Permission "${where}" — "exclude" must be a { base, subtract } object`);
      }
      return {
        kind: 'exclusion',
        base: this.#compilePermissionExpr(type, permName, exclude.base),
        subtract: this.#compileChildren(type, permName, exclude.subtract, 'exclude.subtract'),
      };
    }

    // Arrow (tuple-to-userset): via must be a relation of this definition whose
    // subject types are all direct object refs — SpiceDB forbids wildcards and
    // subject relations in tupleset relations, which keeps traversal
    // unambiguous. The target must exist on every reachable type.
    const via = expr.via;
    const target = expr.permission;
    if (typeof target !== 'string' || !target.length) {
      throw new KerberosRelationsError(`Permission "${where}" — arrow requires a "permission" target name`);
    }
    const tupleset = this.#definitions.get(type).relations.get(via)?.refs;
    if (!tupleset) {
      throw new KerberosRelationsError(
        `Permission "${where}" — arrow "via" must reference a relation of "${type}" (got "${via}")`,
      );
    }
    for (const ref of tupleset) {
      if (ref.wildcard || ref.relation !== null) {
        throw new KerberosRelationsError(
          `Permission "${where}" cannot arrow through "${via}" — tupleset relations must contain only direct object subject types (no wildcards or subject relations)`,
        );
      }
      if (!this.isCheckable(ref.type, target)) {
        throw new KerberosRelationsError(
          `Permission "${where}" — arrow target "${target}" does not exist on "${ref.type}" (reached via "${via}")`,
        );
      }
    }
    return { kind: 'arrow', via, target, all: expr.all === true };
  }
}

module.exports = {
  RelationSchema,
  buildAdmissionKey,
  parseObjectRef,
  parseSubjectRef,
  parseTuple,
};
