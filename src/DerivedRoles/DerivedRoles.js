const { parseDerivedRolesShape } = require('./validation');
const { cloneShapeTree, deepFreeze } = require('../freeze.js');

const { Conditions } = require('../Conditions');
const { compileMatcher } = require('../matching.js');
const { parseConstants, parseVariables } = require('../policyParsers.js');

/**
 * Represents a derived roles definition set.
 */
class DerivedRoles {
  /**
   * Parses a derived roles shape with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parseDerivedRolesShape(shape, options);
  }

  static parseConstants(constants, options = {}) {
    return parseConstants(constants, options);
  }

  static parseVariables(variables, options = {}) {
    return parseVariables(variables, options);
  }

  // Unlike policy rules, a derived-role definition's condition is required, so
  // this intentionally does not share the null-passthrough of policyParsers.
  static parseConditions(conditions, options = {}) {
    return conditions instanceof Conditions ? conditions : new Conditions(conditions, options);
  }

  #shape = null;

  // Condition-backed definitions grouped by name (a set may define one name
  // more than once), and their unique names in definition order — the lazy
  // activation below evaluates by name.
  #conditionDefsByName = new Map();

  #conditionNames = [];

  #hasRelationDefinitions = false;

  /**
   * @param {unknown} shape
   * @param {object} [options]
   */
  constructor(shape, options = {}) {
    this.#shape = cloneShapeTree(DerivedRoles.parseShape(shape, options));
    if (this.#shape.constants) this.#shape.constants = DerivedRoles.parseConstants(this.#shape.constants, options);
    if (this.#shape.variables) this.#shape.variables = DerivedRoles.parseVariables(this.#shape.variables, options);
    if (this.#shape.definitions?.length) {
      const defs = [];
      for (const def of this.#shape.definitions) {
        // A definition is either condition-backed (classic, condition
        // required) or relation-backed (`relation:` present, condition and
        // parentRoles become optional gates). Enforced here so the invariant
        // holds even without a validation backend.
        if (!def.condition && !def.relation) {
          throw new Error(`Derived role definition "${def.name}" must declare a "condition" or a "relation"`);
        }
        // Same rule as every validation backend: a condition-backed
        // definition is gated on its parent roles, so they are required.
        if (!def.relation && !(Array.isArray(def.parentRoles) && def.parentRoles.length)) {
          throw new Error(
            `Derived role definition "${def.name}" requires either "relation" or both "parentRoles" and "condition"`,
          );
        }
        // Never materialize an absent condition (e.g. as null): shapes may be
        // reused across instances, and a written `condition: null` would fail
        // the optional-field validation on the next construction.
        const parsedDef = { ...def };
        if (def.condition) parsedDef.condition = DerivedRoles.parseConditions(def.condition, options);
        if (Array.isArray(def.parentRoles) && def.parentRoles.length) {
          // Cerbos matches parentRoles with globs (`*` and partial patterns
          // like `adm*`) — precompiled here, non-enumerable like the policy
          // rule matchers.
          Object.defineProperty(parsedDef, 'parentRolesMatcher', { value: compileMatcher(def.parentRoles) });
        }
        defs.push(parsedDef);
        if (parsedDef.relation) {
          this.#hasRelationDefinitions = true;
        } else {
          const sameName = this.#conditionDefsByName.get(parsedDef.name);
          if (sameName) sameName.push(parsedDef);
          else {
            this.#conditionDefsByName.set(parsedDef.name, [parsedDef]);
            this.#conditionNames.push(parsedDef.name);
          }
        }
      }
      this.#shape.definitions = defs;
    }

    // Post-construction hardening: the parsed shape IS live evaluation state
    // (stored in the engine's policy Maps), and the constructor-time
    // duplicate/deny integrity guards would be bypassable by mutating
    // `policy.shape` afterwards. Frozen here, matching the codec's frozen
    // shared ASTs and the Relations module's frozen compiled refs.
    deepFreeze(this.#shape);
  }

  get name() {
    return this.#shape.name;
  }

  get roles() {
    const rolesMap = new Map();
    for (const def of this.#shape.definitions) rolesMap.set(def.name, def);
    return rolesMap;
  }

  get shape() {
    return this.#shape;
  }

  /** Whether any definition is relation-backed (resolved on the async phase). */
  get hasRelationDefinitions() {
    return this.#hasRelationDefinitions;
  }

  // Shared evaluation prelude: request enriched with constants/variables plus
  // an O(1) principal-roles set for parent-role gating.
  #buildEvalContext(req) {
    // Skip the request copies when the definition set declares neither
    // constants nor variables (the common case) — conditions then read `C`/`V`
    // as undefined either way.
    const constants = this.#shape.constants?.get();
    const reqWithConstants = constants === undefined ? req : { ...req, constants, C: constants };

    const variables = this.#shape.variables?.get(reqWithConstants);
    const reqWithVariables =
      variables === undefined ? reqWithConstants : { ...reqWithConstants, variables, V: variables };

    return { reqWithVariables, principalRoles: reqWithVariables.P.roles ?? [] };
  }

  /**
   * Resolves active condition-backed derived roles for a request.
   * Relation-backed definitions are skipped here — they require async
   * resolution and are surfaced via `getRelationCandidates` instead.
   *
   * @param {Record<string, unknown>} req
   * @returns {Set<string>}
   */
  get(req) {
    return new Set(this.getActivated(req).keys());
  }

  /**
   * Same resolution as {@link get}, but keyed by role name with the
   * definition's `parentRoles` as the value.
   *
   * Conflict resolution in a resource policy runs per principal role, and a
   * derived role does not form a dimension of its own — it collapses into the
   * principal roles that activated it. The engine therefore needs to know which
   * roles each active derived role stands for, which a bare name cannot say.
   *
   * @param {Record<string, unknown>} req
   * @returns {Map<string, string[]>}
   */
  getActivated(req) {
    const roles = new Map();
    const activation = this.createActivation(req);
    for (const name of activation.names) {
      const active = activation.resolve(name);
      if (active) roles.set(name, active.parentRoles);
    }
    return roles;
  }

  /**
   * Lazy counterpart of {@link getActivated} for one request: `resolve(name)`
   * evaluates that name's condition-backed definitions on first use and
   * memoizes the answer — `{ parentRoles }` when one of them activates (the
   * last active definition wins, as in `getActivated`), `null` otherwise.
   * The engine only resolves the names a rule actually asks about, so a
   * definition no rule needs is never evaluated. `names` lists every
   * condition-backed name in definition order.
   *
   * @param {Record<string, unknown>} req
   * @returns {{
   *   names: readonly string[],
   *   resolve(name: string): { parentRoles: string[] } | null,
   *   peek(name: string): { parentRoles: string[] } | null | undefined,
   * }}
   */
  createActivation(req) {
    const defsByName = this.#conditionDefsByName;
    const results = new Map();
    let context = null;
    return {
      names: this.#conditionNames,
      // The memoized answer, without evaluating (undefined = not resolved yet).
      peek: (name) => results.get(name),
      resolve: (name) => {
        let result = results.get(name);
        if (result !== undefined) return result;
        result = null;
        const defs = defsByName.get(name);
        if (defs) {
          context ??= this.#buildEvalContext(req);
          for (const def of defs) {
            if (!def.parentRolesMatcher.matchesAny(context.principalRoles)) continue;
            if (def.condition.isFulfilled(context.reqWithVariables)) result = { parentRoles: def.parentRoles };
          }
        }
        results.set(name, result);
        return result;
      },
    };
  }

  /**
   * Returns the relation-backed definitions whose synchronous gates
   * (optional `parentRoles`, optional `condition`) pass for this request. The
   * engine resolves the returned relations through the configured `relations`
   * resolver on its async phase.
   *
   * @param {Record<string, unknown>} req
   * @param {ReadonlySet<string>} [names] - only consider definitions with these
   *   names (the engine passes the derived roles its rules reference)
   * @returns {Array<{ name: string, relation: string }>}
   */
  getRelationCandidates(req, names) {
    const candidates = [];

    if (!this.#hasRelationDefinitions || names?.size === 0) return candidates;

    let context = null;
    for (const def of this.#shape.definitions) {
      if (!def.relation) continue;
      if (names && !names.has(def.name)) continue;
      context ??= this.#buildEvalContext(req);

      if (Array.isArray(def.parentRoles) && def.parentRoles.length) {
        if (!def.parentRolesMatcher.matchesAny(context.principalRoles)) continue;
      }
      if (def.condition && !def.condition.isFulfilled(context.reqWithVariables)) continue;

      // `parentRoles` is optional for relation-backed definitions; when absent
      // the role is not gated on a principal role at all, and the engine treats
      // it as standing for every role.
      candidates.push({ name: def.name, relation: def.relation, parentRoles: def.parentRoles ?? null });
    }

    return candidates;
  }
}

module.exports = { DerivedRoles };
