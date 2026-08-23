const { parseDerivedRolesShape } = require('./validation');
const { cloneShapeTree, deepFreeze } = require('../freeze.js');

const { Conditions } = require('../Conditions');
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
        // Never materialize an absent condition (e.g. as null): shapes may be
        // reused across instances, and a written `condition: null` would fail
        // the optional-field validation on the next construction.
        const parsedDef = { ...def };
        if (def.condition) parsedDef.condition = DerivedRoles.parseConditions(def.condition, options);
        defs.push(parsedDef);
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

    return { reqWithVariables, principalRoles: new Set(reqWithVariables.P.roles) };
  }

  static #parentRolesMatch(def, principalRoles) {
    for (const role of def.parentRoles) {
      if (principalRoles.has(role)) return true;
    }
    return false;
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
    const roles = new Set();

    if (!this.#shape.definitions.length) return roles;

    const { reqWithVariables, principalRoles } = this.#buildEvalContext(req);

    for (const def of this.#shape.definitions) {
      if (def.relation) continue;
      if (!DerivedRoles.#parentRolesMatch(def, principalRoles)) continue;

      if (def.condition.isFulfilled(reqWithVariables)) roles.add(def.name);
    }

    return roles;
  }

  /**
   * Returns the relation-backed definitions whose synchronous gates
   * (optional `parentRoles`, optional `condition`) pass for this request. The
   * engine resolves the returned relations through the configured `relations`
   * resolver on its async phase.
   *
   * @param {Record<string, unknown>} req
   * @returns {Array<{ name: string, relation: string }>}
   */
  getRelationCandidates(req) {
    const candidates = [];

    if (!this.#shape.definitions.length) return candidates;

    let context = null;
    for (const def of this.#shape.definitions) {
      if (!def.relation) continue;
      context ??= this.#buildEvalContext(req);

      if (Array.isArray(def.parentRoles) && def.parentRoles.length) {
        if (!DerivedRoles.#parentRolesMatch(def, context.principalRoles)) continue;
      }
      if (def.condition && !def.condition.isFulfilled(context.reqWithVariables)) continue;

      candidates.push({ name: def.name, relation: def.relation });
    }

    return candidates;
  }
}

module.exports = { DerivedRoles };
