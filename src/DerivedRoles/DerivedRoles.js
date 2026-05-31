const { parseDerivedRolesShape } = require('./validation');

const { Variables } = require('../Variables');
const { Conditions } = require('../Conditions');
const { Constants } = require('../Constants');

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
    return constants instanceof Constants ? constants : new Constants(constants, options);
  }

  static parseVariables(variables, options = {}) {
    return variables instanceof Variables ? variables : new Variables(variables, options);
  }

  static parseConditions(conditions, options = {}) {
    return conditions instanceof Conditions ? conditions : new Conditions(conditions, options);
  }

  #shape = null;

  /**
   * @param {unknown} shape
   * @param {object} [options]
   */
  constructor(shape, options = {}) {
    this.#shape = DerivedRoles.parseShape(shape, options);
    if (this.#shape.constants) this.#shape.constants = DerivedRoles.parseConstants(this.#shape.constants, options);
    if (this.#shape.variables) this.#shape.variables = DerivedRoles.parseVariables(this.#shape.variables, options);
    if (this.#shape.definitions?.length) {
      const defs = [];
      for (const def of this.#shape.definitions) {
        defs.push({ ...def, condition: DerivedRoles.parseConditions(def.condition, options) });
      }
      this.#shape.definitions = defs;
    }
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

  /**
   * Resolves active derived roles for a request.
   *
   * @param {Record<string, unknown>} req
   * @returns {Set<string>}
   */
  get(req) {
    const roles = new Set();

    if (!this.#shape.definitions.length) return roles;

    const constants = this.#shape.constants?.get();
    const reqWithConstants = { ...req, constants, C: constants };

    const variables = this.#shape.variables?.get(reqWithConstants);
    const reqWithVariables = { ...reqWithConstants, variables, V: variables };

    // O(1) membership lookups for parent-role matching across all definitions.
    const principalRoles = new Set(reqWithVariables.P.roles);

    for (const def of this.#shape.definitions) {
      let isRoleMatched = false;
      for (const role of def.parentRoles) {
        if (principalRoles.has(role)) {
          isRoleMatched = true;
          break;
        }
      }
      if (!isRoleMatched) continue;

      if (def.condition.isFulfilled(reqWithVariables)) roles.add(def.name);
    }

    return roles;
  }
}

module.exports = { DerivedRoles };
