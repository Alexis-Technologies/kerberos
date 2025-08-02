const { DerivedRolesZodSchemas } = require('./schemas.js');

const { Variables } = require('../Variables');
const { Conditions } = require('../Conditions');
const { Constants } = require('../Constants');

class DerivedRoles {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return DerivedRolesZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  static parseConstants(constants) {
    return constants instanceof Constants ? constants : new Constants(constants);
  }

  static parseVariables(variables) {
    return variables instanceof Variables ? variables : new Variables(variables);
  }

  static parseConditions(conditions) {
    return conditions instanceof Conditions ? conditions : new Conditions(conditions);
  }

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = DerivedRoles.parseShape(shape, { z });
    if (this.#shape.constants) this.#shape.constants = DerivedRoles.parseConstants(this.#shape.constants);
    if (this.#shape.variables) this.#shape.variables = DerivedRoles.parseVariables(this.#shape.variables);
    this.#shape.definitions = this.#shape.definitions.map((def) => ({
      ...def,
      condition: DerivedRoles.parseConditions(def.condition),
    }));
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

  get(req) {
    const roles = new Set();

    if (!this.#shape.definitions.length) return roles;

    const constants = this.#shape.constants?.get();
    const reqWithConstants = { ...req, constants, C: constants };

    const variables = this.#shape.variables?.get(reqWithConstants);
    const reqWithVariables = { ...reqWithConstants, variables, V: variables };

    for (const def of this.#shape.definitions) {
      let isRoleMatched = false;
      for (const role of def.parentRoles) {
        if (reqWithVariables.P.roles.includes(role)) {
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
