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
    return new Map(this.#shape.definitions.map((def) => [def.name, def]));
  }

  get(req) {
    const roles = new Set();

    for (const [name, def] of this.roles) {
      if (this.isRoleMatched(def, this.populateVariables(this.populateConstants(req)))) roles.add(name);
    }

    return roles;
  }

  populateVariables(req) {
    const variables = this.#shape.variables?.get(req);
    return { ...req, variables, V: variables };
  }

  populateConstants(req) {
    const constants = this.#shape.constants?.get();
    return { ...req, constants, C: constants };
  }

  isRoleMatched(def, req) {
    if (!def.parentRoles.some((role) => req.P.roles.includes(role))) return false;
    return def.condition.isFulfilled(req);
  }
}

module.exports = { DerivedRoles };
