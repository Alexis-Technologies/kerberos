const { DerivedRolesSchemaSchema } = require('./schemas.js');

const { Variables } = require('../Variables');
const { Conditions } = require('../Conditions');
const { Constants } = require('../Constants');

class DerivedRoles {
  static parseConstants(constants) {
    return constants instanceof Constants ? constants : new Constants(constants);
  }

  static parseVariables(variables) {
    return variables instanceof Variables ? variables : new Variables(variables);
  }

  static parseConditions(conditions) {
    return conditions instanceof Conditions ? conditions : new Conditions(conditions);
  }

  constructor(schema) {
    this.schema = DerivedRolesSchemaSchema.parse(schema);
    if (this.schema.constants) this.schema.constants = DerivedRoles.parseConstants(this.schema.constants);
    if (this.schema.variables) this.schema.variables = DerivedRoles.parseVariables(this.schema.variables);
    this.schema.definitions = this.schema.definitions.map((def) => ({
      ...def,
      condition: DerivedRoles.parseConditions(def.condition),
    }));
  }

  get name() {
    return this.schema.name;
  }

  get roles() {
    return new Map(this.schema.definitions.map((def) => [def.name, def]));
  }

  get(req) {
    const roles = new Set();

    for (const [name, def] of this.roles) {
      if (this.isRoleMatched(def, this.populateVariables(this.populateConstants(req)))) roles.add(name);
    }

    return roles;
  }

  populateVariables(req) {
    const variables = this.schema.variables?.get(req);
    return { ...req, variables, V: variables };
  }

  populateConstants(req) {
    const constants = this.schema.constants?.get();
    return { ...req, constants, C: constants };
  }

  isRoleMatched(def, req) {
    if (!def.parentRoles.some((role) => req.P.roles.includes(role))) return false;
    return def.condition.isFulfilled(req);
  }
}

module.exports = { DerivedRoles };
