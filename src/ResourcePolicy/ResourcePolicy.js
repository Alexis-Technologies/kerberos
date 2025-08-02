const { ResourcePolicyZodSchemas } = require('./schemas.js');

const { ALL_ACTIONS, Effect } = require('../schemas.js');
const { Variables } = require('../Variables');
const { Conditions } = require('../Conditions');
const { Constants } = require('../Constants');

class ResourcePolicy {
  static parseShape(shape, { schema, z } = {}) {
    if (schema) return schema.parse(shape);
    if (z) return ResourcePolicyZodSchemas.buildShape(z).parse(shape);
    return shape;
  }

  static parseConstants(constants, { z } = {}) {
    return constants instanceof Constants ? constants : new Constants(constants, { z });
  }

  static parseVariables(variables, { z } = {}) {
    return variables instanceof Variables ? variables : new Variables(variables, { z });
  }

  static parseConditions(conditions, { z } = {}) {
    if (!conditions) return undefined;
    return conditions instanceof Conditions ? conditions : new Conditions(conditions, { z });
  }

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = ResourcePolicy.parseShape(shape, { z });
    if (this.#shape.resourcePolicy.constants) {
      this.#shape.resourcePolicy.constants = ResourcePolicy.parseConstants(this.#shape.resourcePolicy.constants, { z });
    }
    if (this.#shape.resourcePolicy.variables) {
      this.#shape.resourcePolicy.variables = ResourcePolicy.parseVariables(this.#shape.resourcePolicy.variables, { z });
    }
    if (this.#shape.resourcePolicy.rules?.length) {
      const rules = [];
      for (const rule of this.#shape.resourcePolicy.rules) {
        rules.push({ ...rule, condition: ResourcePolicy.parseConditions(rule.condition, { z }) });
      }
      this.#shape.resourcePolicy.rules = rules;
    }
  }

  get kind() {
    return this.#shape.resourcePolicy.resource;
  }

  get importDerivedRoles() {
    return this.#shape.resourcePolicy.importDerivedRoles ?? [];
  }

  get rules() {
    return this.#shape.resourcePolicy.rules;
  }

  get shape() {
    return this.#shape;
  }

  // returns map of actions and effects
  check(req, derivedRoles, effectAsBoolean = false) {
    const result = new Map();

    if (!req.actions?.length) return result;

    const constants = this.#shape.resourcePolicy.constants?.get();
    const reqWithConstants = { ...req, constants, C: constants };

    const variables = this.#shape.resourcePolicy.variables?.get(reqWithConstants);
    const reqWithVariables = { ...reqWithConstants, variables, V: variables };

    for (const action of reqWithVariables.actions) {
      const actionEffects = [];

      for (const rule of this.rules) {
        // Checking if the rule applies to the action
        if (!rule.actions.includes(ALL_ACTIONS) && !rule.actions.includes(action)) continue;

        // Checking if the roles match
        const rolesMatch = rule.roles?.some((role) => reqWithVariables.P.roles.includes(role)) ?? false;
        const derivedRolesMatch = rule.derivedRoles?.some((role) => derivedRoles.has(role)) ?? false;

        if (!rolesMatch && !derivedRolesMatch) continue;

        // Checking the condition
        const isConditionFulfilled = rule.condition ? rule.condition.isFulfilled(reqWithVariables) : true;
        if (isConditionFulfilled) actionEffects.push(rule.effect);
      }

      if (actionEffects.includes(Effect.Deny)) {
        result.set(action, !effectAsBoolean ? Effect.Deny : false);
      } else if (actionEffects.includes(Effect.Allow)) {
        result.set(action, !effectAsBoolean ? Effect.Allow : true);
      } else {
        // If there are no rules allowing the action, the default is Deny
        result.set(action, !effectAsBoolean ? Effect.Deny : false);
      }
    }

    return result;
  }
}

module.exports = { ResourcePolicy };
