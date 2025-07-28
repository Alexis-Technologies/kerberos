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

  static parseConstants(constants) {
    return constants instanceof Constants ? constants : new Constants(constants);
  }

  static parseVariables(variables) {
    return variables instanceof Variables ? variables : new Variables(variables);
  }

  static parseConditions(conditions) {
    if (!conditions) return undefined;
    return conditions instanceof Conditions ? conditions : new Conditions(conditions);
  }

  #shape = null;

  constructor(shape, { z } = {}) {
    this.#shape = ResourcePolicy.parseShape(shape, { z });
    if (this.#shape.resourcePolicy.constants) {
      this.#shape.resourcePolicy.constants = ResourcePolicy.parseConstants(this.#shape.resourcePolicy.constants);
    }
    if (this.#shape.resourcePolicy.variables) {
      this.#shape.resourcePolicy.variables = ResourcePolicy.parseVariables(this.#shape.resourcePolicy.variables);
    }
    this.#shape.resourcePolicy.rules = this.#shape.resourcePolicy.rules.map((rule) => ({
      ...rule,
      condition: ResourcePolicy.parseConditions(rule.condition),
    }));
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

  populateVariables(req) {
    const variables = this.#shape.resourcePolicy.variables?.get(req);
    return { ...req, variables, V: variables };
  }

  populateConstants(req) {
    const constants = this.#shape.resourcePolicy.constants?.get();
    return { ...req, constants, C: constants };
  }

  buildEffects(req, derivedRoles) {
    const result = new Map();

    for (const action of req.actions) {
      const actionEffects = [];

      for (const rule of this.rules) {
        // Checking if the rule applies to the action
        if (!rule.actions.includes(ALL_ACTIONS) && !rule.actions.includes(action)) continue;

        // Checking if the roles match
        const rolesMatch = rule.roles?.some((role) => req.P.roles.includes(role)) ?? false;
        const derivedRolesMatch = rule.derivedRoles?.some((role) => derivedRoles.has(role)) ?? false;

        if (!rolesMatch && !derivedRolesMatch) continue;

        // Checking the condition
        const conditionPasses = rule.condition ? rule.condition.isFulfilled(req) : true;
        if (conditionPasses) {
          actionEffects.push(rule.effect);
        }
      }

      if (actionEffects.includes(Effect.Deny)) {
        result.set(action, Effect.Deny);
      } else if (actionEffects.includes(Effect.Allow)) {
        result.set(action, Effect.Allow);
      } else {
        // If there are no rules allowing the action, the default is Deny
        result.set(action, Effect.Deny);
      }
    }

    return result;
  }

  isAllowed(req, derivedRoles) {
    const effects = this.buildEffects(this.populateVariables(this.populateConstants({ ...req, actions: [req.action] })), derivedRoles);
    return effects.get(req.action) === Effect.Allow || effects.get(ALL_ACTIONS) === Effect.Allow;
  }

  // returns map of actions and effects
  check(req, derivedRoles) {
    return this.buildEffects(this.populateVariables(this.populateConstants(req)), derivedRoles);
  }
}

module.exports = { ResourcePolicy };
