import { ResourcePolicyRootSchemaSchema } from './schemas.js';

import { ALL_ACTIONS, Effect } from '../schemas.js';
import { Variables } from '../Variables/index.js';
import { Conditions } from '../Conditions/index.js';
import { Constants } from '../Constants/index.js';

export class ResourcePolicy {
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

  constructor(schema) {
    this.schema = ResourcePolicyRootSchemaSchema.parse(schema);
    if (this.schema.resourcePolicy.constants) {
      this.schema.resourcePolicy.constants = ResourcePolicy.parseConstants(this.schema.resourcePolicy.constants);
    }
    if (this.schema.resourcePolicy.variables) {
      this.schema.resourcePolicy.variables = ResourcePolicy.parseVariables(this.schema.resourcePolicy.variables);
    }
    this.schema.resourcePolicy.rules = this.schema.resourcePolicy.rules.map((rule) => ({
      ...rule,
      condition: ResourcePolicy.parseConditions(rule.condition),
    }));
  }

  get kind() {
    return this.schema.resourcePolicy.resource;
  }

  get importDerivedRoles() {
    return this.schema.resourcePolicy.importDerivedRoles ?? [];
  }

  get rules() {
    return this.schema.resourcePolicy.rules;
  }

  populateVariables(req) {
    const variables = this.schema.resourcePolicy.variables?.get(req);
    return { ...req, variables, V: variables };
  }

  populateConstants(req) {
    const constants = this.schema.resourcePolicy.constants?.get();
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
        } else if (rule.effect === Effect.Allow) {
          // If the condition is not met, the effect is Deny.
          actionEffects.push(Effect.Deny);
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
