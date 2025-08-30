const { Outputs } = require('../Outputs');
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

  static parseOutputs(outputs, { z } = {}) {
    if (!outputs) return undefined;
    return outputs instanceof Outputs ? outputs : new Outputs(outputs, { z });
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
        rules.push({
          ...rule,
          condition: ResourcePolicy.parseConditions(rule.condition, { z }),
          output: ResourcePolicy.parseOutputs(rule.output, { z }),
        });
      }
      this.#shape.resourcePolicy.rules = rules;
    }
  }

  get kind() {
    return this.#shape.resourcePolicy.resource;
  }

  get version() {
    return this.#shape.resourcePolicy.version;
  }

  get scope() {
    return this.#shape.resourcePolicy.scope;
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

  // returns map of actions and effects along with output
  check(req, derivedRoles, effectAsBoolean = false) {
    const effects = new Map();
    const outputs = new Map();
    const metaSrcPrefix = `resource.${this.kind}.v${this.version}`;
    const metaSrcBase = this.scope ? `${metaSrcPrefix}/${this.scope}` : metaSrcPrefix;
    const meta = { actions: {}, effectiveDerivedRoles: [...derivedRoles.values()] };

    if (!req.actions?.length) return { effects, outputs, meta };

    const constants = this.#shape.resourcePolicy.constants?.get();
    const reqWithConstants = { ...req, constants, C: constants };

    const variables = this.#shape.resourcePolicy.variables?.get(reqWithConstants);
    const reqWithVariables = { ...reqWithConstants, variables, V: variables };

    for (const action of reqWithVariables.actions) {
      const actionEffects = [];
      meta.actions[action] = { matchedPolicy: metaSrcBase };

      for (let i = 0; i < this.rules.length; i++) {
        const rule = this.rules[i];
        // Checking if the rule applies to the action
        if (!rule.actions.includes(ALL_ACTIONS) && !rule.actions.includes(action)) continue;

        // Checking if the roles match
        let rolesMatch = false;
        if (rule.roles && Array.isArray(rule.roles)) {
          for (const role of rule.roles) {
            if (reqWithVariables.P.roles.includes(role)) {
              rolesMatch = true;
              break;
            }
          }
        }

        let derivedRolesMatch = false;
        if (rule.derivedRoles && Array.isArray(rule.derivedRoles)) {
          for (const role of rule.derivedRoles) {
            if (derivedRoles.has(role)) {
              derivedRolesMatch = true;
              break;
            }
          }
        }

        if (!rolesMatch && !derivedRolesMatch) continue;

        // Checking the condition
        const isConditionFulfilled = rule.condition ? rule.condition.isFulfilled(reqWithVariables) : true;
        const metaSrc = `${metaSrcBase}#${rule.name || 'UNNAMED_RULE' + `_${i + 1}`}`;

        // Build outputs based on rule activation and condition fulfillment
        if (rule.output) {
          const output = rule.output.build(reqWithVariables, isConditionFulfilled, metaSrc);
          outputs.set(output.src, output);
        }

        if (isConditionFulfilled) {
          actionEffects.push(rule.effect);
          meta.actions[action].matchedRule = metaSrc;
          if (this.scope) meta.actions[action].matchedScope = this.scope;
        }
      }

      if (actionEffects.includes(Effect.Deny)) {
        effects.set(action, !effectAsBoolean ? Effect.Deny : false);
      } else if (actionEffects.includes(Effect.Allow)) {
        effects.set(action, !effectAsBoolean ? Effect.Allow : true);
      } else {
        // If there are no rules allowing the action, the default is Deny
        effects.set(action, !effectAsBoolean ? Effect.Deny : false);
      }
    }

    return { effects, outputs, meta };
  }
}

module.exports = { ResourcePolicy };
