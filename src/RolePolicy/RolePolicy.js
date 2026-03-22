const { Outputs } = require('../Outputs');
const { parseRolePolicyShape } = require('./validation');

const { ALL_ACTIONS, Effect } = require('../schemas');
const { Variables } = require('../Variables');
const { Conditions } = require('../Conditions');
const { Constants } = require('../Constants');

class RolePolicy {
  static parseShape(shape, options = {}) {
    return parseRolePolicyShape(shape, options);
  }

  static parseConstants(constants, options = {}) {
    return constants instanceof Constants ? constants : new Constants(constants, options);
  }

  static parseVariables(variables, options = {}) {
    return variables instanceof Variables ? variables : new Variables(variables, options);
  }

  static parseConditions(conditions, options = {}) {
    if (!conditions) return undefined;
    return conditions instanceof Conditions ? conditions : new Conditions(conditions, options);
  }

  static parseOutputs(outputs, options = {}) {
    if (!outputs) return undefined;
    return outputs instanceof Outputs ? outputs : new Outputs(outputs, options);
  }

  #shape = null;

  constructor(shape, options = {}) {
    this.#shape = RolePolicy.parseShape(shape, options);
    if (this.#shape.rolePolicy.constants) {
      this.#shape.rolePolicy.constants = RolePolicy.parseConstants(this.#shape.rolePolicy.constants, options);
    }
    if (this.#shape.rolePolicy.variables) {
      this.#shape.rolePolicy.variables = RolePolicy.parseVariables(this.#shape.rolePolicy.variables, options);
    }
    if (this.#shape.rolePolicy.rules?.length) {
      const rules = [];
      for (const rule of this.#shape.rolePolicy.rules) {
        rules.push({
          ...rule,
          condition: RolePolicy.parseConditions(rule.condition, options),
          output: RolePolicy.parseOutputs(rule.output, options),
        });
      }
      this.#shape.rolePolicy.rules = rules;
    }
  }

  get role() {
    return this.#shape.rolePolicy.role;
  }

  get version() {
    return this.#shape.rolePolicy.version;
  }

  get scope() {
    return this.#shape.rolePolicy.scope;
  }

  get parentRoles() {
    return this.#shape.rolePolicy.parentRoles ?? [];
  }

  get rules() {
    return this.#shape.rolePolicy.rules;
  }

  get shape() {
    return this.#shape;
  }

  check(req, effectAsBoolean = false) {
    const effects = new Map();
    const outputs = new Map();
    const metaSrcPrefix = `role.${this.role}.v${this.version}`;
    const metaSrcBase = this.scope ? `${metaSrcPrefix}/${this.scope}` : metaSrcPrefix;
    const meta = { actions: {} };

    if (!req.actions?.length) return { effects, outputs, meta };

    const constants = this.#shape.rolePolicy.constants?.get();
    const reqWithConstants = { ...req, constants, C: constants };

    const variables = this.#shape.rolePolicy.variables?.get(reqWithConstants);
    const reqWithVariables = { ...reqWithConstants, variables, V: variables };

    for (const action of reqWithVariables.actions) {
      let matchedResource = false;
      let matchedRule = null;
      let isAllowed = false;

      for (let i = 0; i < this.rules.length; i++) {
        const rule = this.rules[i];
        if (rule.resource !== ALL_ACTIONS && rule.resource !== reqWithVariables.R.kind) continue;

        matchedResource = true;
        if (!rule.allowActions.includes(ALL_ACTIONS) && !rule.allowActions.includes(action)) continue;

        const isConditionFulfilled = rule.condition ? rule.condition.isFulfilled(reqWithVariables) : true;
        const metaSrc = `${metaSrcBase}#${rule.name || `UNNAMED_RULE_${i + 1}`}`;

        if (rule.output) {
          const output = rule.output.build(reqWithVariables, isConditionFulfilled, metaSrc);
          outputs.set(output.src, output);
        }

        if (!isConditionFulfilled) continue;

        isAllowed = true;
        matchedRule = metaSrc;
      }

      if (isAllowed) {
        meta.actions[action] = { matchedPolicy: metaSrcBase, matchedRule };
        if (this.scope) meta.actions[action].matchedScope = this.scope;
        effects.set(action, !effectAsBoolean ? Effect.Allow : true);
        continue;
      }

      if (!matchedResource) continue;

      meta.actions[action] = { matchedPolicy: metaSrcBase };
      if (this.scope) meta.actions[action].matchedScope = this.scope;
      effects.set(action, !effectAsBoolean ? Effect.Deny : false);
    }

    return { effects, outputs, meta };
  }
}

module.exports = { RolePolicy };
