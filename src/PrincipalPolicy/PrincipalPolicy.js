const { Outputs } = require('../Outputs');
const { parsePrincipalPolicyShape } = require('./validation');

const { ALL_ACTIONS, Effect } = require('../schemas');
const { Variables } = require('../Variables');
const { Conditions } = require('../Conditions');
const { Constants } = require('../Constants');

class PrincipalPolicy {
  static parseShape(shape, options = {}) {
    return parsePrincipalPolicyShape(shape, options);
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
    this.#shape = PrincipalPolicy.parseShape(shape, options);
    if (this.#shape.principalPolicy.constants) {
      this.#shape.principalPolicy.constants = PrincipalPolicy.parseConstants(this.#shape.principalPolicy.constants, options);
    }
    if (this.#shape.principalPolicy.variables) {
      this.#shape.principalPolicy.variables = PrincipalPolicy.parseVariables(this.#shape.principalPolicy.variables, options);
    }
    if (this.#shape.principalPolicy.rules?.length) {
      const rules = [];
      for (const rule of this.#shape.principalPolicy.rules) {
        const actions = [];
        for (const actionRule of rule.actions) {
          actions.push({
            ...actionRule,
            condition: PrincipalPolicy.parseConditions(actionRule.condition, options),
            output: PrincipalPolicy.parseOutputs(actionRule.output, options),
          });
        }
        rules.push({ ...rule, actions });
      }
      this.#shape.principalPolicy.rules = rules;
    }
  }

  get principal() {
    return this.#shape.principalPolicy.principal;
  }

  get version() {
    return this.#shape.principalPolicy.version;
  }

  get scope() {
    return this.#shape.principalPolicy.scope;
  }

  get rules() {
    return this.#shape.principalPolicy.rules;
  }

  get shape() {
    return this.#shape;
  }

  check(req, effectAsBoolean = false) {
    const effects = new Map();
    const outputs = new Map();
    const metaSrcPrefix = `principal.${this.principal}.v${this.version}`;
    const metaSrcBase = this.scope ? `${metaSrcPrefix}/${this.scope}` : metaSrcPrefix;
    const meta = { actions: {}, effectiveDerivedRoles: [] };

    if (!req.actions?.length) return { effects, outputs, meta };

    const constants = this.#shape.principalPolicy.constants?.get();
    const reqWithConstants = { ...req, constants, C: constants };

    const variables = this.#shape.principalPolicy.variables?.get(reqWithConstants);
    const reqWithVariables = { ...reqWithConstants, variables, V: variables };

    for (const action of reqWithVariables.actions) {
      const actionEffects = [];
      let matchedRule = null;

      for (let i = 0; i < this.rules.length; i++) {
        const rule = this.rules[i];
        if (rule.resource !== ALL_ACTIONS && rule.resource !== reqWithVariables.R.kind) continue;

        for (let j = 0; j < rule.actions.length; j++) {
          const actionRule = rule.actions[j];
          if (actionRule.action !== ALL_ACTIONS && actionRule.action !== action) continue;

          const isConditionFulfilled = actionRule.condition ? actionRule.condition.isFulfilled(reqWithVariables) : true;
          const metaSrc = `${metaSrcBase}#${actionRule.name || `UNNAMED_RULE_${i + 1}_${j + 1}`}`;

          if (actionRule.output) {
            const output = actionRule.output.build(reqWithVariables, isConditionFulfilled, metaSrc);
            outputs.set(output.src, output);
          }

          if (!isConditionFulfilled) continue;

          actionEffects.push(actionRule.effect);
          matchedRule = metaSrc;
        }
      }

      if (!actionEffects.length) continue;

      meta.actions[action] = { matchedPolicy: metaSrcBase, matchedRule };
      if (this.scope) meta.actions[action].matchedScope = this.scope;

      if (actionEffects.includes(Effect.Deny)) {
        effects.set(action, !effectAsBoolean ? Effect.Deny : false);
      } else if (actionEffects.includes(Effect.Allow)) {
        effects.set(action, !effectAsBoolean ? Effect.Allow : true);
      }
    }

    return { effects, outputs, meta };
  }
}

module.exports = { PrincipalPolicy };
