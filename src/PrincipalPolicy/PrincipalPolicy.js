const { parsePrincipalPolicyShape } = require('./validation');

const { ALL_ACTIONS, ALL_RESOURCES, Effect } = require('../schemas');
const { parseConditions, parseConstants, parseOutputs, parseVariables } = require('../policyParsers.js');

/**
 * Represents a Cerbos-style principal policy: principal-specific overrides
 * bound to a single principal, targeting resource + action directly.
 */
class PrincipalPolicy {
  static parseShape(shape, options = {}) {
    return parsePrincipalPolicyShape(shape, options);
  }

  static parseConstants(constants, options = {}) {
    return parseConstants(constants, options);
  }

  static parseVariables(variables, options = {}) {
    return parseVariables(variables, options);
  }

  static parseConditions(conditions, options = {}) {
    return parseConditions(conditions, options);
  }

  static parseOutputs(outputs, options = {}) {
    return parseOutputs(outputs, options);
  }

  #shape = null;

  constructor(shape, options = {}) {
    this.#shape = PrincipalPolicy.parseShape(shape, options);
    if (this.#shape.principalPolicy.constants) {
      this.#shape.principalPolicy.constants = PrincipalPolicy.parseConstants(
        this.#shape.principalPolicy.constants,
        options,
      );
    }
    if (this.#shape.principalPolicy.variables) {
      this.#shape.principalPolicy.variables = PrincipalPolicy.parseVariables(
        this.#shape.principalPolicy.variables,
        options,
      );
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
    const scope = this.#shape.principalPolicy.scope;
    if (!scope || scope === '.') return undefined;
    return scope;
  }

  get rules() {
    return this.#shape.principalPolicy.rules;
  }

  get shape() {
    return this.#shape;
  }

  /**
   * Evaluates a request. Effects are always canonical
   * `EFFECT_ALLOW`/`EFFECT_DENY` strings — the `effectAsBoolean` response
   * format is applied at the response boundary. Actions with no fulfilled
   * rule are intentionally left unset so evaluation falls through to the
   * role/resource policy layers.
   */
  check(req) {
    const effects = new Map();
    const outputs = new Map();
    const metaSrcPrefix = `principal.${this.principal}.v${this.version}`;
    const metaSrcBase = this.scope ? `${metaSrcPrefix}/${this.scope}` : metaSrcPrefix;
    const meta = { actions: {}, effectiveDerivedRoles: [] };

    if (!req.actions?.length) return { effects, outputs, meta };

    // Skip the request copies when the policy declares neither constants nor
    // variables (the common case): conditions then read `C`/`V` as undefined
    // either way, and the hot path saves two object spreads per check.
    const constants = this.#shape.principalPolicy.constants?.get();
    const reqWithConstants = constants === undefined ? req : { ...req, constants, C: constants };

    const variables = this.#shape.principalPolicy.variables?.get(reqWithConstants);
    const reqWithVariables =
      variables === undefined ? reqWithConstants : { ...reqWithConstants, variables, V: variables };

    const rules = this.rules;

    for (const action of reqWithVariables.actions) {
      // Replace the per-action effects array + double `includes` with flags.
      // A Deny rule pins the matched rule (Deny wins), otherwise the latest
      // fulfilled Allow rule is recorded.
      let matchedRule = null;
      let matchedRuleIsDeny = false;
      let matched = false;
      let hasDeny = false;
      let hasAllow = false;

      for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        if (rule.resource !== ALL_RESOURCES && rule.resource !== reqWithVariables.R.kind) continue;

        const actionRules = rule.actions;
        for (let j = 0; j < actionRules.length; j++) {
          const actionRule = actionRules[j];
          if (actionRule.action !== ALL_ACTIONS && actionRule.action !== action) continue;

          const isConditionFulfilled = actionRule.condition ? actionRule.condition.isFulfilled(reqWithVariables) : true;
          const metaSrc = `${metaSrcBase}#${actionRule.name || `UNNAMED_RULE_${i + 1}_${j + 1}`}`;

          if (actionRule.output) {
            const output = actionRule.output.build(reqWithVariables, isConditionFulfilled, metaSrc);
            if (output) outputs.set(output.src, output);
          }

          if (!isConditionFulfilled) continue;

          matched = true;
          if (actionRule.effect === Effect.Deny) {
            hasDeny = true;
            matchedRule = metaSrc;
            matchedRuleIsDeny = true;
          } else if (actionRule.effect === Effect.Allow) {
            hasAllow = true;
            if (!matchedRuleIsDeny) matchedRule = metaSrc;
          }
        }
      }

      if (!matched) continue;

      meta.actions[action] = { matchedPolicy: metaSrcBase, matchedRule };
      if (this.scope) meta.actions[action].matchedScope = this.scope;

      if (hasDeny) effects.set(action, Effect.Deny);
      else if (hasAllow) effects.set(action, Effect.Allow);
    }

    return { effects, outputs, meta };
  }
}

module.exports = { PrincipalPolicy };
