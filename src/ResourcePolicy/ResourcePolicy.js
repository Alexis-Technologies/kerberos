const { Outputs } = require('../Outputs');
const { parseResourcePolicyShape } = require('./validation');

const { ALL_ACTIONS, Effect } = require('../schemas');
const { Variables } = require('../Variables');
const { Conditions } = require('../Conditions');
const { Constants } = require('../Constants');

/**
 * Represents a resource policy and evaluates actions for requests.
 */
class ResourcePolicy {
  /**
   * Parses a resource policy shape with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parseResourcePolicyShape(shape, options);
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

  /**
   * @param {unknown} shape
   * @param {object} [options]
   */
  constructor(shape, options = {}) {
    this.#shape = ResourcePolicy.parseShape(shape, options);
    if (this.#shape.resourcePolicy.constants) {
      this.#shape.resourcePolicy.constants = ResourcePolicy.parseConstants(this.#shape.resourcePolicy.constants, options);
    }
    if (this.#shape.resourcePolicy.variables) {
      this.#shape.resourcePolicy.variables = ResourcePolicy.parseVariables(this.#shape.resourcePolicy.variables, options);
    }
    if (this.#shape.resourcePolicy.rules?.length) {
      const rules = [];
      for (const rule of this.#shape.resourcePolicy.rules) {
        rules.push({
          ...rule,
          condition: ResourcePolicy.parseConditions(rule.condition, options),
          output: ResourcePolicy.parseOutputs(rule.output, options),
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

  /**
   * Evaluates a request and returns action effects, outputs and metadata.
   *
   * @param {Record<string, unknown>} req
   * @param {Set<string>} derivedRoles
   * @param {boolean} [effectAsBoolean=false]
   * @returns {{ effects: Map<string, string | boolean>, outputs: Map<string, unknown>, meta: Record<string, unknown> }}
   */
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

    // Principal roles are looked up once per rule/action; a Set turns the inner
    // `roles.includes(role)` scans into O(1) membership checks.
    const principalRoles = new Set(reqWithVariables.P.roles);

    const denyValue = !effectAsBoolean ? Effect.Deny : false;
    const allowValue = !effectAsBoolean ? Effect.Allow : true;
    const rules = this.rules;

    for (const action of reqWithVariables.actions) {
      // Track effects with two flags instead of building an array and running
      // `includes` twice; Deny still wins over Allow.
      let hasDeny = false;
      let hasAllow = false;
      // Record the rule that determines the final effect: a Deny rule pins the
      // matched rule (Deny wins), otherwise the latest fulfilled Allow rule.
      let matchedRuleSrc = null;
      let matchedRuleIsDeny = false;
      meta.actions[action] = { matchedPolicy: metaSrcBase };

      for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        // Checking if the rule applies to the action
        if (!rule.actions.includes(ALL_ACTIONS) && !rule.actions.includes(action)) continue;

        // Checking if the roles match (`*` is the wildcard role and matches any principal)
        let rolesMatch = false;
        if (Array.isArray(rule.roles)) {
          for (const role of rule.roles) {
            if (role === ALL_ACTIONS || principalRoles.has(role)) {
              rolesMatch = true;
              break;
            }
          }
        }

        let derivedRolesMatch = false;
        if (!rolesMatch && Array.isArray(rule.derivedRoles)) {
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

        // Build outputs based on rule activation and condition fulfillment.
        // `build` returns null when the rule has no output branch for the
        // current activation state, so we don't emit spurious null outputs.
        if (rule.output) {
          const output = rule.output.build(reqWithVariables, isConditionFulfilled, metaSrc);
          if (output) outputs.set(output.src, output);
        }

        if (isConditionFulfilled) {
          if (rule.effect === Effect.Deny) {
            hasDeny = true;
            matchedRuleSrc = metaSrc;
            matchedRuleIsDeny = true;
          } else if (rule.effect === Effect.Allow) {
            hasAllow = true;
            if (!matchedRuleIsDeny) matchedRuleSrc = metaSrc;
          }
        }
      }

      if (matchedRuleSrc !== null) {
        meta.actions[action].matchedRule = matchedRuleSrc;
        if (this.scope) meta.actions[action].matchedScope = this.scope;
      }

      // Deny wins; otherwise Allow; otherwise default Deny.
      effects.set(action, hasDeny ? denyValue : hasAllow ? allowValue : denyValue);
    }

    return { effects, outputs, meta };
  }
}

module.exports = { ResourcePolicy };
