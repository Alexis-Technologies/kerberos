const { parseResourcePolicyShape } = require('./validation');
const { cloneShapeTree, deepFreeze } = require('../freeze.js');

const { ALL_ACTIONS, ALL_ROLES, Effect } = require('../schemas');
const { parseConditions, parseConstants, parseOutputs, parseVariables } = require('../policyParsers.js');

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

  /**
   * @param {unknown} shape
   * @param {object} [options]
   */
  constructor(shape, options = {}) {
    this.#shape = cloneShapeTree(ResourcePolicy.parseShape(shape, options));
    if (this.#shape.resourcePolicy.constants) {
      this.#shape.resourcePolicy.constants = ResourcePolicy.parseConstants(
        this.#shape.resourcePolicy.constants,
        options,
      );
    }
    if (this.#shape.resourcePolicy.variables) {
      this.#shape.resourcePolicy.variables = ResourcePolicy.parseVariables(
        this.#shape.resourcePolicy.variables,
        options,
      );
    }
    if (this.#shape.resourcePolicy.rules?.length) {
      const rules = [];
      for (const rule of this.#shape.resourcePolicy.rules) {
        const parsedRule = {
          ...rule,
          condition: ResourcePolicy.parseConditions(rule.condition, options),
          output: ResourcePolicy.parseOutputs(rule.output, options),
        };
        // `rule.actions` is static per policy but scanned on every check()
        // call (once per rule per requested action); precomputing the Set
        // once turns the repeated `includes` linear scans into O(1) lookups.
        // Non-enumerable so the runtime-only field never leaks into
        // JSON.stringify / deepEqual / spreads of `.rules` / `.shape`.
        Object.defineProperty(parsedRule, 'actionsSet', { value: new Set(rule.actions) });
        rules.push(parsedRule);
      }
      this.#shape.resourcePolicy.rules = rules;
    }
    // Post-construction hardening: the parsed shape IS live evaluation state
    // (stored in the engine's policy Maps), and the constructor-time
    // duplicate/deny integrity guards would be bypassable by mutating
    // `policy.shape` afterwards. Frozen here, matching the codec's frozen
    // shared ASTs and the Relations module's frozen compiled refs.
    deepFreeze(this.#shape);
  }

  get kind() {
    return this.#shape.resourcePolicy.resource;
  }

  get version() {
    return this.#shape.resourcePolicy.version;
  }

  get scope() {
    const scope = this.#shape.resourcePolicy.scope;
    // `'.'` is the documented base-scope alias; treat it like an unset scope
    // so output `src` and `matchedScope` match Kerberos lookup normalization.
    if (!scope || scope === '.') return undefined;
    return scope;
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
   * Effects are always canonical `EFFECT_ALLOW`/`EFFECT_DENY` strings — the
   * `effectAsBoolean` response format is applied at the response boundary.
   *
   * @param {Record<string, unknown>} req
   * @param {Set<string>} derivedRoles
   * @returns {{ effects: Map<string, string>, outputs: Map<string, unknown>, meta: Record<string, unknown> }}
   */
  check(req, derivedRoles) {
    const effects = new Map();
    const outputs = new Map();
    const metaSrcPrefix = `resource.${this.kind}.v${this.version}`;
    const metaSrcBase = this.scope ? `${metaSrcPrefix}/${this.scope}` : metaSrcPrefix;
    const meta = { actions: {}, effectiveDerivedRoles: [...derivedRoles.values()] };

    if (!req.actions?.length) return { effects, outputs, meta };

    // Skip the request copies when the policy declares neither constants nor
    // variables (the common case): conditions then read `C`/`V` as undefined
    // either way, and the hot path saves two object spreads per check.
    const constants = this.#shape.resourcePolicy.constants?.get();
    const reqWithConstants = constants === undefined ? req : { ...req, constants, C: constants };

    const variables = this.#shape.resourcePolicy.variables?.get(reqWithConstants);
    const reqWithVariables =
      variables === undefined ? reqWithConstants : { ...reqWithConstants, variables, V: variables };

    // Principal roles are looked up once per rule/action; a Set turns the inner
    // `roles.includes(role)` scans into O(1) membership checks.
    const principalRoles = new Set(reqWithVariables.P.roles);

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
      // Decision-trace input: did a rule that targeted this action fail only
      // on its condition?
      let conditionFailed = false;
      meta.actions[action] = { matchedPolicy: metaSrcBase };

      for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        // Checking if the rule applies to the action
        if (!rule.actionsSet.has(ALL_ACTIONS) && !rule.actionsSet.has(action)) continue;

        // Checking if the roles match (`*` is the wildcard role and matches any principal)
        let rolesMatch = false;
        if (Array.isArray(rule.roles)) {
          for (const role of rule.roles) {
            if (role === ALL_ROLES || principalRoles.has(role)) {
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
        } else {
          conditionFailed = true;
        }
      }

      if (matchedRuleSrc !== null) {
        meta.actions[action].matchedRule = matchedRuleSrc;
        if (this.scope) meta.actions[action].matchedScope = this.scope;
      } else {
        // Default deny — record WHY nothing matched for decision tracing:
        // a rule targeted the action but its condition failed
        // ('condition-not-met'), or no rule targeted the action / matched the
        // principal's roles at all ('rule-miss').
        meta.actions[action].reason = conditionFailed ? 'condition-not-met' : 'rule-miss';
      }

      // Deny wins; otherwise Allow; otherwise default Deny.
      effects.set(action, hasDeny ? Effect.Deny : hasAllow ? Effect.Allow : Effect.Deny);
    }

    return { effects, outputs, meta };
  }
}

module.exports = { ResourcePolicy };
