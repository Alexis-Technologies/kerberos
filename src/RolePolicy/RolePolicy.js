const { parseRolePolicyShape } = require('./validation');

const { ALL_ACTIONS, ALL_RESOURCES, Effect } = require('../schemas');
const { parseConditions, parseConstants, parseOutputs, parseVariables } = require('../policyParsers.js');

/**
 * Represents a Cerbos-style role policy: an allowlist bound to a single role,
 * targeting resource + allowActions, with parentRoles inheritance.
 */
class RolePolicy {
  static parseShape(shape, options = {}) {
    return parseRolePolicyShape(shape, options);
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
        const parsedRule = {
          ...rule,
          condition: RolePolicy.parseConditions(rule.condition, options),
          output: RolePolicy.parseOutputs(rule.output, options),
        };
        // See ResourcePolicy's `actionsSet` — same rationale (O(1) hot-path
        // lookups), non-enumerable so it never leaks into serialized shapes.
        Object.defineProperty(parsedRule, 'allowActionsSet', { value: new Set(rule.allowActions) });
        rules.push(parsedRule);
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
    const scope = this.#shape.rolePolicy.scope;
    if (!scope || scope === '.') return undefined;
    return scope;
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

  /**
   * Evaluates a request. Effects are always canonical
   * `EFFECT_ALLOW`/`EFFECT_DENY` strings — the `effectAsBoolean` response
   * format is applied at the response boundary.
   */
  check(req) {
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

    const rules = this.rules;

    for (const action of reqWithVariables.actions) {
      let matchedResource = false;
      let matchedRule = null;
      let isAllowed = false;
      // Decision-trace input: did an allowlisted rule fail only its condition?
      let conditionFailed = false;

      for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        if (rule.resource !== ALL_RESOURCES && rule.resource !== reqWithVariables.R.kind) continue;

        matchedResource = true;
        if (!rule.allowActionsSet.has(ALL_ACTIONS) && !rule.allowActionsSet.has(action)) continue;

        const isConditionFulfilled = rule.condition ? rule.condition.isFulfilled(reqWithVariables) : true;
        const metaSrc = `${metaSrcBase}#${rule.name || `UNNAMED_RULE_${i + 1}`}`;

        if (rule.output) {
          const output = rule.output.build(reqWithVariables, isConditionFulfilled, metaSrc);
          if (output) outputs.set(output.src, output);
        }

        if (!isConditionFulfilled) {
          conditionFailed = true;
          continue;
        }

        isAllowed = true;
        matchedRule = metaSrc;
      }

      if (isAllowed) {
        meta.actions[action] = { matchedPolicy: metaSrcBase, matchedRule };
        if (this.scope) meta.actions[action].matchedScope = this.scope;
        effects.set(action, Effect.Allow);
        continue;
      }

      if (!matchedResource) continue;

      // Allowlist deny — record WHY for decision tracing.
      meta.actions[action] = {
        matchedPolicy: metaSrcBase,
        reason: conditionFailed ? 'condition-not-met' : 'rule-miss',
      };
      if (this.scope) meta.actions[action].matchedScope = this.scope;
      effects.set(action, Effect.Deny);
    }

    return { effects, outputs, meta };
  }
}

module.exports = { RolePolicy };
