const { parseRolePolicyShape } = require('./validation');
const { cloneShapeTree, deepFreeze } = require('../freeze.js');
const { compileMatcher } = require('../matching.js');

const { Effect } = require('../schemas');
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
    this.#shape = cloneShapeTree(RolePolicy.parseShape(shape, options));
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
        // See ResourcePolicy's `actionsMatcher` — same rationale (precompiled
        // glob-aware matchers, non-enumerable so they never leak into
        // serialized shapes).
        Object.defineProperty(parsedRule, 'allowActionsMatcher', { value: compileMatcher(rule.allowActions) });
        Object.defineProperty(parsedRule, 'resourceMatcher', { value: compileMatcher([rule.resource]) });
        rules.push(parsedRule);
      }
      this.#shape.rolePolicy.rules = rules;
    }

    // Post-construction hardening: the parsed shape IS live evaluation state
    // (stored in the engine's policy Maps), and the constructor-time
    // duplicate/deny integrity guards would be bypassable by mutating
    // `policy.shape` afterwards. Frozen here, matching the codec's frozen
    // shared ASTs and the Relations module's frozen compiled refs.
    deepFreeze(this.#shape);
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
   * The policy's `metaSrcBase` — `role.<role>.v<version>[/scope]`.
   */
  get srcBase() {
    const prefix = `role.${this.role}.v${this.version}`;
    return this.scope ? `${prefix}/${this.scope}` : prefix;
  }

  /**
   * Per-action allowlist verdict for the decision walk (`src/decision.js`).
   *
   * A role policy contributes synthetic DENY rows at its scope for every
   * requested action it does not allowlist for this resource kind — which is
   * also what makes a role policy constrain its role for kinds its rules
   * never mention (`allowed` is then simply empty). Rules match resource and
   * actions through Cerbos-style globs; a rule whose condition fails does not
   * allowlist (recorded in `conditionFailed` for decision tracing).
   *
   * @param {Record<string, unknown>} req
   * @returns {{ srcBase: string, scope: string, allowed: Set<string>, conditionFailed: Set<string>, outputs: Map<string, unknown> }}
   */
  evaluateAllowlist(req) {
    const allowed = new Set();
    const conditionFailed = new Set();
    const outputs = new Map();
    const metaSrcBase = this.srcBase;
    const verdict = { srcBase: metaSrcBase, scope: this.scope ?? '', allowed, conditionFailed, outputs };

    if (!req.actions?.length) return verdict;

    const constants = this.#shape.rolePolicy.constants?.get();
    const reqWithConstants = constants === undefined ? req : { ...req, constants, C: constants };
    const variables = this.#shape.rolePolicy.variables?.get(reqWithConstants);
    const reqWithVariables =
      variables === undefined ? reqWithConstants : { ...reqWithConstants, variables, V: variables };

    const rules = this.rules;
    for (const action of reqWithVariables.actions) {
      for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        if (!rule.resourceMatcher.matches(reqWithVariables.R.kind)) continue;
        if (!rule.allowActionsMatcher.matches(action)) continue;

        const isConditionFulfilled = rule.condition ? rule.condition.isFulfilled(reqWithVariables) : true;
        const metaSrc = `${metaSrcBase}#${rule.name || `UNNAMED_RULE_${i + 1}`}`;
        if (rule.output) {
          const output = rule.output.build(reqWithVariables, isConditionFulfilled, metaSrc);
          if (output) outputs.set(output.src, output);
        }
        if (isConditionFulfilled) {
          allowed.add(action);
          break;
        }
        conditionFailed.add(action);
      }
    }

    return verdict;
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

    // Skip the request copies when the policy declares neither constants nor
    // variables (the common case): conditions then read `C`/`V` as undefined
    // either way, and the hot path saves two object spreads per check.
    const constants = this.#shape.rolePolicy.constants?.get();
    const reqWithConstants = constants === undefined ? req : { ...req, constants, C: constants };

    const variables = this.#shape.rolePolicy.variables?.get(reqWithConstants);
    const reqWithVariables =
      variables === undefined ? reqWithConstants : { ...reqWithConstants, variables, V: variables };

    const rules = this.rules;

    for (const action of reqWithVariables.actions) {
      let matchedResource = false;
      let matchedRule = null;
      let isAllowed = false;
      // Decision-trace input: did an allowlisted rule fail only its condition?
      let conditionFailed = false;

      for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        if (!rule.resourceMatcher.matches(reqWithVariables.R.kind)) continue;

        matchedResource = true;
        if (!rule.allowActionsMatcher.matches(action)) continue;

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
