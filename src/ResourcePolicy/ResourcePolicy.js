const { parseResourcePolicyShape } = require('./validation');
const { cloneShapeTree, deepFreeze } = require('../freeze.js');

const { ALL_ACTIONS, ALL_ROLES, Effect } = require('../schemas');
const { parseConditions, parseConstants, parseOutputs, parseVariables } = require('../policyParsers.js');

/**
 * Does `rule` apply to the principal role `role`?
 *
 * Cerbos resolves conflicts per principal role, so every rule has to be
 * attributed to the roles it was written for. A rule reaches `role` either
 * directly through `roles`, or through a derived role that is active for this
 * request AND lists `role` among its `parentRoles` — derived roles do not form
 * a dimension of their own, they collapse into the principal-role dimension
 * that activated them.
 *
 * `derivedRoles` is a Map of active-role name → `parentRoles` when the engine
 * supplies it. A plain Set (or a missing entry) means the parent roles are
 * unknown — for a relation-backed derived role there may genuinely be none —
 * and the rule is then treated as reaching every role, which is the
 * non-narrowing reading.
 *
 * @param {Record<string, unknown>} rule
 * @param {string} role
 * @param {Set<string>|Map<string, string[]>} derivedRoles
 * @returns {boolean}
 */
function ruleCoversRole(rule, role, derivedRoles) {
  if (Array.isArray(rule.roles)) {
    for (const ruleRole of rule.roles) {
      if (ruleRole === ALL_ROLES || ruleRole === role) return true;
    }
  }
  if (Array.isArray(rule.derivedRoles)) {
    for (const name of rule.derivedRoles) {
      if (!derivedRoles.has(name)) continue;
      const parentRoles = derivedRoles.get?.(name);
      if (!Array.isArray(parentRoles) || parentRoles.length === 0) return true;
      // Literal membership, deliberately without a `*` wildcard: this must
      // mirror `DerivedRoles.#parentRolesMatch` (which gates activation the
      // same way) and the planner's `intersects`, or the runtime and the query
      // planner would disagree about which role a derived rule belongs to.
      for (const parentRole of parentRoles) {
        if (parentRole === role) return true;
      }
    }
  }
  return false;
}

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
    // `.keys()` reads the same for a Set of names and the engine's
    // name → parentRoles Map.
    const meta = { actions: {}, effectiveDerivedRoles: [...derivedRoles.keys()] };

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

    // Conflict resolution runs once per principal role (Cerbos semantics), so
    // the roles are the buckets. A principal with no roles at all is not
    // representable in Cerbos and is rejected by every validation backend here,
    // but the engine runs without a backend by default — give it one anonymous
    // bucket so wildcard (`*`) rules keep behaving as they always have instead
    // of silently denying.
    const roleBuckets = principalRoles.size > 0 ? [...principalRoles] : [null];

    const rules = this.rules;

    for (const action of reqWithVariables.actions) {
      // Rules that actually fired, kept as `{ rule, src }` so conflict
      // resolution can attribute each one to the roles it was written for.
      // Only fired rules are collected, so the common shapes stay cheap.
      const firedAllows = [];
      const firedDenies = [];
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
          if (rule.effect === Effect.Deny) firedDenies.push({ rule, src: metaSrc });
          else if (rule.effect === Effect.Allow) firedAllows.push({ rule, src: metaSrc });
        } else {
          conditionFailed = true;
        }
      }

      // Conflict resolution (Cerbos >= 0.41): deny overrides allow WITHIN a
      // role, allow overrides deny ACROSS roles. The action is allowed as soon
      // as one principal role allows it with nothing denying it for that same
      // role — deliberate anti-lockout behaviour, so that holding an extra,
      // less privileged role can never take away access granted by another.
      // A deny therefore only bites when it covers the very role carrying the
      // allow, which a wildcard (`roles: ['*']`) always does.
      // `matchedRule` keeps the established convention of naming the LAST rule
      // that decided the outcome.
      let winningAllowSrc = null;
      if (firedAllows.length > 0) {
        if (firedDenies.length === 0) {
          winningAllowSrc = firedAllows[firedAllows.length - 1].src;
        } else {
          for (const role of roleBuckets) {
            if (firedDenies.some((entry) => ruleCoversRole(entry.rule, role, derivedRoles))) continue;
            for (let i = firedAllows.length - 1; i >= 0; i--) {
              if (ruleCoversRole(firedAllows[i].rule, role, derivedRoles)) {
                winningAllowSrc = firedAllows[i].src;
                break;
              }
            }
            if (winningAllowSrc !== null) break;
          }
        }
      }

      if (winningAllowSrc !== null) {
        meta.actions[action].matchedRule = winningAllowSrc;
        if (this.scope) meta.actions[action].matchedScope = this.scope;
        effects.set(action, Effect.Allow);
        continue;
      }

      if (firedDenies.length > 0) {
        meta.actions[action].matchedRule = firedDenies[firedDenies.length - 1].src;
        if (this.scope) meta.actions[action].matchedScope = this.scope;
      } else {
        // Default deny — record WHY nothing matched for decision tracing:
        // a rule targeted the action but its condition failed
        // ('condition-not-met'), or no rule targeted the action / matched the
        // principal's roles at all ('rule-miss').
        meta.actions[action].reason = conditionFailed ? 'condition-not-met' : 'rule-miss';
      }

      effects.set(action, Effect.Deny);
    }

    return { effects, outputs, meta };
  }
}

module.exports = { ResourcePolicy };
