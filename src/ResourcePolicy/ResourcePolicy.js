const { parseResourcePolicyShape } = require('./validation');
const { cloneShapeTree, deepFreeze } = require('../freeze.js');
const { compileMatcher } = require('../matching.js');
const { evaluateDecisionLayer } = require('../decision.js');

const { ALL_ROLES, Effect } = require('../schemas');
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

  #attributeSchemas = null;

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
        // Rule name fields are static per policy but matched on every check()
        // call — precompile them into glob-aware matchers (Cerbos semantics:
        // bare `*` matches everything, other `*` stay within a `:` segment).
        // Non-enumerable so the runtime-only fields never leak into
        // JSON.stringify / deepEqual / spreads of `.rules` / `.shape`.
        Object.defineProperty(parsedRule, 'actionsMatcher', { value: compileMatcher(rule.actions) });
        if (Array.isArray(rule.roles)) {
          Object.defineProperty(parsedRule, 'rolesMatcher', { value: compileMatcher(rule.roles) });
        }
        rules.push(parsedRule);
      }
      this.#shape.resourcePolicy.rules = rules;
    }
    // Attribute-schema bindings (Cerbos `schemas` parity): keep the compiled
    // ignoreWhen matchers OFF the frozen shape (runtime-only state, like the
    // rule matchers) — the engine reads them through `attributeSchemas`.
    if (this.#shape.resourcePolicy.schemas) {
      const bindings = {};
      for (const key of ['principalSchema', 'resourceSchema']) {
        const schemaRef = this.#shape.resourcePolicy.schemas[key];
        if (!schemaRef) continue;
        bindings[key] = {
          ref: schemaRef.ref,
          ignoreMatcher: schemaRef.ignoreWhen?.actions ? compileMatcher(schemaRef.ignoreWhen.actions) : null,
        };
      }
      this.#attributeSchemas = Object.freeze(bindings);
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

  /**
   * Attribute-schema bindings declared by this policy (`schemas:` block),
   * with precompiled `ignoreWhen.actions` matchers — `null` when the policy
   * declares none. Consumed by the engine's `schemas` enforcement option.
   */
  get attributeSchemas() {
    return this.#attributeSchemas;
  }

  get rules() {
    return this.#shape.resourcePolicy.rules;
  }

  get shape() {
    return this.#shape;
  }

  /**
   * The policy's `metaSrcBase` — `resource.<kind>.v<version>[/scope]`.
   */
  get srcBase() {
    const prefix = `resource.${this.kind}.v${this.version}`;
    return this.scope ? `${prefix}/${this.scope}` : prefix;
  }

  /**
   * Evaluates every rule for the requested actions and reports which ones
   * FIRED (action matched, principal reached through roles/derivedRoles,
   * condition held), without resolving conflicts — resolution is the decision
   * walk's job (`src/decision.js`), where this policy is one scope of a chain.
   *
   * Outputs are built here for every evaluated rule, exactly as before.
   *
   * @param {Record<string, unknown>} req
   * @param {Map<string, string[]|null>|Set<string>} derivedRoles - active derived
   *   roles; a Map carries each role's `parentRoles` for bucket attribution.
   * @returns {{
   *   srcBase: string,
   *   scope: string,
   *   derivedRoles: Map<string, string[]|null>|Set<string>,
   *   outputs: Map<string, unknown>,
   *   actions: Map<string, { firedAllows: Array<{rule: object, src: string}>, firedDenies: Array<{rule: object, src: string}>, conditionFailed: boolean }>,
   * }}
   */
  evaluateRules(req, derivedRoles) {
    const outputs = new Map();
    const actions = new Map();
    const metaSrcBase = this.srcBase;
    const result = { srcBase: metaSrcBase, scope: this.scope ?? '', derivedRoles, outputs, actions };

    if (!req.actions?.length) return result;

    // Skip the request copies when the policy declares neither constants nor
    // variables (the common case): conditions then read `C`/`V` as undefined
    // either way, and the hot path saves two object spreads per check.
    const constants = this.#shape.resourcePolicy.constants?.get();
    const reqWithConstants = constants === undefined ? req : { ...req, constants, C: constants };

    const variables = this.#shape.resourcePolicy.variables?.get(reqWithConstants);
    const reqWithVariables =
      variables === undefined ? reqWithConstants : { ...reqWithConstants, variables, V: variables };

    const principalRoles = reqWithVariables.P.roles ?? [];
    const rules = this.rules;

    for (const action of reqWithVariables.actions) {
      const perAction = { firedAllows: [], firedDenies: [], conditionFailed: false };
      actions.set(action, perAction);

      for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        if (!rule.actionsMatcher.matches(action)) continue;

        // Does the rule reach this principal at all? (Bucket attribution — WHICH
        // role it reaches through — happens in the decision walk.)
        let rolesMatch = rule.rolesMatcher ? rule.rolesMatcher.matchesAny(principalRoles) : false;
        // The wildcard role also reaches a principal with no roles at all.
        if (!rolesMatch && rule.rolesMatcher && principalRoles.length === 0 && rule.rolesMatcher.matches(ALL_ROLES)) {
          rolesMatch = true;
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

        if (!isConditionFulfilled) {
          perAction.conditionFailed = true;
          continue;
        }

        if (rule.effect === Effect.Deny) perAction.firedDenies.push({ rule, src: metaSrc });
        else if (rule.effect === Effect.Allow) perAction.firedAllows.push({ rule, src: metaSrc });
      }
    }

    return result;
  }

  /**
   * Evaluates a request against THIS policy alone and returns action effects,
   * outputs and metadata — a single-scope instance of the shared decision
   * walk, so class-level and engine-level semantics can never drift. Effects
   * are always canonical `EFFECT_ALLOW`/`EFFECT_DENY` strings.
   *
   * @param {Record<string, unknown>} req
   * @param {Map<string, string[]|null>|Set<string>} derivedRoles
   * @returns {{ effects: Map<string, string>, outputs: Map<string, unknown>, meta: Record<string, unknown> }}
   */
  check(req, derivedRoles) {
    if (!req.actions?.length) {
      return {
        effects: new Map(),
        outputs: new Map(),
        meta: { actions: {}, effectiveDerivedRoles: [...derivedRoles.keys()] },
      };
    }
    const { effects, outputs, meta } = evaluateDecisionLayer({
      req,
      scopes: [{ scope: this.scope ?? '', resource: { policy: this, derivedRoles }, rows: new Map() }],
    });
    // Single-policy convention: every action names the policy it was checked
    // against, even undecided ones (the engine-level walk reserves that for
    // deciding policies).
    for (const action of req.actions) {
      meta.actions[action] = { matchedPolicy: this.srcBase, ...meta.actions[action] };
      if (meta.actions[action].matchedScope === '') delete meta.actions[action].matchedScope;
    }
    return { effects, outputs, meta };
  }
}

module.exports = { ResourcePolicy };
