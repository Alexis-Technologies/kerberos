/**
 * Layer-composition planner: mirrors `#evaluatePolicySources` symbolically.
 *
 * Per action the runtime resolves Principal → Role → Resource, each layer
 * seeing only actions the previous one left unset. At plan time the layer
 * SELECTORS are constants (which policies resolve, whether any role policy
 * targets `R.kind` — all derived from the fully-known principal and
 * `resource.kind`); only the principal layer can defer the choice, because
 * its rule conditions may read unknown resource fields. Hence per action:
 *
 *   plan = OR( AND(PA, NOT(PD)),                  — principal decides Allow
 *              AND(NOT(PA), NOT(PD), layer) )     — principal silent → next layer
 *
 * where PA/PD are the ORs of fulfilled allow/deny principal rules, and
 * `layer` is the resource layer — conflict resolution per principal role
 * (`OR` over roles of `AND(OR(allow rules), NOT(OR(deny rules)))`, default
 * deny) — `AND`ed with the role-policy filter when every principal role is
 * constrained by an applicable role policy (union across roles, parentRoles
 * intersection within one — semantics of `#evaluateRolePolicies`).
 *
 * All inputs are pre-resolved policy class instances — this module is pure
 * and synchronous; the engine does the (async, cache-aware) lookups.
 */

const { ALL_ACTIONS, ALL_RESOURCES, ALL_ROLES, Effect } = require('../schemas');
const { FALSE, andNode, constNode, notNode, orNode, relationNode } = require('./nodes.js');
const { createExprPlanner } = require('./partialEval.js');

function intersects(roles, principalRoleSet) {
  for (const role of roles) if (principalRoleSet.has(role)) return true;
  return false;
}

/**
 * Builds the query plan for one request.
 *
 * @param {object} input
 * @param {Record<string, unknown>} input.principal
 * @param {{ kind: string, scope?: string, policyVersion?: string, attr?: Record<string, unknown> }} input.resource
 * @param {string[]} input.actions
 * @param {import('../PrincipalPolicy').PrincipalPolicy | null} input.principalPolicy
 * @param {import('../RolePolicy').RolePolicy[]} input.rolePolicies - resolved for deduped principal roles, order kept
 * @param {Map<string, import('../RolePolicy').RolePolicy | null>} input.rolePolicyClosure - incl. transitive parents
 * @param {import('../ResourcePolicy').ResourcePolicy | null} input.resourcePolicy
 * @param {import('../DerivedRoles').DerivedRoles[]} input.derivedRolesSets - resolved importDerivedRoles, order kept
 * @param {boolean} input.hasRelations
 * @param {Array<object> | null} [input.trace] - decision trace (includeMeta); receives no-resolver entries
 * @returns {{ node: import('./nodes.js').PlanNode, perAction: Map<string, import('./nodes.js').PlanNode> }}
 */
function buildResourcePlan({
  principal,
  resource,
  actions,
  principalPolicy,
  rolePolicies,
  rolePolicyClosure,
  resourcePolicy,
  derivedRolesSets,
  hasRelations,
  trace = null,
}) {
  const principalRoleSet = new Set(principal.roles);

  // One expression planner per policy: each policy evaluates conditions
  // against its own constants/variables context, exactly like check().
  const planners = new Map();
  function plannerFor(key, holder) {
    let planner = planners.get(key);
    if (!planner) {
      planner = createExprPlanner({
        principal,
        resource,
        actions,
        constants: holder?.constants,
        variables: holder?.variables,
      });
      planners.set(key, planner);
    }
    return planner;
  }

  // ---- principal layer -----------------------------------------------------

  function principalNodes(action) {
    if (!principalPolicy) return { allow: FALSE, deny: FALSE };
    const planner = plannerFor(principalPolicy, principalPolicy.shape.principalPolicy);
    const allowParts = [];
    const denyParts = [];
    for (const rule of principalPolicy.rules ?? []) {
      if (rule.resource !== ALL_RESOURCES && rule.resource !== resource.kind) continue;
      for (const actionRule of rule.actions) {
        if (actionRule.action !== ALL_ACTIONS && actionRule.action !== action) continue;
        const node = planner.planCondition(actionRule.condition);
        if (actionRule.effect === Effect.Deny) denyParts.push(node);
        else allowParts.push(node);
      }
    }
    return { allow: orNode(allowParts), deny: orNode(denyParts) };
  }

  // ---- role layer ----------------------------------------------------------

  // Memoized per policy: consulted once for applicability and once per
  // roleAllowNode call (including transitive parents).
  const roleMatches = new Map();

  function roleMatchesResource(policy) {
    let matched = roleMatches.get(policy);
    if (matched === undefined) {
      matched = false;
      for (const rule of policy.rules ?? []) {
        if (rule.resource === ALL_RESOURCES || rule.resource === resource.kind) {
          matched = true;
          break;
        }
      }
      roleMatches.set(policy, matched);
    }
    return matched;
  }

  const applicableRolePolicies = [];
  for (const policy of rolePolicies) {
    if (roleMatchesResource(policy)) applicableRolePolicies.push(policy);
  }

  /**
   * Effective role allow: the child's fulfilled allowlist OR, intersected
   * with every resolvable parent (a parent that never targets the resource
   * contributes FALSE — runtime parity: the child's Allow is downgraded).
   * Memoized per `${policyKey}|${action}`; a cycle throws the same error the
   * runtime does.
   */
  function roleAllowNode(policy, action, memo, stack) {
    const policyKey = `${policy.role}.${policy.version}.${policy.scope ?? ''}|${action}`;
    if (memo.has(policyKey)) return memo.get(policyKey);
    if (stack.has(policyKey)) {
      throw new Error(`Circular role policy inheritance detected for role "${policy.role}"`);
    }
    stack.add(policyKey);

    let node;
    if (!roleMatchesResource(policy)) {
      node = FALSE;
    } else {
      const planner = plannerFor(policy, policy.shape.rolePolicy);
      const allowParts = [];
      for (const rule of policy.rules ?? []) {
        if (rule.resource !== ALL_RESOURCES && rule.resource !== resource.kind) continue;
        if (!rule.allowActionsSet.has(ALL_ACTIONS) && !rule.allowActionsSet.has(action)) continue;
        allowParts.push(planner.planCondition(rule.condition));
      }
      node = orNode(allowParts);
      for (const parentRole of policy.parentRoles) {
        const parentPolicy = rolePolicyClosure.get(parentRole);
        if (!parentPolicy) continue;
        node = andNode([node, roleAllowNode(parentPolicy, action, memo, stack)]);
      }
    }

    stack.delete(policyKey);
    memo.set(policyKey, node);
    return node;
  }

  // Union across roles: the principal may do what ANY of its roles permits.
  function roleFilterNode(action) {
    const memo = new Map();
    const parts = new Array(applicableRolePolicies.length);
    for (let i = 0; i < applicableRolePolicies.length; i++) {
      parts[i] = roleAllowNode(applicableRolePolicies[i], action, memo, new Set());
    }
    return orNode(parts);
  }

  // ---- derived roles (resource layer) --------------------------------------

  const derivedRoleNodes = new Map();
  // `DerivedRoles.roles` is a getter that rebuilds its Map on every access —
  // snapshot it once per set instead of once per referenced role name.
  const derivedRoleMaps = new Map();

  function definitionsOf(set) {
    let definitions = derivedRoleMaps.get(set);
    if (!definitions) {
      definitions = set.roles;
      derivedRoleMaps.set(set, definitions);
    }
    return definitions;
  }

  /**
   * Plans a derived role, restricted to the principal role `forRole`.
   *
   * Conflict resolution runs per principal role, so a derived role only counts
   * for the roles it was derived FROM — the definitions whose `parentRoles`
   * contain `forRole`. Passing `null` keeps the un-restricted reading (any
   * principal role), which is what the role-policy layer wants.
   */
  function derivedRoleNode(name, forRole = null) {
    const cacheKey = forRole === null ? name : `${name} ${forRole}`;
    if (derivedRoleNodes.has(cacheKey)) return derivedRoleNodes.get(cacheKey);
    const parts = [];
    for (const set of derivedRolesSets) {
      const def = definitionsOf(set).get(name);
      if (!def) continue;
      // Mirrors ResourcePolicy's `ruleCoversRole`: literal membership, no
      // wildcard, and a relation-backed definition without `parentRoles` is
      // ungated and stands for every role.
      if (forRole !== null && Array.isArray(def.parentRoles) && def.parentRoles.length > 0) {
        if (!def.parentRoles.includes(forRole)) continue;
      }
      const planner = plannerFor(set, set.shape);
      if (def.relation) {
        const gateParts = [];
        if (Array.isArray(def.parentRoles) && def.parentRoles.length) {
          gateParts.push(constNode(intersects(def.parentRoles, principalRoleSet)));
        }
        if (def.condition) gateParts.push(planner.planCondition(def.condition));
        const gate = andNode(gateParts);
        if (!hasRelations) {
          // Runtime parity: without a resolver the candidate can never
          // activate — trace it instead of denying silently.
          if (trace && gate !== FALSE) {
            trace.push({
              source: 'relations',
              name: def.name,
              relation: def.relation,
              matched: false,
              reason: 'no-relations-resolver',
            });
          }
          parts.push(FALSE);
        } else {
          parts.push(andNode([gate, relationNode(def.name, def.relation)]));
        }
      } else {
        const gate = constNode(intersects(def.parentRoles, principalRoleSet));
        parts.push(andNode([gate, planner.planCondition(def.condition)]));
      }
    }
    const node = orNode(parts);
    derivedRoleNodes.set(cacheKey, node);
    return node;
  }

  // ---- resource layer ------------------------------------------------------

  // A principal with no roles is rejected by every validation backend but the
  // engine runs without one by default; ResourcePolicy.check gives that case a
  // single anonymous bucket so wildcard rules still apply, and so does this.
  const resourceRoleBuckets = principalRoleSet.size > 0 ? [...principalRoleSet] : [null];

  function resourceLayerNode(action) {
    if (!resourcePolicy) return FALSE; // 'policy-miss' default deny
    const planner = plannerFor(resourcePolicy, resourcePolicy.shape.resourcePolicy);

    // Conflict resolution is per principal role (Cerbos >= 0.41): deny
    // overrides allow WITHIN a role, allow overrides deny ACROSS roles. So the
    // layer is a disjunction over roles of the old allow-and-not-deny form,
    // with each rule attributed to the roles it was written for — mirroring
    // ResourcePolicy.check exactly (PlanParity.test.js enforces this).
    const perRole = [];
    for (const role of resourceRoleBuckets) {
      const allowParts = [];
      const denyParts = [];

      for (const rule of resourcePolicy.rules ?? []) {
        if (!rule.actionsSet.has(ALL_ACTIONS) && !rule.actionsSet.has(action)) continue;

        let rolesGate = FALSE;
        if (Array.isArray(rule.roles)) {
          let covers = false;
          for (const ruleRole of rule.roles) {
            if (ruleRole === ALL_ROLES || ruleRole === role) {
              covers = true;
              break;
            }
          }
          rolesGate = constNode(covers);
        }
        let derivedGate = FALSE;
        if (Array.isArray(rule.derivedRoles)) {
          const derivedParts = new Array(rule.derivedRoles.length);
          for (let i = 0; i < rule.derivedRoles.length; i++) {
            derivedParts[i] = derivedRoleNode(rule.derivedRoles[i], role);
          }
          derivedGate = orNode(derivedParts);
        }
        const gate = orNode([rolesGate, derivedGate]);
        if (gate === FALSE) continue; // rule does not reach this role at all

        const node = andNode([gate, planner.planCondition(rule.condition)]);
        if (rule.effect === Effect.Deny) denyParts.push(node);
        else allowParts.push(node);
      }

      // Within this role: allowed ⇔ some allow ∧ no deny.
      perRole.push(andNode([orNode(allowParts), notNode(orNode(denyParts))]));
    }

    return orNode(perRole);
  }

  // ---- composition ---------------------------------------------------------

  // The role layer narrows the resource layer only when EVERY principal role is
  // constrained by an applicable role policy; a role without one is
  // unrestricted, so the union already permits everything. Mirrors
  // `#evaluateRolePolicies`.
  const roleLayerApplicable =
    applicableRolePolicies.length > 0 && applicableRolePolicies.length >= principalRoleSet.size;

  function planAction(action) {
    const { allow, deny } = principalNodes(action);
    // Role policies can never grant on their own — they filter the resource
    // layer, which is always the thing that decides.
    const layer = roleLayerApplicable
      ? andNode([resourceLayerNode(action), roleFilterNode(action)])
      : resourceLayerNode(action);
    return orNode([andNode([allow, notNode(deny)]), andNode([notNode(allow), notNode(deny), layer])]);
  }

  // Multi-action requests plan the conjunction (Cerbos semantics: the rows
  // where ALL requested actions are allowed). One pass fills both the
  // per-action map and the conjunction input.
  const perAction = new Map();
  const actionNodes = new Array(actions.length);
  for (let i = 0; i < actions.length; i++) {
    const node = planAction(actions[i]);
    perAction.set(actions[i], node);
    actionNodes[i] = node;
  }
  return { node: andNode(actionNodes), perAction };
}

module.exports = { buildResourcePlan };
