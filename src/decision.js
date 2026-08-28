/**
 * The unified decision walk — Cerbos's rule-table semantics, verified against
 * a live PDP (see conformance/):
 *
 * For every action, and for every principal role independently (the
 * "buckets"), walk the RESOURCE scope chain from the most specific scope to
 * the base. At each scope the bucket sees:
 *
 * - the resource policy's rules at that scope that FIRE for the action
 *   (action glob-matches, condition holds) and REACH this bucket — directly
 *   through `roles`, or through an active derived role whose `parentRoles`
 *   cover the bucket;
 * - synthetic DENY rows from role policies: a role policy AT THAT SCOPE for
 *   the bucket's role (or a transitive `parentRoles` ancestor) that does not
 *   allowlist the action for this resource kind denies it — which also means
 *   a role policy constrains its role for EVERY kind, including kinds its
 *   rules never mention.
 *
 * Within a scope, deny beats allow for the bucket; the first scope that
 * decides seals the bucket (a condition that fails is no decision — the walk
 * falls through). Across buckets an ALLOW from any role wins (anti-lockout).
 * Nothing decided anywhere → default deny.
 *
 * This one walk subsumes what used to be three separate mechanisms (resource
 * conflict resolution, the role-policy filter, per-source scope lookup), and
 * is shared by `ResourcePolicy.check` (a single-scope, no-rows instance of
 * it), both engine drivers, and — symbolically — the query planner.
 *
 * Pure and synchronous; the engine resolves policies/derived roles first.
 */

const { Effect } = require('./schemas');
const { matchesPattern } = require('./matching.js');

/**
 * Does `rule` (already known to have fired) reach principal role `role`?
 *
 * `derivedRoles` maps active derived-role name → its definition's
 * `parentRoles` (null/empty when ungated, e.g. relation-backed — those reach
 * every bucket). Entries glob-match per Cerbos (`team_*`, bare `*`).
 * `role === null` is the anonymous bucket of a principal with no roles: only
 * bare-`*` patterns reach it.
 */
function ruleCoversRole(rule, role, derivedRoles) {
  if (Array.isArray(rule.roles)) {
    for (const pattern of rule.roles) {
      if (pattern === '*' || (role !== null && matchesPattern(pattern, role))) return true;
    }
  }
  if (Array.isArray(rule.derivedRoles) && derivedRoles) {
    for (const name of rule.derivedRoles) {
      if (!derivedRoles.has(name)) continue;
      // A plain Set (legacy call shape) carries no parentRoles — treat the
      // active role as reaching every bucket.
      const parentRoles = derivedRoles.get?.(name);
      if (!Array.isArray(parentRoles) || parentRoles.length === 0) return true;
      for (const pattern of parentRoles) {
        if (pattern === '*' || (role !== null && matchesPattern(pattern, role))) return true;
      }
    }
  }
  return false;
}

/**
 * @param {object} input
 * @param {Record<string, unknown>} input.req - narrowed to the undecided actions
 * @param {Array<{
 *   scope: string,
 *   resource: { policy: import('./ResourcePolicy').ResourcePolicy, derivedRoles: Map<string, string[]|null> } | null,
 *   rows: Map<string|null, Array<import('./RolePolicy').RolePolicy>>,
 * }>} input.scopes - one entry per scope of the resource scope chain, most specific first
 * @returns {{ effects: Map, outputs: Map, meta: { actions: Record<string, object>, effectiveDerivedRoles: string[] }, hadSources: boolean }}
 */
function evaluateDecisionLayer({ req, scopes }) {
  const effects = new Map();
  const outputs = new Map();
  const actionsMeta = {};
  const effectiveDerivedRoles = new Set();

  const uniqueRoles = [];
  {
    const seen = new Set();
    for (const role of req.P.roles ?? []) {
      if (!seen.has(role)) {
        seen.add(role);
        uniqueRoles.push(role);
      }
    }
  }
  // A principal with no roles is rejected by every validation backend, but the
  // engine runs without one by default — one anonymous bucket keeps bare-`*`
  // rules working instead of silently denying.
  const buckets = uniqueRoles.length > 0 ? uniqueRoles : [null];

  // Evaluate each policy once (rules fire per action; outputs are emitted for
  // every evaluated rule, sealed or not — matching single-policy behavior).
  let hadSources = false;
  let mostSpecificSrcBase = null;
  const scopeEvals = [];
  const rowVerdicts = new Map();
  for (const entry of scopes) {
    let resourceEval = null;
    if (entry.resource) {
      hadSources = true;
      resourceEval = entry.resource.policy.evaluateRules(req, entry.resource.derivedRoles);
      mostSpecificSrcBase ??= resourceEval.srcBase;
      for (const [src, output] of resourceEval.outputs) outputs.set(src, output);
      for (const name of entry.resource.derivedRoles.keys()) effectiveDerivedRoles.add(name);
    }
    for (const policies of entry.rows.values()) {
      for (const policy of policies) {
        if (rowVerdicts.has(policy)) continue;
        hadSources = true;
        const verdict = policy.evaluateAllowlist(req);
        rowVerdicts.set(policy, verdict);
        for (const [src, output] of verdict.outputs) outputs.set(src, output);
      }
    }
    scopeEvals.push({ ...entry, resourceEval });
  }

  for (const action of req.actions) {
    let winningAllow = null;
    let firstDenyMeta = null;
    let conditionFailed = false;

    for (const role of buckets) {
      for (const { resourceEval, rows } of scopeEvals) {
        const perAction = resourceEval?.actions.get(action);
        if (perAction?.conditionFailed) conditionFailed = true;

        // Deny beats allow within the bucket at this scope.
        let deny = null;
        if (perAction) {
          for (const fired of perAction.firedDenies) {
            if (ruleCoversRole(fired.rule, role, resourceEval.derivedRoles)) {
              deny = { matchedPolicy: resourceEval.srcBase, matchedRule: fired.src, scope: resourceEval.scope };
              // keep scanning: the LAST covering deny names the rule (existing convention)
            }
          }
        }
        if (!deny) {
          const rowPolicies = rows.get(role);
          if (rowPolicies) {
            for (const policy of rowPolicies) {
              const verdict = rowVerdicts.get(policy);
              if (verdict.allowed.has(action)) continue;
              if (verdict.conditionFailed.has(action)) conditionFailed = true;
              deny = {
                matchedPolicy: verdict.srcBase,
                reason: verdict.conditionFailed.has(action) ? 'condition-not-met' : 'rule-miss',
                scope: verdict.scope,
              };
              break;
            }
          }
        }
        if (deny) {
          if (!firstDenyMeta) firstDenyMeta = deny;
          break;
        }

        if (perAction) {
          let allow = null;
          for (const fired of perAction.firedAllows) {
            if (ruleCoversRole(fired.rule, role, resourceEval.derivedRoles)) {
              allow = { matchedPolicy: resourceEval.srcBase, matchedRule: fired.src, scope: resourceEval.scope };
            }
          }
          if (allow) {
            winningAllow = allow;
            break;
          }
        }
      }
      // Across buckets an allow wins immediately.
      if (winningAllow) break;
    }

    if (winningAllow) {
      effects.set(action, Effect.Allow);
      actionsMeta[action] = { matchedPolicy: winningAllow.matchedPolicy, matchedRule: winningAllow.matchedRule };
      if (winningAllow.scope) actionsMeta[action].matchedScope = winningAllow.scope;
      continue;
    }

    if (!hadSources) continue; // engine records 'policy-miss'

    effects.set(action, Effect.Deny);
    if (firstDenyMeta) {
      const meta = { matchedPolicy: firstDenyMeta.matchedPolicy };
      if (firstDenyMeta.matchedRule) meta.matchedRule = firstDenyMeta.matchedRule;
      if (firstDenyMeta.reason) meta.reason = firstDenyMeta.reason;
      if (firstDenyMeta.scope) meta.matchedScope = firstDenyMeta.scope;
      actionsMeta[action] = meta;
    } else {
      // Nothing fired anywhere: default deny, explained.
      const meta = { reason: conditionFailed ? 'condition-not-met' : 'rule-miss' };
      if (mostSpecificSrcBase) meta.matchedPolicy = mostSpecificSrcBase;
      actionsMeta[action] = meta;
    }
  }

  return {
    effects,
    outputs,
    meta: { actions: actionsMeta, effectiveDerivedRoles: [...effectiveDerivedRoles] },
    hadSources,
  };
}

module.exports = { evaluateDecisionLayer, ruleCoversRole };
