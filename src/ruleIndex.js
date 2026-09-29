/**
 * Per-policy rule indexes for the decision hot path.
 *
 * A policy's rules are static, yet every check used to test every rule
 * against every requested action — decision cost grew with the size of the
 * policy rather than with the rules that could actually fire. These indexes
 * answer "which rules can fire for this key?" from a small per-policy cache:
 *
 * - `createRuleIndex` (resource policies): rules whose `actions` match the
 *   action, further split by the principal role they reach once an action has
 *   enough rules for the split to pay off;
 * - `createKeyedSelector` (principal/role policies): rules whose `resource`
 *   matches the sanitized kind.
 *
 * Indexes only NARROW a scan. Callers keep their per-rule checks, and
 * candidates always come back in rule order, so which rules fire — and the
 * order they fire in (meta attribution, outputs) — is unchanged.
 *
 * Platform-neutral, zero dependencies.
 */

const { ALL_ROLES } = require('./schemas');

// Keys are request-supplied strings (actions, kinds). Bound the cache so a
// stream of distinct keys cannot grow it without limit — evicted FIFO, like
// the glob pattern cache in matching.js.
const MAX_CACHED_KEYS = 256;
// At or below this many rules for one action, handing back the whole list is
// cheaper than merging per-role buckets.
const SPLIT_THRESHOLD = 8;
const NO_INDICES = Object.freeze([]);

function remember(cache, key, value) {
  if (cache.size >= MAX_CACHED_KEYS) cache.delete(cache.keys().next().value);
  cache.set(key, value);
}

/**
 * Selects, per key, the ascending indices of the items `matches` accepts.
 *
 * @param {number} count - number of items
 * @param {(index: number, key: unknown) => boolean} matches
 * @returns {(key: unknown) => readonly number[]}
 */
function createKeyedSelector(count, matches) {
  const cache = new Map();
  return (key) => {
    let indices = cache.get(key);
    if (indices !== undefined) return indices;
    indices = [];
    for (let i = 0; i < count; i++) if (matches(i, key)) indices.push(i);
    remember(cache, key, indices);
    return indices;
  };
}

// Splits one action's rules by how they can reach a principal. A rule that
// lists a bare `*`, a glob or any derived role is a candidate for every
// principal (the per-rule checks decide); a rule listing only literal roles
// is a candidate only for principals holding one of them; a rule with
// neither roles nor derived roles reaches nobody and is dropped.
function splitByRole(rules, indices) {
  const always = [];
  const byRole = new Map();
  for (const i of indices) {
    const rule = rules[i];
    if (Array.isArray(rule.derivedRoles) && rule.derivedRoles.length > 0) {
      always.push(i);
      continue;
    }
    if (!Array.isArray(rule.roles)) continue;
    if (rule.roles.some((role) => role === ALL_ROLES || (typeof role === 'string' && role.includes('*')))) {
      always.push(i);
      continue;
    }
    for (const role of new Set(rule.roles)) {
      const list = byRole.get(role);
      if (list) list.push(i);
      else byRole.set(role, [i]);
    }
  }
  return { always, byRole };
}

/**
 * Index over a resource policy's rules, keyed by action.
 *
 * @param {readonly object[]} rules - rules carrying precompiled `actionsMatcher`
 * @returns {{
 *   forAction(action: string): readonly number[],
 *   candidates(action: string, principalRoles: readonly string[]): readonly number[],
 *   referencedDerivedRoles(action: string): ReadonlySet<string>,
 * }}
 */
function createRuleIndex(rules) {
  const cache = new Map();

  function entryFor(action) {
    let entry = cache.get(action);
    if (entry !== undefined) return entry;
    const indices = [];
    for (let i = 0; i < rules.length; i++) {
      if (rules[i].actionsMatcher.matches(action)) indices.push(i);
    }
    entry = {
      indices,
      split: indices.length > SPLIT_THRESHOLD ? splitByRole(rules, indices) : null,
      derivedRoles: null,
    };
    remember(cache, action, entry);
    return entry;
  }

  return {
    /** Every rule whose `actions` match, in rule order. */
    forAction(action) {
      return entryFor(action).indices;
    },

    /** The rules of `forAction` that can reach a principal with these roles. */
    candidates(action, principalRoles) {
      const entry = entryFor(action);
      if (entry.split === null) return entry.indices;
      const { always, byRole } = entry.split;

      let single = always.length > 0 ? always : null;
      let merged = null;
      for (const role of principalRoles) {
        const list = byRole.get(role);
        if (list === undefined || list === single) continue;
        if (single === null) {
          single = list;
          continue;
        }
        merged ??= [...single];
        for (const i of list) merged.push(i);
      }
      if (merged === null) return single ?? NO_INDICES;

      // Restore rule order and drop duplicates (a rule listing two of the
      // principal's roles arrives once per role).
      merged.sort((a, b) => a - b);
      let length = 0;
      for (let i = 0; i < merged.length; i++) {
        if (length === 0 || merged[i] !== merged[length - 1]) merged[length++] = merged[i];
      }
      merged.length = length;
      return merged;
    },

    /** Derived-role names referenced by the rules of `forAction`. */
    referencedDerivedRoles(action) {
      const entry = entryFor(action);
      if (entry.derivedRoles === null) {
        const names = new Set();
        for (const i of entry.indices) {
          const refs = rules[i].derivedRoles;
          if (Array.isArray(refs)) for (const name of refs) names.add(name);
        }
        entry.derivedRoles = names;
      }
      return entry.derivedRoles;
    },
  };
}

module.exports = { createKeyedSelector, createRuleIndex, SPLIT_THRESHOLD, MAX_CACHED_KEYS };
