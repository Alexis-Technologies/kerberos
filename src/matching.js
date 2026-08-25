/**
 * Cerbos-style glob matching for policy name fields (actions, roles,
 * parentRoles, principal-policy resource, role-policy resource/allowActions).
 *
 * Semantics, verified against a live Cerbos PDP and Cerbos's own
 * `internal/util/globs_common.go` (globs compiled with `:` as the separator;
 * `fixGlob` rewrites a bare `*` to `**`):
 * - a bare `*` is special-cased and matches ANY value, `:` included;
 * - `**` matches across `:` segments;
 * - any other `*` matches within a single `:`-delimited segment only —
 *   `view:*` matches `view:public` but neither the bare `view` nor
 *   `view:a:b`, and `v*w` matches `view` but not `view:public`;
 * - patterns without a `*` are literal. Other gobwas-glob forms (`?`,
 *   `[...]`, `{a,b}`) are deliberately NOT supported — Cerbos's docs only
 *   document `*` wildcards, and anything fancier is treated here as literal
 *   text (recorded in conformance/DIVERGENCES.md).
 *
 * `rules[].derivedRoles` references are deliberately NOT globbed — Cerbos's
 * policy schema rejects `*` there (`^[\w\-\.]+$`).
 *
 * Platform-neutral, zero dependencies.
 */

const { ALL_ACTIONS } = require('./schemas');

// Escapes regex metacharacters except `*`; `**` crosses `:` segments, a
// single `*` stays within one.
function patternToRegExp(pattern) {
  // Splitting on `**` first keeps the two wildcard forms from interfering
  // regardless of what other characters the pattern contains.
  const parts = pattern.split('**').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^:]*'));
  return new RegExp(`^${parts.join('.*')}$`);
}

// Bounded pattern → RegExp cache for eval-time matching of patterns that are
// not precompiled at construction (derived-role parentRoles read back off the
// activation Map). Policies are static per instance, but dynamic/cache-backed
// policies could otherwise grow this without bound — evict FIFO like the
// codec's AST cache.
const MAX_CACHED_PATTERNS = 1000;
const compiledPatterns = new Map();

/**
 * Does one pattern match one value?
 *
 * @param {string} pattern
 * @param {string} value
 * @returns {boolean}
 */
function matchesPattern(pattern, value) {
  if (pattern === value) return true;
  if (pattern === ALL_ACTIONS) return true; // bare '*' — same token for every field
  if (typeof pattern !== 'string' || !pattern.includes('*')) return false;
  let re = compiledPatterns.get(pattern);
  if (!re) {
    if (compiledPatterns.size >= MAX_CACHED_PATTERNS) {
      compiledPatterns.delete(compiledPatterns.keys().next().value);
    }
    re = patternToRegExp(pattern);
    compiledPatterns.set(pattern, re);
  }
  return re.test(value);
}

/**
 * Precompiles a list of patterns into an O(1)-for-exact matcher. Built once
 * per rule at policy construction (mirrors the existing `actionsSet`
 * optimization), so the hot path pays a Set lookup for literal patterns and a
 * regex test only when a rule actually uses globs.
 *
 * @param {readonly string[]} patterns
 * @returns {{ matches(value: string): boolean, matchesAny(values: Iterable<string>): boolean }}
 */
function compileMatcher(patterns) {
  const exact = new Set();
  const globs = [];
  let matchAll = false;
  for (const pattern of patterns) {
    if (pattern === ALL_ACTIONS) matchAll = true;
    else if (typeof pattern === 'string' && pattern.includes('*')) globs.push(patternToRegExp(pattern));
    else exact.add(pattern);
  }
  return {
    matches(value) {
      if (matchAll || exact.has(value)) return true;
      for (const re of globs) if (re.test(value)) return true;
      return false;
    },
    matchesAny(values) {
      for (const value of values) if (this.matches(value)) return true;
      return false;
    },
  };
}

module.exports = { compileMatcher, matchesPattern };
