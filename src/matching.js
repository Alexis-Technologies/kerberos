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

// Cerbos sanitizes resource KIND names before they reach the rule table:
// `namer.SanitizedResource` (internal/namer/namer.go) replaces every run of
// `[^\w.]` with `_`, but only for names matching its legacy `oldNamePattern`.
// Both sides of a kind comparison go through it — the `resource` field of
// resource/principal/role policies AND the `resource.kind` of the request —
// so for Cerbos `a-b`, `a/b`, `a@b` and `a:b` are all the same kind `a_b`
// (two policies spelled that way are a duplicate-definition COMPILE error),
// and a glob like `gl*` matches the kind `gla:b` because the `:` is gone by
// the time the pattern runs. A pattern that itself contains `*` never
// matches the legacy pattern, so it is passed through unchanged — which is
// why `doc:*` matches NO kind at all in Cerbos.
//
// Verified against a live Cerbos 0.55.0 PDP; recorded in
// conformance/DIVERGENCES.md. Names are ASCII-only in Go's RE2
// (`[[:alpha:]]` / `[[:word:]]`), which is what `\w` means here too (no `u`
// flag), so the two regexes match the same strings.
const LEGACY_KIND_NAME = /^[A-Za-z][\w@.\-/]*(:[A-Za-z][\w@.\-/]*)*$/;
const NON_IDENTIFIER_CHARS = /[^\w.]+/g;
// Same class, non-global: `.test()` on a /g regex is stateful (lastIndex).
const HAS_NON_IDENTIFIER_CHAR = /[^\w.]/;

/**
 * Cerbos's resource-name sanitization, applied to one kind or one policy
 * `resource` field. Returns the value unchanged when it is not a legacy-shaped
 * name (a glob, a name starting with a digit, `a::b`, …).
 *
 * @param {string} kind
 * @returns {string}
 */
// One request asks for the same kind several times (the resource-policy
// lookup, then every principal/role policy along the chain), so the last
// answer is memoized — a string identity check instead of a regex test. One
// slot, no eviction policy needed.
let lastKind;
let lastSanitizedKind;

function sanitizeResourceKind(kind) {
  if (kind === lastKind) return lastSanitizedKind;
  // A kind made only of identifier characters sanitizes to itself, whatever
  // its shape — one unanchored test, no replace, no allocation.
  let sanitized = kind;
  if (typeof kind === 'string' && HAS_NON_IDENTIFIER_CHAR.test(kind) && LEGACY_KIND_NAME.test(kind)) {
    sanitized = kind.replace(NON_IDENTIFIER_CHARS, '_');
  }
  lastKind = kind;
  lastSanitizedKind = sanitized;
  return sanitized;
}

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

/**
 * `compileMatcher` for a policy field that names a resource KIND
 * (principal-policy / role-policy `resource`): the pattern is sanitized the
 * way Cerbos sanitizes it at compile time. Callers must pass an equally
 * sanitized kind to `matches()` — use `sanitizeResourceKind` once per
 * request rather than once per rule.
 *
 * @param {string} pattern
 * @returns {{ matches(value: string): boolean, matchesAny(values: Iterable<string>): boolean }}
 */
function compileKindMatcher(pattern) {
  return compileMatcher([sanitizeResourceKind(pattern)]);
}

module.exports = { compileKindMatcher, compileMatcher, matchesPattern, sanitizeResourceKind };
