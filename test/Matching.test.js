const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { compileKindMatcher, compileMatcher, matchesPattern, sanitizeResourceKind } = require('../src/matching.js');

// Cerbos glob semantics (internal/util/globs_common.go): globs are compiled
// with `:` as the separator and a bare `*` is rewritten to `**`. The case
// matrix is data — every row is verified against a live PDP through the
// conformance wildcards suite.
describe('matching', () => {
  const cases = [
    // pattern, value, expected
    ['*', 'view', true],
    ['*', 'view:public', true], // bare * crosses segments (fixGlob: '*' → '**')
    ['**', 'a:b:c', true],
    ['view:*', 'view:public', true],
    ['view:*', 'view', false], // the literal `view:` prefix is required
    ['view:*', 'view:a:b', false], // a single * cannot cross `:`
    ['deep:**', 'deep:a:b', true],
    ['v*w', 'view', true], // mid-segment glob
    ['v*w', 'view:public', false],
    ['team_*', 'team_red', true],
    ['team_*', 'team:red', false],
    ['adm*', 'admin', true],
    ['exact', 'exact', true],
    ['exact', 'other', false],
    ['a.b*', 'aXbc', false], // regex metacharacters stay literal
    ['a.b*', 'a.bc', true],
    ['a+b', 'a+b', true],
    ['a+b', 'aab', false],
  ];

  for (const [pattern, value, expected] of cases) {
    it(`${JSON.stringify(pattern)} vs ${JSON.stringify(value)} → ${expected}`, () => {
      assert.equal(matchesPattern(pattern, value), expected);
    });
  }

  it('compileMatcher mixes exact and glob patterns', () => {
    const matcher = compileMatcher(['view', 'edit:*']);
    assert.equal(matcher.matches('view'), true);
    assert.equal(matcher.matches('edit:x'), true);
    assert.equal(matcher.matches('edit'), false);
    assert.equal(matcher.matches('edit:x:y'), false);
    assert.equal(matcher.matchesAny(['nope', 'view']), true);
    assert.equal(matcher.matchesAny(['nope']), false);
  });

  it('compileMatcher with a bare * matches everything', () => {
    const matcher = compileMatcher(['*']);
    assert.equal(matcher.matches('anything:at:all'), true);
  });
});

// Cerbos runs resource KIND names through namer.SanitizedResource before they
// reach the rule table (both the policy field and the request kind). Every row
// below was verified against a live Cerbos 0.55.0 PDP.
describe('resource-kind sanitization', () => {
  const sanitized = [
    ['gla:b', 'gla_b'],
    ['gl:x', 'gl_x'],
    ['a-b', 'a_b'],
    ['a/b', 'a_b'],
    ['a@b', 'a_b'],
    ['a_b', 'a_b'],
    ['a.b', 'a.b'], // dots are identifier-safe for Cerbos
    ['UP-x', 'UP_x'],
    ['plain', 'plain'],
    // Not a legacy-shaped name → passed through untouched.
    ['1a:b', '1a:b'],
    ['a::b', 'a::b'],
    ['gl*', 'gl*'],
    ['doc:*', 'doc:*'],
    ['', ''],
  ];

  for (const [input, expected] of sanitized) {
    it(`${JSON.stringify(input)} → ${JSON.stringify(expected)}`, () => {
      assert.equal(sanitizeResourceKind(input), expected);
    });
  }

  it('leaves non-string input alone', () => {
    assert.equal(sanitizeResourceKind(undefined), undefined);
    assert.equal(sanitizeResourceKind(42), 42);
  });

  const kindMatches = [
    // A single `*` appears to cross `:` because the kind no longer has one.
    ['gl*', 'gla:b', true],
    ['gl*', 'gl:x', true],
    ['gl*', 'glx', true],
    ['gl*', 'gl', true],
    // A pattern containing `:` can never match a sanitized kind.
    ['doc:*', 'doc:x', false],
    ['doc:*', 'doc_x', false],
    ['doc:*', 'docx', false],
    // Separators collapse into `_`, so these spellings are one kind.
    ['a-b', 'a-b', true],
    ['a-b', 'a_b', true],
    ['a-b', 'a/b', true],
    ['a_b', 'a-b', true],
    ['x*y', 'x:y', true],
    ['x*y', 'xay', true],
    // Kinds outside the legacy name pattern stay literal on both sides.
    ['1a:b', '1a:b', true],
    ['1a:b', '1a_b', false],
    ['a::b', 'a::b', true],
    // Matching is case-sensitive.
    ['UP-x', 'UP_x', true],
    ['UP-x', 'up-x', false],
    ['**', 'anything:at:all', true],
  ];

  for (const [pattern, kind, expected] of kindMatches) {
    it(`rule ${JSON.stringify(pattern)} vs kind ${JSON.stringify(kind)} → ${expected}`, () => {
      assert.equal(compileKindMatcher(pattern).matches(sanitizeResourceKind(kind)), expected);
    });
  }
});
