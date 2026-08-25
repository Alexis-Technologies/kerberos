const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { compileMatcher, matchesPattern } = require('../src/matching.js');

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
