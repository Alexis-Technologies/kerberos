const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const {
  addConcrete,
  cloneSubjectSet,
  emptySubjectSet,
  intersectSubjectSets,
  normalizeSubjectSet,
  subtractSubjectSets,
  unionSubjectSets,
  wildcardCovers,
} = require('../src/Relations/subjectSet.js');

// Direct unit tests for the subject-set algebra (previously only reachable
// through end-to-end lookupSubjects walks). The semantics are subtle and
// security-relevant — especially subtraction's wildcard-minus-wildcard rule —
// so the case matrix lives here as data.

// Compact constructors: c(type, ...ids) = concrete members; w(type, ...excl)
// = a wildcard with exclusions.
function build(...parts) {
  const set = emptySubjectSet();
  for (const part of parts) {
    if (part.kind === 'c') for (const id of part.ids) addConcrete(set, part.type, id);
    else set.wildcards.set(part.type, new Set(part.ids));
  }
  return normalizeSubjectSet(set);
}
const c = (type, ...ids) => ({ kind: 'c', type, ids });
const w = (type, ...ids) => ({ kind: 'w', type, ids });

// Canonical, comparable rendering: sorted concrete ids + sorted exclusions.
function render(set) {
  const out = { concrete: {}, wildcards: {} };
  for (const [type, ids] of set.concrete) out.concrete[type] = [...ids].sort();
  for (const [type, exclusions] of set.wildcards) out.wildcards[type] = [...exclusions].sort();
  return out;
}

describe('subject-set algebra', () => {
  describe('union', () => {
    const cases = [
      ['concrete ∪ concrete merges ids', build(c('user', 'a')), build(c('user', 'b')), build(c('user', 'a', 'b'))],
      [
        'concrete ∪ wildcard keeps both layers',
        build(c('user', 'a')),
        build(w('user')),
        build(c('user', 'a'), w('user')),
      ],
      [
        'wildcard exclusions survive only when excluded on BOTH sides',
        build(w('user', 'a', 'b')),
        build(w('user', 'b', 'x')),
        build(w('user', 'b')),
      ],
      [
        'a concrete member voids the same-type exclusion',
        build(c('user', 'a')),
        build(w('user', 'a', 'b')),
        // 'a' is independently a member, so excluding it from the wildcard is
        // void; 'b' stays excluded... but union with the left side (no
        // wildcard) keeps the right side's exclusions minus members.
        build(c('user', 'a'), w('user', 'b')),
      ],
      [
        'types are independent',
        build(c('user', 'a')),
        build(c('group', 'g'), w('svc')),
        build(c('user', 'a'), c('group', 'g'), w('svc')),
      ],
    ];
    for (const [name, left, right, expected] of cases) {
      it(name, () => {
        assert.deepEqual(render(unionSubjectSets(cloneSubjectSet(left), right)), render(expected));
      });
    }
  });

  describe('intersection', () => {
    const cases = [
      [
        'concrete ∩ concrete keeps common ids',
        build(c('user', 'a', 'b')),
        build(c('user', 'b', 'x')),
        build(c('user', 'b')),
      ],
      [
        'concrete ∩ wildcard keeps unexcluded members',
        build(c('user', 'a', 'b')),
        build(w('user', 'b')),
        build(c('user', 'a')),
      ],
      [
        'wildcard ∩ wildcard unions the exclusions',
        build(w('user', 'a')),
        build(w('user', 'b')),
        build(w('user', 'a', 'b')),
      ],
      ['disjoint types intersect to empty', build(c('user', 'a')), build(c('group', 'a')), build()],
      [
        'wildcard ∩ concrete (symmetric case) keeps unexcluded members',
        build(w('user', 'b')),
        build(c('user', 'a', 'b')),
        build(c('user', 'a')),
      ],
    ];
    for (const [name, left, right, expected] of cases) {
      it(name, () => {
        assert.deepEqual(render(intersectSubjectSets(left, right)), render(expected));
      });
    }
  });

  describe('subtraction', () => {
    const cases = [
      ['concrete − concrete removes ids', build(c('user', 'a', 'b')), build(c('user', 'b')), build(c('user', 'a'))],
      [
        'concrete − wildcard removes unexcluded members',
        build(c('user', 'a', 'b')),
        build(w('user', 'b')),
        // 'a' is covered by the wildcard (removed); 'b' is excluded from the
        // subtrahend wildcard, so it survives.
        build(c('user', 'b')),
      ],
      [
        'wildcard − concrete adds ids to the exclusions',
        build(w('user')),
        build(c('user', 'a')),
        build(w('user', 'a')),
      ],
      [
        'wildcard − wildcard: subtrahend exclusions become concrete members unless also excluded in the minuend',
        build(w('user', 'a')),
        build(w('user', 'a', 'b')),
        // The wildcard cancels; 'b' (excluded only from the subtrahend) was
        // NOT subtracted, so it materializes as a concrete member. 'a' was
        // excluded on both sides — gone entirely.
        build(c('user', 'b')),
      ],
      [
        'other types are untouched',
        build(c('user', 'a'), c('group', 'g')),
        build(c('user', 'a')),
        build(c('group', 'g')),
      ],
    ];
    for (const [name, target, other, expected] of cases) {
      it(name, () => {
        assert.deepEqual(render(subtractSubjectSets(cloneSubjectSet(target), other)), render(expected));
      });
    }
  });

  describe('helpers', () => {
    it('wildcardCovers respects exclusions', () => {
      const set = build(w('user', 'blocked'));
      assert.equal(wildcardCovers(set, 'user', 'anyone'), true);
      assert.equal(wildcardCovers(set, 'user', 'blocked'), false);
      assert.equal(wildcardCovers(set, 'group', 'anyone'), false);
    });

    it('normalize drops exclusions that are independently concrete members', () => {
      const set = emptySubjectSet();
      addConcrete(set, 'user', 'a');
      set.wildcards.set('user', new Set(['a', 'b']));
      assert.deepEqual(render(normalizeSubjectSet(set)), render(build(c('user', 'a'), w('user', 'b'))));
    });

    it('clone is deep for both layers', () => {
      const original = build(c('user', 'a'), w('group', 'x'));
      const clone = cloneSubjectSet(original);
      clone.concrete.get('user').add('b');
      clone.wildcards.get('group').add('y');
      assert.deepEqual(render(original), render(build(c('user', 'a'), w('group', 'x'))));
    });
  });
});
