/**
 * Subject-set algebra for the resolver's `lookupSubjects` collect-walk, keyed
 * per type:
 *   { concrete: Map<type, Set<id>>, wildcards: Map<type, Set<excluded id>> }
 *
 * Per-type Maps make wildcard coverage and subtraction O(1) per id instead of
 * slicing/`startsWith`-scanning composite string keys. Caveated tuples are
 * INCLUDED (results are an upper bound for them) — use check() for
 * per-subject certainty.
 *
 * Flat infra module (the src/planning/ style) extracted from
 * RelationResolver.js so the security-relevant case matrix — concrete ×
 * wildcard × exclusion across union/intersection/subtraction — is directly
 * unit-testable instead of only reachable through end-to-end lookup walks.
 */

function emptySubjectSet() {
  return { concrete: new Map(), wildcards: new Map() };
}

function cloneSubjectSet(set) {
  const clone = emptySubjectSet();
  for (const [type, ids] of set.concrete) clone.concrete.set(type, new Set(ids));
  for (const [type, exclusions] of set.wildcards) clone.wildcards.set(type, new Set(exclusions));
  return clone;
}

function addConcrete(set, type, id) {
  let ids = set.concrete.get(type);
  if (!ids) {
    ids = new Set();
    set.concrete.set(type, ids);
  }
  ids.add(id);
}

function wildcardCovers(set, type, id) {
  const exclusions = set.wildcards.get(type);
  return exclusions !== undefined && !exclusions.has(id);
}

function normalizeSubjectSet(set) {
  // An exclusion that is also independently a concrete member is void.
  for (const [type, exclusions] of set.wildcards) {
    const ids = set.concrete.get(type);
    if (!ids) continue;
    for (const id of exclusions) if (ids.has(id)) exclusions.delete(id);
  }
  return set;
}

function unionSubjectSets(target, other) {
  for (const [type, ids] of other.concrete) {
    let targetIds = target.concrete.get(type);
    if (!targetIds) {
      targetIds = new Set();
      target.concrete.set(type, targetIds);
    }
    for (const id of ids) targetIds.add(id);
  }
  for (const [type, otherExclusions] of other.wildcards) {
    const existing = target.wildcards.get(type);
    if (existing === undefined) {
      target.wildcards.set(type, new Set(otherExclusions));
      continue;
    }
    // Excluded from the union only if excluded on both sides. Deleting the
    // current entry during Set iteration is safe per spec.
    for (const id of existing) if (!otherExclusions.has(id)) existing.delete(id);
  }
  return normalizeSubjectSet(target);
}

function intersectSubjectSets(a, b) {
  const result = emptySubjectSet();
  for (const [type, ids] of a.concrete) {
    const bIds = b.concrete.get(type);
    for (const id of ids) {
      if ((bIds !== undefined && bIds.has(id)) || wildcardCovers(b, type, id)) addConcrete(result, type, id);
    }
  }
  for (const [type, ids] of b.concrete) {
    for (const id of ids) {
      if (wildcardCovers(a, type, id)) addConcrete(result, type, id);
    }
  }
  for (const [type, aExclusions] of a.wildcards) {
    const bExclusions = b.wildcards.get(type);
    if (bExclusions === undefined) continue;
    const merged = new Set(aExclusions);
    for (const id of bExclusions) merged.add(id);
    result.wildcards.set(type, merged);
  }
  return normalizeSubjectSet(result);
}

function subtractSubjectSets(target, other) {
  for (const [type, ids] of target.concrete) {
    const otherIds = other.concrete.get(type);
    for (const id of ids) {
      if ((otherIds !== undefined && otherIds.has(id)) || wildcardCovers(other, type, id)) ids.delete(id);
    }
    if (!ids.size) target.concrete.delete(type);
  }
  for (const [type, exclusions] of target.wildcards) {
    const otherExclusions = other.wildcards.get(type);
    if (otherExclusions !== undefined) {
      // `type:* - type:*` removes the wildcard; the subtrahend's exclusions
      // survive (they were not subtracted) unless excluded here too.
      target.wildcards.delete(type);
      for (const id of otherExclusions) if (!exclusions.has(id)) addConcrete(target, type, id);
      continue;
    }
    const otherIds = other.concrete.get(type);
    if (otherIds !== undefined) for (const id of otherIds) exclusions.add(id);
  }
  return normalizeSubjectSet(target);
}

module.exports = {
  addConcrete,
  cloneSubjectSet,
  emptySubjectSet,
  intersectSubjectSets,
  normalizeSubjectSet,
  subtractSubjectSets,
  unionSubjectSets,
  wildcardCovers,
};
