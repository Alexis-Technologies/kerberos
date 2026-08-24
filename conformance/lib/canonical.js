'use strict';

/**
 * Canonicalizes a planResources filter so two engines can be compared on
 * meaning rather than on incidental syntax.
 *
 * Neither engine promises a normal form for operand order: Cerbos emits
 * comparison operands in source order, and both engines flatten/dedupe
 * `and`/`or` children by their own rules. Deep-equalling raw JSON therefore
 * produces false failures. This sorts the children of commutative operators by
 * a stable serialization, which is meaning-preserving for the operators listed
 * below and for nothing else — anything not listed keeps its operand order.
 */

// Commutative *and* associative: children may be reordered freely.
const REORDERABLE = new Set(['and', 'or']);
// Commutative binary comparisons: the two operands may be swapped.
const SWAPPABLE = new Set(['eq', 'ne']);

// Operators Kerberos emits that have no Cerbos counterpart. A plan containing
// one is out of scope for parity rather than a failure.
const KERBEROS_ONLY = new Set(['opaque', 'relation']);

function stableKey(node) {
  return JSON.stringify(node);
}

function canonicalizeOperand(operand) {
  if (!operand || typeof operand !== 'object') return operand;

  if (operand.expression) {
    const { operator, operands = [] } = operand.expression;
    let children = operands.map(canonicalizeOperand);
    if (REORDERABLE.has(operator) || (SWAPPABLE.has(operator) && children.length === 2)) {
      children = [...children].sort((a, b) => (stableKey(a) < stableKey(b) ? -1 : stableKey(a) > stableKey(b) ? 1 : 0));
    }
    return { expression: { operator, operands: children } };
  }

  // `value` / `variable` leaves are already canonical; re-wrap so key order in
  // the serialization cannot differ.
  if ('variable' in operand) return { variable: operand.variable };
  if ('value' in operand) return { value: operand.value };
  return operand;
}

function canonicalizeFilter(filter) {
  if (!filter || typeof filter !== 'object') return filter;
  if (filter.condition === undefined) return { kind: filter.kind };
  return { kind: filter.kind, condition: canonicalizeOperand(filter.condition) };
}

/** Collects every operator appearing in a filter, for scope checks. */
function collectOperators(operand, into = new Set()) {
  if (!operand || typeof operand !== 'object') return into;
  if (operand.expression) {
    into.add(operand.expression.operator);
    for (const child of operand.expression.operands ?? []) collectOperators(child, into);
  }
  return into;
}

/** True when the plan uses a Kerberos extension Cerbos cannot express. */
function usesKerberosOnlyOperators(filter) {
  if (!filter?.condition) return false;
  for (const operator of collectOperators(filter.condition)) {
    if (KERBEROS_ONLY.has(operator)) return true;
  }
  return false;
}

module.exports = { canonicalizeFilter, collectOperators, usesKerberosOnlyOperators };
