/**
 * Plan-node model for `kerberos.planResources()`.
 *
 * Nodes form a boolean tree over residual conditions. The constructors
 * normalize on the way up (constant folding, flattening, dedup), so any tree
 * built through them is already in normal form: `const` nodes only ever
 * survive at the root, `and`/`or` never nest a child of the same kind and
 * always hold at least two children, `not` never wraps a constant.
 *
 * Serialization (`toFilter`) produces the Cerbos PlanResources filter shape —
 * `KIND_ALWAYS_ALLOWED` / `KIND_ALWAYS_DENIED` / `KIND_CONDITIONAL` with an
 * `{ operator, operands }` expression tree — extended with two Kerberos
 * operators: `opaque` (statically unplannable condition, translators must
 * post-filter) and `relation` (ReBAC dependency, see expandRelationOperands).
 *
 * @typedef {Record<string, unknown>} PlanOperand
 *   Cerbos operand: `{ value }` | `{ variable }` | `{ expression: { operator, operands } }`.
 * @typedef {(
 *   { t: 'const', v: boolean } |
 *   { t: 'expr', e: PlanOperand } |
 *   { t: 'and' | 'or', children: PlanNode[] } |
 *   { t: 'not', child: PlanNode } |
 *   { t: 'opaque', src: string, reason: string } |
 *   { t: 'relation', name: string, relation: string }
 * )} PlanNode
 */

/**
 * Builds a prototype-less dispatch table (same rationale as the codec's
 * interpreter tables: lookups can never resolve to inherited members and the
 * hot path stays O(1) instead of a switch scan). Shared by the planning
 * modules.
 *
 * @param {Record<string, unknown>} entries
 * @returns {Record<string, unknown>}
 */
function createDispatch(entries) {
  return Object.assign(Object.create(null), entries);
}

// Runtime enum (typed as `enum PlanKind` in index.d.ts, like `Effect`).
const PlanKind = Object.freeze({
  AlwaysAllowed: 'KIND_ALWAYS_ALLOWED',
  AlwaysDenied: 'KIND_ALWAYS_DENIED',
  Conditional: 'KIND_CONDITIONAL',
});

const TRUE = Object.freeze({ t: 'const', v: true });
const FALSE = Object.freeze({ t: 'const', v: false });

function constNode(value) {
  return value ? TRUE : FALSE;
}

function exprNode(operand) {
  return { t: 'expr', e: operand };
}

function opaqueNode(src, reason) {
  return { t: 'opaque', src, reason };
}

function relationNode(name, relation) {
  return { t: 'relation', name, relation };
}

// Two opaque nodes are never provably the same condition (two distinct JS
// functions can render identical sources), so they are exempt from dedup.
function dedupKey(node) {
  if (node.t === 'opaque') return null;
  return JSON.stringify(node);
}

/**
 * Shared normalization for `and`/`or`. `absorbing` is the constant that
 * decides the whole node (`false` for and, `true` for or); the opposite
 * constant is the identity and is dropped. Flattening, dedup and the
 * constant checks all happen in the same single pass over the children.
 *
 * @param {'and' | 'or'} kind
 * @param {PlanNode[]} children
 * @param {boolean} absorbing
 * @returns {PlanNode}
 */
function logicalNode(kind, children, absorbing) {
  const flat = [];
  const seen = new Set();
  for (const child of children) {
    if (child.t === 'const') {
      if (child.v === absorbing) return constNode(absorbing);
      continue; // identity element
    }
    const nested = child.t === kind ? child.children : [child];
    for (const node of nested) {
      const key = dedupKey(node);
      if (key !== null) {
        if (seen.has(key)) continue;
        seen.add(key);
      }
      flat.push(node);
    }
  }
  if (!flat.length) return constNode(!absorbing);
  if (flat.length === 1) return flat[0];
  return { t: kind, children: flat };
}

function andNode(children) {
  return logicalNode('and', children, false);
}

function orNode(children) {
  return logicalNode('or', children, true);
}

function notNode(child) {
  if (child.t === 'const') return constNode(!child.v);
  if (child.t === 'not') return child.child;
  return { t: 'not', child };
}

function buildLogicalOperand(node) {
  const operands = new Array(node.children.length);
  for (let i = 0; i < node.children.length; i++) operands[i] = toOperand(node.children[i]);
  return { expression: { operator: node.t, operands } };
}

// O(1) node-kind dispatch for serialization into Cerbos operands.
const OPERAND_BUILDERS = createDispatch({
  const: (node) => ({ value: node.v }),
  expr: (node) => node.e,
  and: buildLogicalOperand,
  or: buildLogicalOperand,
  not: (node) => ({ expression: { operator: 'not', operands: [toOperand(node.child)] } }),
  opaque: (node) => ({
    expression: { operator: 'opaque', operands: [{ value: { src: node.src, reason: node.reason } }] },
  }),
  relation: (node) => ({
    expression: { operator: 'relation', operands: [{ value: { name: node.name, relation: node.relation } }] },
  }),
});

/**
 * Serializes a plan node into a Cerbos condition operand.
 *
 * @param {PlanNode} node
 * @returns {PlanOperand}
 */
function toOperand(node) {
  const build = OPERAND_BUILDERS[node.t];
  if (!build) throw new TypeError(`Unknown plan node: ${node.t}`);
  return build(node);
}

/**
 * Converts a normalized plan node into the response `filter`.
 *
 * @param {PlanNode} node
 * @returns {{ kind: string, condition?: PlanOperand }}
 */
function toFilter(node) {
  if (node.t === 'const') {
    return { kind: node.v ? PlanKind.AlwaysAllowed : PlanKind.AlwaysDenied };
  }
  return { kind: PlanKind.Conditional, condition: toOperand(node) };
}

function fromOperandList(operands) {
  const nodes = new Array(operands.length);
  for (let i = 0; i < operands.length; i++) nodes[i] = fromOperand(operands[i]);
  return nodes;
}

// O(1) operator dispatch for reconstruction; operators outside this table are
// opaque-to-us expression leaves kept verbatim.
const FROM_EXPRESSION_BUILDERS = createDispatch({
  and: (operands) => andNode(fromOperandList(operands)),
  or: (operands) => orNode(fromOperandList(operands)),
  not: (operands) => notNode(fromOperand(operands[0])),
  opaque: (operands) => {
    const detail = operands[0]?.value ?? {};
    return opaqueNode(detail.src, detail.reason);
  },
  relation: (operands) => {
    const detail = operands[0]?.value ?? {};
    return relationNode(detail.name, detail.relation);
  },
});

/**
 * Rebuilds a plan node from a Cerbos condition operand. Boolean positions
 * (children of and/or/not and the root) recurse; every other expression is an
 * opaque-to-us leaf kept verbatim. Reconstruction runs through the normalizing
 * constructors, so replacing a subtree and re-running `fromOperand` restores
 * normal form — this is what `expandRelationOperands` relies on.
 *
 * @param {PlanOperand} operand
 * @returns {PlanNode}
 */
function fromOperand(operand) {
  const expression = operand && typeof operand === 'object' ? operand.expression : undefined;
  if (!expression || typeof expression !== 'object') {
    if (operand && typeof operand === 'object' && typeof operand.value === 'boolean') {
      return constNode(operand.value);
    }
    return exprNode(operand);
  }
  const build = FROM_EXPRESSION_BUILDERS[expression.operator];
  return build ? build(expression.operands) : exprNode(operand);
}

function renderOperand(operand) {
  if (operand && typeof operand === 'object') {
    if ('variable' in operand) return String(operand.variable);
    if ('value' in operand) return JSON.stringify(operand.value);
    if (operand.expression && typeof operand.expression === 'object') {
      const { operator, operands } = operand.expression;
      let out = `(${operator}`;
      for (const child of operands) out += ` ${renderOperand(child)}`;
      return `${out})`;
    }
  }
  return JSON.stringify(operand);
}

/**
 * Human-readable s-expression rendering of a plan node (the `meta.filterDebug`
 * payload, mirroring Cerbos).
 *
 * @param {PlanNode} node
 * @returns {string}
 */
function toDebugString(node) {
  if (node.t === 'const') return String(node.v);
  return renderOperand(toOperand(node));
}

module.exports = {
  FALSE,
  PlanKind,
  TRUE,
  andNode,
  constNode,
  createDispatch,
  exprNode,
  fromOperand,
  notNode,
  opaqueNode,
  orNode,
  relationNode,
  toDebugString,
  toFilter,
  toOperand,
};
