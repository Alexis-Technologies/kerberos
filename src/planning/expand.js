/**
 * ReBAC bridge for query plans: materializes `relation` operands.
 *
 * A plan built over relation-backed derived roles carries
 * `{ operator: 'relation', operands: [{ value: { name, relation } }] }`
 * placeholders — the ABAC filter is complete, but the ReBAC part depends on
 * relationship data the planner cannot see. This helper resolves each
 * placeholder through a caller-supplied lookup (typically wrapping
 * `RelationResolver.lookupResources` from `@alexify/kerberos/relations`, but
 * any resolver works) into `in(request.resource.id, [ids])`, then
 * re-normalizes the tree and recomputes `filter.kind` — an empty id list
 * folds the branch to FALSE, which can collapse the whole plan.
 */

const {
  andNode,
  constNode,
  createDispatch,
  exprNode,
  fromOperand,
  notNode,
  orNode,
  toDebugString,
  toFilter,
} = require('./nodes.js');

async function resolveRelationIds(lookup, node) {
  const ids = await lookup({ name: node.name, relation: node.relation });
  const list = [];
  // Any iterable of ids works (array, Set, generator); strings are scalars,
  // not id lists.
  if (ids !== null && ids !== undefined && typeof ids !== 'string' && typeof ids[Symbol.iterator] === 'function') {
    for (const id of ids) list.push(id);
  }
  return list;
}

async function expandLogical(node, expandOne) {
  const children = new Array(node.children.length);
  for (let i = 0; i < node.children.length; i++) children[i] = await expandNode(node.children[i], expandOne);
  return node.t === 'and' ? andNode(children) : orNode(children);
}

// O(1) node-kind dispatch; kinds outside the table (expr/opaque/const) hold no
// relation nodes and pass through untouched.
const NODE_EXPANDERS = createDispatch({
  and: expandLogical,
  or: expandLogical,
  not: async (node, expandOne) => notNode(await expandNode(node.child, expandOne)),
  relation: (node, expandOne) => expandOne(node),
});

/**
 * Walks a plan node and replaces every `relation` node with the looked-up
 * id-membership expression. Lookups run sequentially: plans hold few distinct
 * relations, and `expandOne` memoizes by `name|relation`.
 */
async function expandNode(node, expandOne) {
  const expander = NODE_EXPANDERS[node.t];
  return expander ? expander(node, expandOne) : node;
}

/**
 * Expands the `relation` operands of a planResources response.
 *
 * @param {{ filter: { kind: string, condition?: object }, meta?: { filterDebug?: string } }} planResponse
 * @param {(args: { name: string, relation: string }) => Promise<Iterable<string>> | Iterable<string>} lookup
 *   Resolves one relation-backed derived role to the ids of the resources the
 *   principal holds the relation on (array or Set; empty → no access).
 * @returns {Promise<object>} a new response object with a materialized filter
 */
async function expandRelationOperands(planResponse, lookup) {
  if (typeof lookup !== 'function') {
    throw new TypeError('expandRelationOperands requires a lookup({ name, relation }) function');
  }
  const { filter } = planResponse;
  if (!filter?.condition) return planResponse;

  const memo = new Map();
  const expandOne = async (node) => {
    const key = `${node.name}|${node.relation}`;
    if (!memo.has(key)) {
      const ids = await resolveRelationIds(lookup, node);
      const expanded = ids.length
        ? exprNode({
            expression: { operator: 'in', operands: [{ variable: 'request.resource.id' }, { value: ids }] },
          })
        : constNode(false);
      memo.set(key, expanded);
    }
    return memo.get(key);
  };

  const node = await expandNode(fromOperand(filter.condition), expandOne);
  const response = { ...planResponse, filter: toFilter(node) };
  if (planResponse.meta) response.meta = { ...planResponse.meta, filterDebug: toDebugString(node) };
  return response;
}

module.exports = { expandRelationOperands };
