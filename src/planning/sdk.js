/**
 * Bridge to the Cerbos JavaScript SDK plan shape, which the official Cerbos
 * ORM adapters (`@cerbos/orm-prisma`, `@cerbos/orm-drizzle`) consume.
 *
 * Kerberos's `planResources` emits the Cerbos **HTTP API** operand encoding —
 * `{ value }` / `{ variable }` / `{ expression: { operator, operands } }` —
 * which is what the conformance suite compares against a live PDP. The
 * `@cerbos/core` SDK (and therefore the adapters) uses a flattened encoding:
 * `{ value }` / `{ name }` / `{ operator, operands }`. The plan kinds are
 * byte-identical between the two. This converter is that one hop:
 *
 *   const plan = await kerberos.planResources({ ... });
 *   const { filters } = queryPlanToPrisma({ queryPlan: toCerbosQueryPlan(plan), mapper });
 *
 * Kerberos-only operators are REJECTED here, not guessed at: `relation`
 * operands must be materialized first (`expandRelationOperands`), and
 * `opaque` operands mean the condition is not statically plannable — the
 * caller must post-filter instead (see the query-plans guide).
 */

const { KerberosValidationError } = require('../errors.js');

function convertOperand(operand, path) {
  if (operand && typeof operand === 'object') {
    if ('value' in operand) return { value: operand.value };
    if ('variable' in operand) return { name: operand.variable };
    if (operand.expression && typeof operand.expression === 'object') {
      const { operator, operands } = operand.expression;
      if (operator === 'opaque' || operator === 'relation') {
        throw new KerberosValidationError(
          operator === 'relation'
            ? 'toCerbosQueryPlan: the plan contains a `relation` operand — materialize it with expandRelationOperands(plan, lookup) before handing the plan to a Cerbos ORM adapter'
            : `toCerbosQueryPlan: the plan contains an \`opaque\` operand (${path}) — the condition is not statically plannable, so translate the rest and post-filter (see the query-plans guide)`,
        );
      }
      if (typeof operator !== 'string' || !Array.isArray(operands)) {
        throw new KerberosValidationError(`toCerbosQueryPlan: malformed expression operand at ${path}`);
      }
      return {
        operator,
        operands: operands.map((child, i) => convertOperand(child, `${path}.operands[${i}]`)),
      };
    }
  }
  throw new KerberosValidationError(`toCerbosQueryPlan: unrecognized plan operand at ${path}`);
}

/**
 * Converts a Kerberos `planResources` response (or its `filter`) into the
 * `@cerbos/core`-SDK-shaped `{ kind, condition? }` object the official Cerbos
 * ORM adapters accept.
 *
 * @param {{ filter?: { kind: string, condition?: unknown }, kind?: string, condition?: unknown }} planOrFilter
 * @returns {{ kind: string, condition?: unknown }}
 */
function toCerbosQueryPlan(planOrFilter) {
  const filter =
    planOrFilter && typeof planOrFilter === 'object' && planOrFilter.filter ? planOrFilter.filter : planOrFilter;
  if (!filter || typeof filter !== 'object' || typeof filter.kind !== 'string') {
    throw new KerberosValidationError(
      'toCerbosQueryPlan expects a planResources response (or its `filter`) with a `kind`',
    );
  }
  if (filter.kind !== 'KIND_CONDITIONAL') return { kind: filter.kind };
  if (filter.condition === undefined) {
    throw new KerberosValidationError('toCerbosQueryPlan: a KIND_CONDITIONAL filter must carry a condition');
  }
  return { kind: filter.kind, condition: convertOperand(filter.condition, 'condition') };
}

module.exports = { toCerbosQueryPlan };
