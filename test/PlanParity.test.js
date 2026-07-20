const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { Effect, Kerberos, createSafeExprCodec, deserializePolicy } = require('../src/index.js');

const jsepModule = require('jsep');
const jsep = jsepModule.default || jsepModule;
jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));
jsep.addUnaryOp('typeof');

const codec = createSafeExprCodec({ jsep });

// ---------------------------------------------------------------------------
// Test-side interpreter for the Cerbos operand tree. Any operator outside the
// documented vocabulary (including `opaque` / `relation`) throws — drift in
// the planner output fails the suite loudly instead of passing vacuously.
// ---------------------------------------------------------------------------
const OPERATORS = {
  and: (operands) => operands.every(Boolean),
  or: (operands) => operands.some(Boolean),
  not: ([value]) => !value,
  eq: ([left, right]) => left === right,
  ne: ([left, right]) => left !== right,
  lt: ([left, right]) => left < right,
  le: ([left, right]) => left <= right,
  gt: ([left, right]) => left > right,
  ge: ([left, right]) => left >= right,
  add: ([left, right]) => left + right,
  sub: ([left, right]) => left - right,
  mult: ([left, right]) => left * right,
  div: ([left, right]) => left / right,
  mod: ([left, right]) => left % right,
  in: ([item, list]) => (Array.isArray(list) ? list.includes(item) : false),
  index: ([base, key]) => base?.[key],
  list: (operands) => operands,
};

function evalOperand(operand, row) {
  if ('value' in operand) return operand.value;
  if ('variable' in operand) {
    const path = operand.variable.split('.');
    assert.strictEqual(path[0], 'request');
    assert.strictEqual(path[1], 'resource');
    let current = row;
    for (let i = 2; i < path.length; i++) current = current?.[path[i]];
    return current;
  }
  const { operator, operands } = operand.expression;
  const handler = OPERATORS[operator];
  if (!handler) throw new Error(`Unexpected operator in plan: ${operator}`);
  return handler(operands.map((child) => evalOperand(child, row)));
}

function evalFilter(filter, row) {
  if (filter.kind === 'KIND_ALWAYS_ALLOWED') return true;
  if (filter.kind === 'KIND_ALWAYS_DENIED') return false;
  return Boolean(evalOperand(filter.condition, row));
}

// ---------------------------------------------------------------------------
// Fixture: an all-$expr policy suite exercising every layer.
// ---------------------------------------------------------------------------
const policies = [
  deserializePolicy(
    {
      resourcePolicy: {
        resource: 'document',
        version: 'default',
        importDerivedRoles: ['doc_roles'],
        constants: { minQty: 10 },
        variables: {
          isOpen: { $expr: "R.attr.status === 'OPEN'" },
        },
        rules: [
          { actions: ['view'], effect: Effect.Allow, roles: ['ADMIN'] },
          {
            actions: ['view', 'edit'],
            effect: Effect.Allow,
            derivedRoles: ['OWNER'],
            condition: { match: { all: [{ $expr: 'V.isOpen' }] } },
          },
          {
            actions: ['view'],
            effect: Effect.Allow,
            roles: ['USER'],
            condition: { match: { $expr: 'R.attr.public === true' } },
          },
          {
            actions: ['count'],
            effect: Effect.Allow,
            roles: ['USER'],
            condition: { match: { $expr: 'R.attr.qty > C.minQty && R.attr.qty % 2 === 0' } },
          },
          {
            actions: ['*'],
            effect: Effect.Deny,
            roles: ['*'],
            condition: { match: { $expr: 'R.attr.banned === true' } },
          },
        ],
      },
    },
    codec,
  ),
  deserializePolicy(
    {
      principalPolicy: {
        principal: 'boss',
        version: 'default',
        rules: [
          {
            resource: 'document',
            actions: [
              { action: 'view', effect: Effect.Allow, condition: { match: { $expr: 'R.attr.classified !== true' } } },
              { action: 'edit', effect: Effect.Deny },
            ],
          },
        ],
      },
    },
    codec,
  ),
  deserializePolicy(
    {
      rolePolicy: {
        role: 'CONTRACTOR',
        version: 'default',
        parentRoles: ['STAFF'],
        rules: [
          {
            resource: 'document',
            allowActions: ['view'],
            condition: { match: { $expr: 'R.attr.public === true' } },
          },
        ],
      },
    },
    codec,
  ),
  deserializePolicy(
    {
      rolePolicy: {
        role: 'STAFF',
        version: 'default',
        rules: [{ resource: 'document', allowActions: ['view', 'edit'] }],
      },
    },
    codec,
  ),
];

const derivedRoles = [
  deserializePolicy(
    {
      name: 'doc_roles',
      definitions: [
        { name: 'OWNER', parentRoles: ['USER'], condition: { match: { $expr: 'R.attr.ownerId === P.id' } } },
      ],
    },
    codec,
  ),
];

const principals = [
  { id: 'root', roles: ['ADMIN'] },
  { id: 'u1', roles: ['USER'] },
  { id: 'u2', roles: ['USER'] },
  { id: 'boss', roles: ['USER'] },
  { id: 'c1', roles: ['CONTRACTOR'] },
];

const actions = ['view', 'edit', 'count'];

// Sampled grid over the unknown attributes (64 rows).
const attrGrid = [];
for (const ownerId of ['u1', 'u2']) {
  for (const status of ['OPEN', 'CLOSED']) {
    for (const isPublic of [true, false]) {
      for (const banned of [true, false]) {
        for (const classified of [true, false]) {
          for (const qty of [5, 12]) {
            attrGrid.push({ ownerId, status, public: isPublic, banned, classified, qty });
          }
        }
      }
    }
  }
}

const kerberos = new Kerberos(policies, derivedRoles);

async function assertParity(principal, action, planArgs, rows) {
  const plan = await kerberos.planResources(planArgs);
  for (const attr of rows) {
    const row = { id: 'r1', attr };
    const planned = evalFilter(plan.filter, row);
    const actual = await kerberos.isAllowed({
      principal,
      resource: { id: 'r1', kind: 'document', attr },
      action,
    });
    assert.strictEqual(
      planned,
      actual,
      `drift for ${principal.id}/${action} on ${JSON.stringify(attr)}: plan=${planned} isAllowed=${actual}`,
    );
  }
}

describe('planResources ↔ isAllowed parity', () => {
  for (const principal of principals) {
    for (const action of actions) {
      it(`matches isAllowed for ${principal.id}/${action} across the attr grid`, async () => {
        await assertParity(principal, action, { principal, resource: { kind: 'document' }, action }, attrGrid);
      });
    }
  }

  it('keeps parity when some attributes are known at plan time', async () => {
    const known = { status: 'OPEN', banned: false };
    const rows = attrGrid.filter((attr) => attr.status === 'OPEN' && attr.banned === false);
    for (const principal of principals) {
      const plan = await kerberos.planResources({
        principal,
        resource: { kind: 'document', attr: known },
        action: 'view',
      });
      for (const attr of rows) {
        const planned = evalFilter(plan.filter, { id: 'r1', attr });
        const actual = await kerberos.isAllowed({
          principal,
          resource: { id: 'r1', kind: 'document', attr },
          action: 'view',
        });
        assert.strictEqual(planned, actual, `partial-known drift for ${principal.id} on ${JSON.stringify(attr)}`);
      }
    }
  });

  it('keeps parity for multi-action plans (AND of the per-action results)', async () => {
    for (const principal of principals) {
      const plan = await kerberos.planResources({
        principal,
        resource: { kind: 'document' },
        actions: ['view', 'edit'],
      });
      for (const attr of attrGrid) {
        const planned = evalFilter(plan.filter, { id: 'r1', attr });
        const view = await kerberos.isAllowed({
          principal,
          resource: { id: 'r1', kind: 'document', attr },
          action: 'view',
        });
        const edit = await kerberos.isAllowed({
          principal,
          resource: { id: 'r1', kind: 'document', attr },
          action: 'edit',
        });
        assert.strictEqual(planned, view && edit, `multi-action drift for ${principal.id} on ${JSON.stringify(attr)}`);
      }
    }
  });
});
