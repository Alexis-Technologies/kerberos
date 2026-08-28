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

// The wire contract: parity must hold for the filter AS TRANSPORTED, not just
// the in-memory object — JSON round-tripping catches operands that would
// silently corrupt (undefined → {}, NaN/Infinity → null, Date → ISO string).
function wireFilter(plan) {
  return JSON.parse(JSON.stringify(plan.filter));
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
          // Role-SCOPED deny. Conflict resolution is per principal role, so
          // this must not veto an allow carried by a different role the
          // principal also holds — unlike the wildcard deny above.
          {
            actions: ['view'],
            effect: Effect.Deny,
            roles: ['AUDITOR'],
            condition: { match: { $expr: 'R.attr.classified === true' } },
          },
          // Deny reached through a derived role, which collapses into the
          // principal role that activated it (AUDITOR here, via parentRoles).
          {
            actions: ['edit'],
            effect: Effect.Deny,
            derivedRoles: ['REVIEWER'],
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
  // Scoped policy: the per-(action, role) walk must fall through a failed
  // condition to the base policy, and a scoped deny must seal its role.
  deserializePolicy(
    {
      resourcePolicy: {
        resource: 'document',
        version: 'default',
        scope: 'acme',
        rules: [
          { actions: ['edit'], effect: Effect.Deny, roles: ['USER'] },
          {
            actions: ['view'],
            effect: Effect.Allow,
            roles: ['AUDITOR'],
            condition: { match: { $expr: 'R.attr.public === true' } },
          },
          // Glob rule: matches `count` via a mid-segment wildcard.
          { actions: ['c*t'], effect: Effect.Allow, roles: ['ADMIN'] },
        ],
      },
    },
    codec,
  ),
  // Scoped role policy at the RESOURCE scope: narrows CONTRACTOR to view-only
  // at acme while the base policy also allowlists nothing else there.
  deserializePolicy(
    {
      rolePolicy: {
        role: 'CONTRACTOR',
        version: 'default',
        scope: 'acme',
        rules: [{ resource: 'document', allowActions: ['view'] }],
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
        { name: 'REVIEWER', parentRoles: ['AUDITOR'], condition: { match: { $expr: 'R.attr.status === "OPEN"' } } },
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
  // Multi-role principals: the shape that exercises cross-role conflict
  // resolution. Without these the grid only ever fills one role bucket, and a
  // planner that still used plain deny-overrides would pass unnoticed.
  { id: 'u1', roles: ['USER', 'AUDITOR'] },
  { id: 'm2', roles: ['AUDITOR'] },
  { id: 'm3', roles: ['USER', 'ADMIN'] },
  // Role-layer shapes. `c2` mixes a role that HAS a role policy with one that
  // does not (the layer must abstain entirely); `c3` holds two policied roles
  // (the layer must union them). Neither is observable with a single-role
  // principal, which is how the intersection semantics went unnoticed.
  { id: 'c2', roles: ['CONTRACTOR', 'USER'] },
  { id: 'c3', roles: ['CONTRACTOR', 'STAFF'] },
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
  const filter = wireFilter(plan);
  for (const attr of rows) {
    const row = { id: 'r1', attr };
    const planned = evalFilter(filter, row);
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

  // The scope walk is per (action, role) with condition fall-through — the
  // planner folds it symbolically, and this sweep pins the two against each
  // other for scoped requests (which no other plan test exercises).
  for (const principal of principals) {
    for (const action of actions) {
      it(`matches isAllowed for ${principal.id}/${action} at scope acme`, async () => {
        const plan = await kerberos.planResources({
          principal,
          resource: { kind: 'document', scope: 'acme' },
          action,
        });
        const filter = wireFilter(plan);
        for (const attr of attrGrid) {
          const planned = evalFilter(filter, { id: 'r1', attr });
          const actual = await kerberos.isAllowed({
            principal,
            resource: { id: 'r1', kind: 'document', scope: 'acme', attr },
            action,
          });
          assert.strictEqual(
            planned,
            actual,
            `scoped drift for ${principal.id}/${action} on ${JSON.stringify(attr)}: plan=${planned} isAllowed=${actual}`,
          );
        }
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
      const filter = wireFilter(plan);
      for (const attr of rows) {
        const planned = evalFilter(filter, { id: 'r1', attr });
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
      const filter = wireFilter(plan);
      for (const attr of attrGrid) {
        const planned = evalFilter(filter, { id: 'r1', attr });
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
