const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const { Keyv } = require('keyv');
const { z } = require('zod');
const AjvModule = require('ajv');
const Ajv = AjvModule.default ?? AjvModule;
const { Type } = require('@sinclair/typebox');

const {
  Effect,
  Kerberos,
  KerberosValidationError,
  PlanKind,
  createSafeExprCodec,
  deserializePolicy,
  expandRelationOperands,
  serializePolicy,
} = require('../src/index.js');

const jsepModule = require('jsep');
const jsep = jsepModule.default || jsepModule;
jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));
jsep.addUnaryOp('typeof');

const codec = createSafeExprCodec({ jsep });

const user = { id: 'u1', roles: ['USER'] };
const docKind = { kind: 'document' };

// The runtime PlanKind enum members are the canonical Cerbos strings.
const ALLOWED = PlanKind.AlwaysAllowed;
const DENIED = PlanKind.AlwaysDenied;
const CONDITIONAL = PlanKind.Conditional;

function dynamicPolicy(shape) {
  return deserializePolicy(shape, codec);
}

async function planOf(kerberos, overrides = {}) {
  const args = { principal: user, resource: docKind, action: 'view', ...overrides };
  if (overrides.actions) delete args.action;
  return kerberos.planResources(args);
}

describe('planResources', () => {
  describe('resource layer', () => {
    it('returns ALWAYS_DENIED when no policy exists at all', async () => {
      const kerberos = new Kerberos([], []);
      const plan = await planOf(kerberos);
      assert.deepStrictEqual(plan.filter, { kind: DENIED });
      assert.strictEqual(plan.resourceKind, 'document');
      assert.strictEqual(plan.policyVersion, 'default');
      assert.strictEqual(plan.action, 'view');
      assert.ok(plan.kerberosCallId);
    });

    it('returns ALWAYS_ALLOWED for an unconditional allow rule', async () => {
      const kerberos = new Kerberos(
        [
          {
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
            },
          },
        ],
        [],
      );
      assert.deepStrictEqual((await planOf(kerberos)).filter, { kind: ALLOWED });
    });

    it('emits a residual condition for $expr rules and folds known attrs', async () => {
      const kerberos = new Kerberos(
        [
          dynamicPolicy({
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              rules: [
                {
                  actions: ['view'],
                  effect: Effect.Allow,
                  roles: ['USER'],
                  condition: { match: { $expr: "R.attr.status === 'OPEN'" } },
                },
              ],
            },
          }),
        ],
        [],
      );

      const plan = await planOf(kerberos);
      assert.strictEqual(plan.filter.kind, CONDITIONAL);
      assert.deepStrictEqual(plan.filter.condition, {
        expression: { operator: 'eq', operands: [{ variable: 'request.resource.attr.status' }, { value: 'OPEN' }] },
      });

      const known = await planOf(kerberos, { resource: { kind: 'document', attr: { status: 'OPEN' } } });
      assert.deepStrictEqual(known.filter, { kind: ALLOWED });
      const knownDenied = await planOf(kerberos, { resource: { kind: 'document', attr: { status: 'CLOSED' } } });
      assert.deepStrictEqual(knownDenied.filter, { kind: DENIED });
    });

    it('inverts deny rules and honors Deny-over-Allow', async () => {
      const kerberos = new Kerberos(
        [
          dynamicPolicy({
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              rules: [
                { actions: ['*'], effect: Effect.Allow, roles: ['USER'] },
                {
                  actions: ['view'],
                  effect: Effect.Deny,
                  roles: ['*'],
                  condition: { match: { $expr: "R.attr.status === 'ARCHIVED'" } },
                },
              ],
            },
          }),
        ],
        [],
      );
      const plan = await planOf(kerberos);
      assert.deepStrictEqual(plan.filter.condition, {
        expression: {
          operator: 'not',
          operands: [
            {
              expression: {
                operator: 'eq',
                operands: [{ variable: 'request.resource.attr.status' }, { value: 'ARCHIVED' }],
              },
            },
          ],
        },
      });
    });

    it('treats non-matching roles as ALWAYS_DENIED and wildcard roles as matching', async () => {
      const kerberos = new Kerberos(
        [
          {
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              rules: [
                { actions: ['view'], effect: Effect.Allow, roles: ['ADMIN'] },
                { actions: ['list'], effect: Effect.Allow, roles: ['*'] },
              ],
            },
          },
        ],
        [],
      );
      assert.deepStrictEqual((await planOf(kerberos)).filter, { kind: DENIED });
      assert.deepStrictEqual((await planOf(kerberos, { action: 'list' })).filter, { kind: ALLOWED });
    });

    it('marks JS-function conditions as opaque operands', async () => {
      const kerberos = new Kerberos(
        [
          {
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              rules: [
                {
                  actions: ['view'],
                  effect: Effect.Allow,
                  roles: ['USER'],
                  condition: { match: (req) => req.R.attr.ownerId === req.P.id },
                },
              ],
            },
          },
        ],
        [],
      );
      const plan = await planOf(kerberos);
      assert.strictEqual(plan.filter.kind, CONDITIONAL);
      assert.strictEqual(plan.filter.condition.expression.operator, 'opaque');
      assert.strictEqual(plan.filter.condition.expression.operands[0].value.reason, 'js-function');
    });
  });

  describe('principal layer', () => {
    const resourcePolicy = {
      resourcePolicy: {
        resource: 'document',
        version: 'default',
        rules: [{ actions: ['*'], effect: Effect.Allow, roles: ['USER'] }],
      },
    };

    it('unconditional principal ALLOW short-circuits to ALWAYS_ALLOWED', async () => {
      const kerberos = new Kerberos(
        [
          {
            principalPolicy: {
              principal: 'u1',
              version: 'default',
              rules: [{ resource: 'document', actions: [{ action: 'view', effect: Effect.Allow }] }],
            },
          },
        ],
        [],
      );
      assert.deepStrictEqual((await planOf(kerberos)).filter, { kind: ALLOWED });
    });

    it('unconditional principal DENY beats an unconditional resource ALLOW', async () => {
      const kerberos = new Kerberos(
        [
          resourcePolicy,
          {
            principalPolicy: {
              principal: 'u1',
              version: 'default',
              rules: [{ resource: '*', actions: [{ action: 'view', effect: Effect.Deny }] }],
            },
          },
        ],
        [],
      );
      assert.deepStrictEqual((await planOf(kerberos)).filter, { kind: DENIED });
    });

    it('a residual principal condition composes with the fallthrough layer', async () => {
      const kerberos = new Kerberos(
        [
          resourcePolicy,
          dynamicPolicy({
            principalPolicy: {
              principal: 'u1',
              version: 'default',
              rules: [
                {
                  resource: 'document',
                  actions: [
                    {
                      action: 'view',
                      effect: Effect.Deny,
                      condition: { match: { $expr: 'R.attr.classified === true' } },
                    },
                  ],
                },
              ],
            },
          }),
        ],
        [],
      );
      // deny wins where classified; resource allows otherwise:
      // OR(AND(FALSE, ...), AND(NOT(FALSE), NOT(classified), TRUE)) → not(classified)
      const plan = await planOf(kerberos);
      assert.deepStrictEqual(plan.filter.condition, {
        expression: {
          operator: 'not',
          operands: [
            {
              expression: {
                operator: 'eq',
                operands: [{ variable: 'request.resource.attr.classified' }, { value: true }],
              },
            },
          ],
        },
      });
    });

    it('does not consult the principal policy of another principal', async () => {
      const kerberos = new Kerberos(
        [
          resourcePolicy,
          {
            principalPolicy: {
              principal: 'u2',
              version: 'default',
              rules: [{ resource: '*', actions: [{ action: '*', effect: Effect.Deny }] }],
            },
          },
        ],
        [],
      );
      assert.deepStrictEqual((await planOf(kerberos)).filter, { kind: ALLOWED });
    });
  });

  describe('role layer', () => {
    it('applies allowlist semantics with implicit deny', async () => {
      const kerberos = new Kerberos(
        [
          {
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              rules: [{ actions: ['*'], effect: Effect.Allow, roles: ['*'] }],
            },
          },
          {
            rolePolicy: { role: 'USER', version: 'default', rules: [{ resource: 'document', allowActions: ['view'] }] },
          },
        ],
        [],
      );
      // Allowlisted action → allowed; unlisted action → implicit deny even
      // though the resource policy would allow it.
      assert.deepStrictEqual((await planOf(kerberos)).filter, { kind: ALLOWED });
      assert.deepStrictEqual((await planOf(kerberos, { action: 'delete' })).filter, { kind: DENIED });
    });

    it('keeps role rule conditions residual', async () => {
      const kerberos = new Kerberos(
        [
          dynamicPolicy({
            rolePolicy: {
              role: 'USER',
              version: 'default',
              rules: [
                {
                  resource: 'document',
                  allowActions: ['view'],
                  condition: { match: { $expr: 'R.attr.public === true' } },
                },
              ],
            },
          }),
        ],
        [],
      );
      const plan = await planOf(kerberos);
      assert.deepStrictEqual(plan.filter.condition, {
        expression: { operator: 'eq', operands: [{ variable: 'request.resource.attr.public' }, { value: true }] },
      });
    });

    it('lets deny win across multiple role policies', async () => {
      const kerberos = new Kerberos(
        [
          {
            rolePolicy: { role: 'USER', version: 'default', rules: [{ resource: 'document', allowActions: ['view'] }] },
          },
          {
            rolePolicy: {
              role: 'AUDITOR',
              version: 'default',
              rules: [{ resource: 'document', allowActions: ['audit'] }],
            },
          },
        ],
        [],
      );
      // AUDITOR matches the resource but does not allowlist 'view' → Deny
      // wins over USER's Allow.
      const plan = await planOf(kerberos, { principal: { id: 'u1', roles: ['USER', 'AUDITOR'] } });
      assert.deepStrictEqual(plan.filter, { kind: DENIED });
    });

    it('intersects child allows with parent role policies', async () => {
      const child = {
        rolePolicy: {
          role: 'EDITOR',
          version: 'default',
          parentRoles: ['READER'],
          rules: [{ resource: 'document', allowActions: ['view', 'edit'] }],
        },
      };
      const parent = {
        rolePolicy: { role: 'READER', version: 'default', rules: [{ resource: 'document', allowActions: ['view'] }] },
      };
      const kerberos = new Kerberos([child, parent], []);
      const editor = { id: 'u1', roles: ['EDITOR'] };

      assert.deepStrictEqual((await planOf(kerberos, { principal: editor })).filter, { kind: ALLOWED });
      // 'edit' is allowlisted by the child but not by the parent → denied.
      assert.deepStrictEqual((await planOf(kerberos, { principal: editor, action: 'edit' })).filter, { kind: DENIED });
    });

    it('denies when a parent role policy never targets the resource', async () => {
      const kerberos = new Kerberos(
        [
          {
            rolePolicy: {
              role: 'EDITOR',
              version: 'default',
              parentRoles: ['READER'],
              rules: [{ resource: 'document', allowActions: ['view'] }],
            },
          },
          {
            rolePolicy: {
              role: 'READER',
              version: 'default',
              rules: [{ resource: 'invoice', allowActions: ['view'] }],
            },
          },
        ],
        [],
      );
      const plan = await planOf(kerberos, { principal: { id: 'u1', roles: ['EDITOR'] } });
      assert.deepStrictEqual(plan.filter, { kind: DENIED });
    });

    it('throws on circular role policy inheritance (runtime parity)', async () => {
      const kerberos = new Kerberos(
        [
          {
            rolePolicy: {
              role: 'A',
              version: 'default',
              parentRoles: ['B'],
              rules: [{ resource: 'document', allowActions: ['view'] }],
            },
          },
          {
            rolePolicy: {
              role: 'B',
              version: 'default',
              parentRoles: ['A'],
              rules: [{ resource: 'document', allowActions: ['view'] }],
            },
          },
        ],
        [],
      );
      await assert.rejects(
        planOf(kerberos, { principal: { id: 'u1', roles: ['A'] } }),
        /Circular role policy inheritance/,
      );
    });
  });

  describe('derived roles', () => {
    it('inlines condition-backed definitions gated by parentRoles', async () => {
      const kerberos = new Kerberos(
        [
          dynamicPolicy({
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              importDerivedRoles: ['doc_roles'],
              rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['OWNER'] }],
            },
          }),
        ],
        [
          dynamicPolicy({
            name: 'doc_roles',
            definitions: [
              { name: 'OWNER', parentRoles: ['USER'], condition: { match: { $expr: 'R.attr.ownerId === P.id' } } },
            ],
          }),
        ],
      );

      const plan = await planOf(kerberos);
      assert.deepStrictEqual(plan.filter.condition, {
        expression: { operator: 'eq', operands: [{ variable: 'request.resource.attr.ownerId' }, { value: 'u1' }] },
      });
      // parentRoles gate is a plan-time constant: a guest can never be OWNER.
      const guest = await planOf(kerberos, { principal: { id: 'u1', roles: ['GUEST'] } });
      assert.deepStrictEqual(guest.filter, { kind: DENIED });
    });

    it('emits relation operands for relation-backed definitions', async () => {
      const kerberos = new Kerberos(
        [
          {
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              importDerivedRoles: ['doc_roles'],
              rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['VIEWER'] }],
            },
          },
        ],
        [{ name: 'doc_roles', definitions: [{ name: 'VIEWER', relation: 'viewer' }] }],
        { relations: { check: async () => true } },
      );
      const plan = await planOf(kerberos);
      assert.deepStrictEqual(plan.filter.condition, {
        expression: { operator: 'relation', operands: [{ value: { name: 'VIEWER', relation: 'viewer' } }] },
      });
    });

    it('folds relation-backed definitions to DENIED without a resolver and traces why', async () => {
      const kerberos = new Kerberos(
        [
          {
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              importDerivedRoles: ['doc_roles'],
              rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['VIEWER'] }],
            },
          },
        ],
        [{ name: 'doc_roles', definitions: [{ name: 'VIEWER', relation: 'viewer' }] }],
      );
      const plan = await planOf(kerberos, { includeMeta: true });
      assert.deepStrictEqual(plan.filter, { kind: DENIED });
      const entry = plan.meta.resolution.find((item) => item.source === 'relations');
      assert.deepStrictEqual(entry, {
        source: 'relations',
        name: 'VIEWER',
        relation: 'viewer',
        matched: false,
        reason: 'no-relations-resolver',
      });
    });

    it('expandRelationOperands materializes relation nodes via the lookup', async () => {
      const kerberos = new Kerberos(
        [
          {
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              importDerivedRoles: ['doc_roles'],
              rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['VIEWER'] }],
            },
          },
        ],
        [{ name: 'doc_roles', definitions: [{ name: 'VIEWER', relation: 'viewer' }] }],
        { relations: { check: async () => true } },
      );
      const plan = await kerberos.planResources({
        principal: user,
        resource: docKind,
        action: 'view',
        includeMeta: true,
      });

      const calls = [];
      const expanded = await expandRelationOperands(plan, async (args) => {
        calls.push(args);
        return new Set(['d1', 'd2']);
      });
      assert.deepStrictEqual(calls, [{ name: 'VIEWER', relation: 'viewer' }]);
      assert.deepStrictEqual(expanded.filter.condition, {
        expression: { operator: 'in', operands: [{ variable: 'request.resource.id' }, { value: ['d1', 'd2'] }] },
      });
      assert.strictEqual(expanded.meta.filterDebug, '(in request.resource.id ["d1","d2"])');
      // Original response is untouched.
      assert.strictEqual(plan.filter.condition.expression.operator, 'relation');

      const empty = await expandRelationOperands(plan, async () => []);
      assert.deepStrictEqual(empty.filter, { kind: DENIED });

      // Plans without a condition pass through unchanged.
      const denied = await planOf(new Kerberos([], []), {});
      assert.strictEqual(await expandRelationOperands(denied, async () => []), denied);
      await assert.rejects(expandRelationOperands(plan, null), TypeError);
    });
  });

  describe('scopes, versions and cache-backed policies', () => {
    it('resolves the most specific scoped policy (first-match-wins)', async () => {
      const kerberos = new Kerberos(
        [
          {
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
            },
          },
          {
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              scope: 'acme',
              rules: [{ actions: ['view'], effect: Effect.Deny, roles: ['*'] }],
            },
          },
        ],
        [],
      );
      const base = await planOf(kerberos, { includeMeta: true });
      assert.deepStrictEqual(base.filter, { kind: ALLOWED });
      assert.strictEqual(base.meta.matchedScopes.resource, '');

      const scoped = await planOf(kerberos, { resource: { kind: 'document', scope: 'acme.team' }, includeMeta: true });
      assert.deepStrictEqual(scoped.filter, { kind: DENIED });
      assert.strictEqual(scoped.meta.matchedScopes.resource, 'acme');
      const lookup = scoped.meta.resolution.find((entry) => entry.source === 'resource');
      assert.deepStrictEqual(lookup.scopesSearched, ['acme.team', 'acme', '']);
      assert.strictEqual(lookup.matchedScope, 'acme');
    });

    it('honors policyVersion and echoes it in the response', async () => {
      const kerberos = new Kerberos(
        [
          {
            resourcePolicy: {
              resource: 'document',
              version: 'v2',
              rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
            },
          },
        ],
        [],
      );
      assert.deepStrictEqual((await planOf(kerberos)).filter, { kind: DENIED });
      const versioned = await planOf(kerberos, { resource: { kind: 'document', policyVersion: 'v2' } });
      assert.deepStrictEqual(versioned.filter, { kind: ALLOWED });
      assert.strictEqual(versioned.policyVersion, 'v2');
    });

    it('plans cache-backed $expr policies (origin: cache in the trace)', async () => {
      const keyv = new Keyv();
      await keyv.set(
        'resource:document:default:',
        serializePolicy(
          {
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              importDerivedRoles: ['doc_roles'],
              rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['OWNER'] }],
            },
          },
          { jsep },
        ),
      );
      await keyv.set(
        'derivedRoles:doc_roles',
        serializePolicy(
          {
            name: 'doc_roles',
            definitions: [
              { name: 'OWNER', parentRoles: ['USER'], condition: { match: { $expr: 'R.attr.ownerId === P.id' } } },
            ],
          },
          { jsep },
        ),
      );

      const kerberos = new Kerberos([], [], { cache: keyv, codec: { jsep } });
      const plan = await planOf(kerberos, { includeMeta: true });
      assert.deepStrictEqual(plan.filter.condition, {
        expression: { operator: 'eq', operands: [{ variable: 'request.resource.attr.ownerId' }, { value: 'u1' }] },
      });
      const lookup = plan.meta.resolution.find((entry) => entry.source === 'resource');
      assert.strictEqual(lookup.origin, 'cache');
    });
  });

  describe('multiple actions (AND semantics)', () => {
    it('plans the conjunction of the per-action plans', async () => {
      const kerberos = new Kerberos(
        [
          dynamicPolicy({
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              rules: [
                { actions: ['view'], effect: Effect.Allow, roles: ['USER'] },
                {
                  actions: ['edit'],
                  effect: Effect.Allow,
                  roles: ['USER'],
                  condition: { match: { $expr: 'R.attr.ownerId === P.id' } },
                },
              ],
            },
          }),
        ],
        [],
      );
      const plan = await planOf(kerberos, { actions: ['view', 'edit'] });
      assert.deepStrictEqual(plan.actions, ['view', 'edit']);
      assert.strictEqual(plan.action, undefined);
      // view is unconditionally allowed → the conjunction reduces to edit's condition.
      assert.deepStrictEqual(plan.filter.condition, {
        expression: { operator: 'eq', operands: [{ variable: 'request.resource.attr.ownerId' }, { value: 'u1' }] },
      });

      const denied = await planOf(kerberos, { actions: ['view', 'delete'] });
      assert.deepStrictEqual(denied.filter, { kind: DENIED });
    });
  });

  describe('argument validation', () => {
    const kerberos = new Kerberos([], []);

    it('requires exactly one of action / actions', async () => {
      await assert.rejects(kerberos.planResources({ principal: user, resource: docKind }), KerberosValidationError);
      await assert.rejects(
        kerberos.planResources({ principal: user, resource: docKind, action: 'view', actions: ['view'] }),
        KerberosValidationError,
      );
      await assert.rejects(
        kerberos.planResources({ principal: user, resource: docKind, actions: [] }),
        KerberosValidationError,
      );
      await assert.rejects(
        kerberos.planResources({ principal: user, resource: docKind, actions: [42] }),
        KerberosValidationError,
      );
    });

    it('rejects the wildcard action', async () => {
      await assert.rejects(
        kerberos.planResources({ principal: user, resource: docKind, action: '*' }),
        /wildcard action/,
      );
    });

    it('validates argument shapes across the three backends', async () => {
      const ajv = () => new Ajv({ allowUnionTypes: true });
      const backends = [
        new Kerberos([], [], { z }),
        new Kerberos([], [], { ajv: ajv(), typebox: Type }),
        new Kerberos([], [], { ajv: ajv() }),
      ];
      for (const instance of backends) {
        const plan = await instance.planResources({ principal: user, resource: docKind, action: 'view' });
        assert.deepStrictEqual(plan.filter, { kind: DENIED });
        // Plan resources take no `id`; a malformed principal must throw.
        await assert.rejects(
          instance.planResources({ principal: { id: 'u1', roles: [] }, resource: docKind, action: 'view' }),
          KerberosValidationError,
        );
        await assert.rejects(
          instance.planResources({ principal: user, resource: {}, action: 'view' }),
          KerberosValidationError,
        );
      }
    });
  });

  describe('error semantics and observability', () => {
    const badPolicy = () =>
      dynamicPolicy({
        resourcePolicy: {
          resource: 'document',
          version: 'default',
          rules: [
            {
              actions: ['view'],
              effect: Effect.Allow,
              roles: ['USER'],
              condition: { match: { $expr: 'R.attr.obj.x === 1' } },
            },
          ],
        },
      });
    const badResource = { kind: 'document', attr: { obj: null } };

    it('propagates evaluation errors by default (onError: throw)', async () => {
      const kerberos = new Kerberos([badPolicy()], []);
      await assert.rejects(planOf(kerberos, { resource: badResource }), TypeError);
    });

    it('fails closed with onError: deny', async () => {
      const kerberos = new Kerberos([badPolicy()], [], { onError: 'deny' });
      const plan = await planOf(kerberos, { resource: badResource, reqId: 'req-9' });
      assert.deepStrictEqual(plan.filter, { kind: DENIED });
      assert.strictEqual(plan.reqId, 'req-9');
      assert.strictEqual(plan.action, 'view');
      assert.strictEqual(plan.resourceKind, 'document');
      assert.ok(plan.kerberosCallId);
    });

    it('always rethrows validation errors even with onError: deny', async () => {
      const kerberos = new Kerberos([], [], { onError: 'deny' });
      await assert.rejects(kerberos.planResources({ principal: user, resource: docKind }), KerberosValidationError);
    });

    it('emits PlanResources start/finish audit events to a structured logger', async () => {
      const entries = [];
      const logger = {
        info: (entry) => entries.push(entry),
        debug: (entry) => entries.push(entry),
        error: (entry) => entries.push(entry),
      };
      const kerberos = new Kerberos([], [], { logger });
      await planOf(kerberos, { reqId: 'req-1' });
      const events = entries.map((entry) => entry.event);
      assert.ok(events.includes('PlanResources.start'));
      assert.ok(events.includes('PlanResources.finish'));
      const start = entries.find((entry) => entry.event === 'PlanResources.start');
      assert.strictEqual(start.reqId, 'req-1');
      assert.ok(start.callId);
    });
  });

  describe('includeMeta', () => {
    it('returns filterDebug, matchedScopes and the resolution trace', async () => {
      const kerberos = new Kerberos(
        [
          dynamicPolicy({
            resourcePolicy: {
              resource: 'document',
              version: 'default',
              rules: [
                {
                  actions: ['view'],
                  effect: Effect.Allow,
                  roles: ['USER'],
                  condition: { match: { $expr: 'R.attr.qty > 5' } },
                },
              ],
            },
          }),
          {
            rolePolicy: {
              role: 'AUDITOR',
              version: 'default',
              rules: [{ resource: 'invoice', allowActions: ['audit'] }],
            },
          },
        ],
        [],
      );
      const plan = await planOf(kerberos, { principal: { id: 'u1', roles: ['USER', 'AUDITOR'] }, includeMeta: true });
      assert.strictEqual(plan.meta.filterDebug, '(gt request.resource.attr.qty 5)');
      assert.deepStrictEqual(plan.meta.matchedScopes, {
        principal: null,
        resource: '',
        roles: { USER: null, AUDITOR: '' },
      });
      const sources = plan.meta.resolution.map((entry) => entry.source);
      assert.ok(sources.includes('principal'));
      assert.ok(sources.includes('role'));
      assert.ok(sources.includes('resource'));
    });

    it('omits meta without includeMeta', async () => {
      const kerberos = new Kerberos([], []);
      assert.strictEqual((await planOf(kerberos)).meta, undefined);
    });
  });
});
