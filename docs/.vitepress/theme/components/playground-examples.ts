/**
 * Seed documents for the playground. Everything is JSON — conditions use the
 * `{ "$expr": "..." }` descriptor form rather than live functions, so each
 * example is also a valid *stored* policy, and the playground exercises the
 * same eval-free codec path a cache-backed deployment uses.
 */
type Example = {
  title: string;
  description: string;
  policies: string;
  derivedRoles: string;
  isAllowed?: string;
  checkResources?: string;
  planResources?: string;
};

const json = (value: unknown) => JSON.stringify(value, null, 2);

export const EXAMPLES = {
  quickstart: {
    title: 'RBAC + ABAC',
    description:
      'A document policy combining a static role (ADMIN), a derived role computed from the request (OWNER), a variable, a condition and an output. Try flipping d1’s status to CLOSED.',
    policies: json([
      {
        resourcePolicy: {
          version: 'default',
          resource: 'document',
          importDerivedRoles: ['doc_roles'],
          variables: { isOpen: { $expr: "R.attr.status == 'OPEN'" } },
          rules: [
            { name: 'admins-do-anything', actions: ['*'], effect: 'EFFECT_ALLOW', roles: ['ADMIN'] },
            { name: 'owner-can-view', actions: ['view'], effect: 'EFFECT_ALLOW', derivedRoles: ['OWNER'] },
            {
              name: 'owner-edits-while-open',
              actions: ['edit'],
              effect: 'EFFECT_ALLOW',
              derivedRoles: ['OWNER'],
              condition: { match: { $expr: 'V.isOpen' } },
              output: { when: { ruleActivated: { $expr: '({ owner: R.attr.ownerId, by: P.id })' } } },
            },
          ],
        },
      },
    ]),
    derivedRoles: json([
      {
        name: 'doc_roles',
        definitions: [
          { name: 'OWNER', parentRoles: ['USER'], condition: { match: { $expr: 'R.attr.ownerId == P.id' } } },
        ],
      },
    ]),
    isAllowed: json({
      principal: { id: 'u1', roles: ['USER'] },
      resource: { kind: 'document', id: 'd1', attr: { ownerId: 'u1', status: 'OPEN' } },
      action: 'edit',
    }),
    checkResources: json({
      principal: { id: 'u1', roles: ['USER'] },
      resources: [
        {
          resource: { kind: 'document', id: 'd1', attr: { ownerId: 'u1', status: 'OPEN' } },
          actions: ['view', 'edit'],
        },
        {
          resource: { kind: 'document', id: 'd2', attr: { ownerId: 'u2', status: 'OPEN' } },
          actions: ['view', 'edit'],
        },
      ],
      includeMeta: true,
    }),
  },

  queryPlan: {
    title: 'Query plan',
    description:
      'planResources answers “which rows may this principal see?” without any resource ids — the condition that could not be decided statically comes back as a filter tree you hand to your ORM.',
    policies: json([
      {
        resourcePolicy: {
          version: 'default',
          resource: 'expense',
          rules: [
            {
              actions: ['view'],
              effect: 'EFFECT_ALLOW',
              roles: ['USER'],
              condition: { match: { $expr: "R.attr.ownerId === P.id || R.attr.status === 'APPROVED'" } },
            },
            { actions: ['*'], effect: 'EFFECT_ALLOW', roles: ['ADMIN'] },
          ],
        },
      },
    ]),
    derivedRoles: json([]),
    planResources: json({
      principal: { id: 'u1', roles: ['USER'] },
      resource: { kind: 'expense' },
      action: 'view',
      includeMeta: true,
    }),
    isAllowed: json({
      principal: { id: 'u1', roles: ['USER'] },
      resource: { kind: 'expense', id: 'e1', attr: { ownerId: 'u2', status: 'APPROVED' } },
      action: 'view',
    }),
    checkResources: json({
      principal: { id: 'u1', roles: ['USER'] },
      resources: [
        { resource: { kind: 'expense', id: 'e1', attr: { ownerId: 'u1', status: 'OPEN' } }, actions: ['view'] },
        { resource: { kind: 'expense', id: 'e2', attr: { ownerId: 'u2', status: 'APPROVED' } }, actions: ['view'] },
        { resource: { kind: 'expense', id: 'e3', attr: { ownerId: 'u2', status: 'OPEN' } }, actions: ['view'] },
      ],
    }),
  },

  scopes: {
    title: 'Scopes',
    description:
      'Two policies for the same kind at different scopes. The request asks at `acme.eu`, which is not defined — the engine walks `acme.eu` → `acme` → base and stops at the first match. Change the request scope to `other` to fall through to the base policy instead.',
    policies: json([
      {
        resourcePolicy: {
          version: 'default',
          resource: 'invoice',
          rules: [{ actions: ['view', 'approve'], effect: 'EFFECT_ALLOW', roles: ['USER'] }],
        },
      },
      {
        resourcePolicy: {
          version: 'default',
          resource: 'invoice',
          scope: 'acme',
          rules: [
            { actions: ['view'], effect: 'EFFECT_ALLOW', roles: ['USER'] },
            { actions: ['approve'], effect: 'EFFECT_DENY', roles: ['USER'] },
          ],
        },
      },
    ]),
    derivedRoles: json([]),
    checkResources: json({
      principal: { id: 'u1', roles: ['USER'] },
      resources: [
        { resource: { kind: 'invoice', id: 'i1', scope: 'acme.eu' }, actions: ['view', 'approve'] },
        { resource: { kind: 'invoice', id: 'i2', scope: 'other' }, actions: ['view', 'approve'] },
      ],
      includeMeta: true,
    }),
    isAllowed: json({
      principal: { id: 'u1', roles: ['USER'] },
      resource: { kind: 'invoice', id: 'i1', scope: 'acme.eu' },
      action: 'approve',
    }),
  },
} satisfies Record<string, Example>;
