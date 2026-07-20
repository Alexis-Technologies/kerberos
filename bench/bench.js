/**
 * Zero-dependency ops/sec benchmark for the Kerberos hot paths.
 *
 * Run: pnpm bench (or: node bench/bench.js)
 *
 * Results are recorded in the README "Benchmarks" section — update it when a
 * change moves the numbers. jsep (devDependency) is only needed for the
 * cache-backed scenario.
 */
const { performance } = require('node:perf_hooks');
const { Kerberos, Effect } = require('../src/index.js');

const WARMUP_ITERATIONS = 2_000;
const MEASURE_MS = 1_000;

async function bench(name, fn) {
  for (let i = 0; i < WARMUP_ITERATIONS; i++) await fn();

  let iterations = 0;
  const start = performance.now();
  while (performance.now() - start < MEASURE_MS) {
    await fn();
    iterations += 1;
  }
  const elapsed = performance.now() - start;
  const opsPerSec = Math.round((iterations / elapsed) * 1000);
  console.log(`${name.padEnd(52)} ${opsPerSec.toLocaleString('en-US').padStart(12)} ops/sec`);
  return { name, opsPerSec };
}

const principal = { id: 'sally', roles: ['USER'], attr: { department: 'SALES' } };
const resource = { id: 'expense1', kind: 'expense', attr: { ownerId: 'sally', status: 'OPEN', amount: 500 } };

const simplePolicies = [
  {
    resourcePolicy: {
      version: 'default',
      resource: 'expense',
      rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
    },
  },
];

const richPolicies = [
  {
    resourcePolicy: {
      version: 'default',
      resource: 'expense',
      importDerivedRoles: ['bench_roles'],
      variables: {
        isOpen: ({ R }) => R.attr.status === 'OPEN',
        isSmall: ({ R }) => R.attr.amount < 1000,
      },
      rules: [
        { actions: ['view'], effect: Effect.Allow, roles: ['USER'] },
        {
          actions: ['edit'],
          effect: Effect.Allow,
          derivedRoles: ['OWNER'],
          condition: { match: ({ V }) => V.isOpen && V.isSmall },
        },
        { actions: ['approve'], effect: Effect.Deny, roles: ['USER'] },
      ],
    },
  },
];

const benchDerivedRoles = {
  name: 'bench_roles',
  definitions: [{ name: 'OWNER', parentRoles: ['USER'], condition: { match: ({ P, R }) => R.attr.ownerId === P.id } }],
};

function buildManyResources(count) {
  const resources = [];
  for (let i = 0; i < count; i++) {
    resources.push({
      resource: { id: `expense${i}`, kind: 'expense', attr: { ownerId: 'sally', status: 'OPEN', amount: 500 } },
      actions: ['view', 'edit', 'approve'],
    });
  }
  return resources;
}

async function main() {
  console.log(`Node ${process.version} | ${new Date().toISOString()}\n`);
  const results = [];

  const simple = new Kerberos(simplePolicies, []);
  results.push(
    await bench('isAllowed — simple role match', () => simple.isAllowed({ principal, action: 'view', resource })),
  );

  const rich = new Kerberos(richPolicies, [benchDerivedRoles]);
  results.push(
    await bench('isAllowed — derived roles + variables + condition', () =>
      rich.isAllowed({ principal, action: 'edit', resource })),
  );

  const manyResources = buildManyResources(10);
  results.push(
    await bench('checkResources — 10 resources × 3 actions', () =>
      rich.checkResources({ principal, resources: manyResources })),
  );

  // Cache-backed scenario: dynamic $expr policy resolved through a Map cache.
  let jsep;
  try {
    const jsepModule = require('jsep');
    jsep = jsepModule.default || jsepModule;
    jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));
  } catch {
    console.log('\n(jsep not installed — skipping the cache-backed scenario)');
  }

  if (jsep) {
    const store = new Map([
      [
        'resource:document:default:',
        {
          resourcePolicy: {
            version: 'default',
            resource: 'document',
            rules: [
              {
                actions: ['view'],
                effect: 'EFFECT_ALLOW',
                roles: ['USER'],
                condition: { match: { $expr: "R.attr.status == 'OPEN'" } },
              },
            ],
          },
        },
      ],
    ]);
    const cached = new Kerberos([], [], { cache: store, codec: { jsep } });
    const docResource = { id: 'doc1', kind: 'document', attr: { status: 'OPEN' } };
    results.push(
      await bench('isAllowed — cache-backed dynamic policy ($expr)', () =>
        cached.isAllowed({ principal, action: 'view', resource: docResource })),
    );

    // Query planning: partial evaluation of a rich $expr policy (variables +
    // constants + allow/deny rules) into a Cerbos-shaped filter.
    const { createSafeExprCodec, deserializePolicy } = require('../src/index.js');
    const codec = createSafeExprCodec({ jsep });
    const plannable = new Kerberos(
      [
        deserializePolicy(
          {
            resourcePolicy: {
              version: 'default',
              resource: 'document',
              constants: { minQty: 10 },
              variables: { isOwner: { $expr: 'R.attr.ownerId === P.id' } },
              rules: [
                {
                  actions: ['view'],
                  effect: 'EFFECT_ALLOW',
                  roles: ['USER'],
                  condition: { match: { all: [{ $expr: 'V.isOwner' }, { $expr: 'R.attr.qty > C.minQty' }] } },
                },
                {
                  actions: ['*'],
                  effect: 'EFFECT_DENY',
                  roles: ['*'],
                  condition: { match: { $expr: "R.attr.status === 'ARCHIVED'" } },
                },
              ],
            },
          },
          codec,
        ),
      ],
      [],
    );
    results.push(
      await bench('planResources — $expr policy (variables + deny rule)', () =>
        plannable.planResources({ principal, resource: { kind: 'document' }, action: 'view' })),
    );
  }

  // ReBAC scenarios: the built-in Zanzibar-lite resolver over static tuples.
  const { RelationResolver } = require('../src/Relations/index.js');
  const relationSchema = {
    relationSchema: {
      definitions: {
        user: {},
        group: { relations: { member: ['user', 'group#member'] } },
        folder: {
          relations: { parent: ['folder'], viewer: ['user', 'group#member'] },
          permissions: { view: { anyOf: ['viewer', { via: 'parent', permission: 'view' }] } },
        },
        document: {
          relations: { parent: ['folder'], owner: ['user'], viewer: ['user', 'group#member'] },
          permissions: {
            edit: { anyOf: ['owner'] },
            view: { anyOf: ['edit', 'viewer', { via: 'parent', permission: 'view' }] },
          },
        },
      },
    },
  };
  const relationTuples = [
    'document:doc1#owner@user:sally',
    'document:doc1#parent@folder:f3',
    'folder:f3#parent@folder:f2',
    'folder:f2#parent@folder:f1',
    'folder:f1#viewer@group:eng#member',
    'group:eng#member@group:leads#member',
    'group:leads#member@user:deep',
  ];
  const relations = new RelationResolver({ schema: relationSchema, tuples: relationTuples });

  results.push(
    await bench('relations.check — direct tuple (flat)', () =>
      relations.check({ resource: 'document:doc1', permission: 'edit', subject: 'user:sally' })),
  );
  results.push(
    await bench('relations.check — deep walk (3 arrows + nested groups)', () =>
      relations.check({ resource: 'document:doc1', permission: 'view', subject: 'user:deep' })),
  );

  const relationDerivedRoles = {
    name: 'doc_roles',
    definitions: [{ name: 'DOC_VIEWER', relation: 'view' }],
  };
  const relationPolicy = {
    resourcePolicy: {
      version: 'default',
      resource: 'document',
      importDerivedRoles: ['doc_roles'],
      rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['DOC_VIEWER'] }],
    },
  };
  const rebacKerberos = new Kerberos([relationPolicy], [relationDerivedRoles], { relations });
  results.push(
    await bench('isAllowed — relation-backed derived role (deep walk)', () =>
      rebacKerberos.isAllowed({
        principal: { id: 'deep', roles: ['USER'] },
        action: 'view',
        resource: { id: 'doc1', kind: 'document' },
      })),
  );

  return results;
}

main();
