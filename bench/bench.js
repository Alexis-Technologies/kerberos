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
  results.push(await bench('isAllowed — simple role match', () => simple.isAllowed({ principal, action: 'view', resource })));

  const rich = new Kerberos(richPolicies, [benchDerivedRoles]);
  results.push(
    await bench('isAllowed — derived roles + variables + condition', () =>
      rich.isAllowed({ principal, action: 'edit', resource }),
    ),
  );

  const manyResources = buildManyResources(10);
  results.push(
    await bench('checkResources — 10 resources × 3 actions', () =>
      rich.checkResources({ principal, resources: manyResources }),
    ),
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
        cached.isAllowed({ principal, action: 'view', resource: docResource }),
      ),
    );
  }

  return results;
}

main();
