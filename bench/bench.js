/**
 * Zero-dependency ops/sec benchmark for the Kerberos hot paths.
 *
 * Run: pnpm bench (or: node bench/bench.js [filter] [--samples N] [--json] [--src DIR])
 * - a filter runs only the scenarios whose name contains it (e.g.
 *   `node bench/bench.js scaling`);
 * - `--samples N` times each scenario N times and reports the median;
 * - `--json` merges the results into bench/results/engine.json under the
 *   measured package version (the docs charts and README tables read it —
 *   regenerate them with `pnpm bench:report`);
 * - `--src DIR` benchmarks another checkout of the package (e.g. a worktree
 *   of the previous release), which is how release-over-release numbers are
 *   produced on one machine with one harness.
 *
 * jsep (devDependency) is only needed for the cache-backed scenario.
 */
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { parseArgs } = require('node:util');
const { describeMachine } = require('./machine.js');

const { values: options, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    samples: { type: 'string', default: '1' },
    json: { type: 'boolean', default: false },
    src: { type: 'string', default: path.join(__dirname, '..') },
  },
});
const SRC = path.resolve(options.src);
const SAMPLES = Number(options.samples);
const RESULTS_FILE = path.join(__dirname, 'results', 'engine.json');

const { Kerberos, Effect } = require(path.join(SRC, 'src', 'index.js'));

const WARMUP_ITERATIONS = 2_000;
// Slow scenarios (millisecond-scale batches) stop warming up after this long
// instead of spending seconds on 2 000 iterations.
const WARMUP_MAX_MS = 500;
const MEASURE_MS = 1_000;
const filter = positionals[0] ?? '';

async function bench(name, fn) {
  if (!name.includes(filter)) return null;
  const warmupStart = performance.now();
  for (let i = 0; i < WARMUP_ITERATIONS && performance.now() - warmupStart < WARMUP_MAX_MS; i++) await fn();

  const rates = [];
  for (let sample = 0; sample < SAMPLES; sample++) {
    let iterations = 0;
    const start = performance.now();
    while (performance.now() - start < MEASURE_MS) {
      await fn();
      iterations += 1;
    }
    rates.push((iterations / (performance.now() - start)) * 1000);
  }
  rates.sort((a, b) => a - b);
  const mid = rates.length >> 1;
  const opsPerSec = Math.round(rates.length % 2 ? rates[mid] : (rates[mid - 1] + rates[mid]) / 2);
  console.log(`${name.padEnd(66)} ${opsPerSec.toLocaleString('en-US').padStart(12)} ops/sec`);
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

  results.push(
    await bench('checkResources — 10 resources, includeMeta', () =>
      rich.checkResources({ principal, resources: manyResources, includeMeta: true })),
  );

  // Role-policy layer: principal + role policies with a 2-level parentRoles
  // chain (exercises #evaluateRolePolicy's memo/inheritance machinery).
  const layeredPolicies = [
    {
      principalPolicy: {
        principal: 'root',
        version: 'default',
        rules: [{ resource: 'expense', actions: [{ action: '*', effect: Effect.Allow }] }],
      },
    },
    {
      rolePolicy: {
        role: 'JUNIOR',
        version: 'default',
        parentRoles: ['SENIOR'],
        rules: [{ resource: 'expense', allowActions: ['view', 'approve'] }],
      },
    },
    {
      rolePolicy: {
        role: 'SENIOR',
        version: 'default',
        parentRoles: ['LEAD'],
        rules: [{ resource: 'expense', allowActions: ['view', 'approve'] }],
      },
    },
    {
      rolePolicy: {
        role: 'LEAD',
        version: 'default',
        rules: [{ resource: 'expense', allowActions: ['view'] }],
      },
    },
  ];
  const layered = new Kerberos(layeredPolicies, []);
  results.push(
    await bench('isAllowed — role policy + 2-level parentRoles chain', () =>
      layered.isAllowed({ principal: { id: 'joe', roles: ['JUNIOR'] }, action: 'view', resource })),
  );

  // Scoped lookup: a 3-segment request scope walks the scope chain (4 lookups
  // per source) before falling back to the base policy.
  const scoped = new Kerberos(simplePolicies, []);
  const scopedResource = { ...resource, scope: 'acme.emea.sales' };
  results.push(
    await bench('isAllowed — 3-segment scoped request (chain walk)', () =>
      scoped.isAllowed({ principal, action: 'view', resource: scopedResource })),
  );

  // Validation-backend scenario: the same simple check with Zod configured —
  // measures the args-validation cost on top of evaluation.
  try {
    const { z } = require('zod');
    const validated = new Kerberos(simplePolicies, [], { z });
    results.push(
      await bench('isAllowed — simple role match + Zod validation', () =>
        validated.isAllowed({ principal, action: 'view', resource })),
    );
  } catch {
    console.log('(zod not installed — skipping the validation-backend scenario)');
  }

  // Hooks/events scenarios: the baseline above is what every request pays
  // with nothing configured; these measure the seams themselves — a sync
  // listener (the emitter's promise-free fast path), request-level hooks (one
  // await per request, sync driver kept) and per-resource hooks (the async
  // frame around each evaluation).
  const listened = new Kerberos(simplePolicies, []);
  listened.on('decision', () => {});
  results.push(
    await bench('isAllowed — simple role match + 1 sync decision listener', () =>
      listened.isAllowed({ principal, action: 'view', resource })),
  );
  const requestHooked = new Kerberos(simplePolicies, [], { hooks: { beforeRequest() {}, afterRequest() {} } });
  results.push(
    await bench('isAllowed — simple role match + request-level hooks', () =>
      requestHooked.isAllowed({ principal, action: 'view', resource })),
  );
  const resourceHooked = new Kerberos(simplePolicies, [], { hooks: { beforeResource() {}, afterResource() {} } });
  results.push(
    await bench('isAllowed — simple role match + per-resource hooks', () =>
      resourceHooked.isAllowed({ principal, action: 'view', resource })),
  );
  const richListened = new Kerberos(richPolicies, [benchDerivedRoles]);
  richListened.on('decision', () => {});
  results.push(
    await bench('checkResources — 10 resources × 3 actions + decision listener', () =>
      richListened.checkResources({ principal, resources: manyResources })),
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

    // Cache-backed batch: exercises the per-batch singleflight lookups memo
    // (each distinct policy resolves once per batch, not once per resource).
    const cachedBatchResources = [];
    for (let i = 0; i < 50; i++) {
      cachedBatchResources.push({
        resource: { id: `doc${i}`, kind: 'document', attr: { status: 'OPEN' } },
        actions: ['view'],
      });
    }
    results.push(
      await bench('checkResources — 50 resources, cache-backed', () =>
        cached.checkResources({ principal, resources: cachedBatchResources })),
    );

    // Query planning: partial evaluation of a rich $expr policy (variables +
    // constants + allow/deny rules) into a Cerbos-shaped filter.
    const { createSafeExprCodec, deserializePolicy } = require(path.join(SRC, 'src', 'index.js'));
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
  const { RelationResolver } = require(path.join(SRC, 'src', 'Relations', 'index.js'));
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

  await scalingScenarios(results, RelationResolver);

  return results;
}

/**
 * Scaling sweeps over the dimensions that drive decision cost: rules per
 * policy, principal roles, imported derived-role definitions, scope depth and
 * relation-graph depth under a batch. Every scenario name starts with
 * `scaling —` so `node bench/bench.js scaling` runs just these.
 */
async function scalingScenarios(results, RelationResolver) {
  const user = { id: 'sally', roles: ['USER'] };
  const expense = { id: 'e1', kind: 'expense', attr: { ownerId: 'sally' } };

  // 1 000 rules, one distinct action each: the requested action's rule sits
  // first or last in the policy.
  const distinctActionRules = [];
  for (let i = 0; i < 1000; i++) {
    distinctActionRules.push({ actions: [`act${i}`], effect: Effect.Allow, roles: ['USER'] });
  }
  const distinctActions = new Kerberos(
    [{ resourcePolicy: { version: 'default', resource: 'expense', rules: distinctActionRules } }],
    [],
  );
  results.push(
    await bench('scaling — 1 000 rules × distinct actions, match first', () =>
      distinctActions.isAllowed({ principal: user, action: 'act0', resource: expense })),
  );
  results.push(
    await bench('scaling — 1 000 rules × distinct actions, match last', () =>
      distinctActions.isAllowed({ principal: user, action: 'act999', resource: expense })),
  );

  // 1 000 rules sharing one action, one distinct role each.
  const distinctRoleRules = [];
  for (let i = 0; i < 1000; i++) {
    distinctRoleRules.push({ actions: ['view'], effect: Effect.Allow, roles: [`role${i}`] });
  }
  const distinctRoles = new Kerberos(
    [{ resourcePolicy: { version: 'default', resource: 'expense', rules: distinctRoleRules } }],
    [],
  );
  results.push(
    await bench('scaling — 1 000 rules × distinct roles, match last', () =>
      distinctRoles.isAllowed({ principal: { id: 'sally', roles: ['role999'] }, action: 'view', resource: expense })),
  );

  // A principal with 64 roles and no role policy loaded at all.
  const manyRoles = [];
  for (let i = 0; i < 63; i++) manyRoles.push(`team${i}`);
  manyRoles.push('USER');
  const simpleExpense = new Kerberos(
    [
      {
        resourcePolicy: {
          version: 'default',
          resource: 'expense',
          rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
        },
      },
    ],
    [],
  );
  results.push(
    await bench('scaling — 64 principal roles, no role policies', () =>
      simpleExpense.isAllowed({ principal: { id: 'sally', roles: manyRoles }, action: 'view', resource: expense })),
  );

  // 32 imported derived-role definitions, only one referenced by a rule.
  const definitions = [];
  for (let i = 0; i < 32; i++) {
    definitions.push({
      name: `DR${i}`,
      parentRoles: ['USER'],
      condition: { match: ({ P, R }) => R.attr.ownerId === P.id },
    });
  }
  const manyDerived = new Kerberos(
    [
      {
        resourcePolicy: {
          version: 'default',
          resource: 'expense',
          importDerivedRoles: ['many_roles'],
          rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['DR0'] }],
        },
      },
    ],
    [{ name: 'many_roles', definitions }],
  );
  results.push(
    await bench('scaling — 32 derived-role definitions, 1 referenced', () =>
      manyDerived.isAllowed({ principal: user, action: 'view', resource: expense })),
  );

  // Scope depth 8, every level has a policy, the most specific one decides.
  const scopedPolicies = [];
  const segments = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
  for (let depth = 0; depth <= segments.length; depth++) {
    scopedPolicies.push({
      resourcePolicy: {
        version: 'default',
        resource: 'expense',
        scope: segments.slice(0, depth).join('.'),
        rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
      },
    });
  }
  const deepScopes = new Kerberos(scopedPolicies, []);
  const deepResource = { ...expense, scope: segments.join('.') };
  results.push(
    await bench('scaling — scope depth 8, decided at the most specific scope', () =>
      deepScopes.isAllowed({ principal: user, action: 'view', resource: deepResource })),
  );

  // ReBAC batch: 100 documents in one folder, folder chain depth 16.
  const folderSchema = {
    relationSchema: {
      definitions: {
        user: {},
        group: { relations: { member: ['user', 'group#member'] } },
        folder: {
          relations: { parent: ['folder'], viewer: ['user', 'group#member'] },
          permissions: { view: { anyOf: ['viewer', { via: 'parent', permission: 'view' }] } },
        },
        document: {
          relations: { parent: ['folder'], viewer: ['user', 'group#member'] },
          permissions: { view: { anyOf: ['viewer', { via: 'parent', permission: 'view' }] } },
        },
      },
    },
  };
  const DEPTH = 16;
  const folderTuples = ['folder:f1#viewer@group:eng#member', 'group:eng#member@user:deep'];
  for (let level = 2; level <= DEPTH; level++) folderTuples.push(`folder:f${level}#parent@folder:f${level - 1}`);
  const docResources = [];
  for (let i = 0; i < 100; i++) {
    folderTuples.push(`document:d${i}#parent@folder:f${DEPTH}`);
    docResources.push({ resource: { id: `d${i}`, kind: 'document' }, actions: ['view'] });
  }
  const folderRelations = new RelationResolver({ schema: folderSchema, tuples: folderTuples });
  const folderEngine = new Kerberos(
    [
      {
        resourcePolicy: {
          version: 'default',
          resource: 'document',
          importDerivedRoles: ['doc_viewers'],
          rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['DOC_VIEWER'] }],
        },
      },
    ],
    [{ name: 'doc_viewers', definitions: [{ name: 'DOC_VIEWER', relation: 'view' }] }],
    { relations: folderRelations },
  );
  results.push(
    await bench('scaling — checkResources 100 docs, relation depth 16', () =>
      folderEngine.checkResources({ principal: { id: 'deep', roles: ['USER'] }, resources: docResources })),
  );
  results.push(
    await bench('scaling — 100 concurrent relations.check, shared memo, depth 16', () => {
      const memo = new Map();
      return Promise.all(
        docResources.map(({ resource }) =>
          folderRelations.check(
            { resource: `document:${resource.id}`, permission: 'view', subject: 'user:deep' },
            { memo },
          ),
        ),
      );
    }),
  );
}

/**
 * Merges this run into bench/results/engine.json under the benchmarked
 * version: a filtered run (e.g. `scaling`) only replaces its own scenarios.
 */
function writeResults(results) {
  const { version } = JSON.parse(fs.readFileSync(path.join(SRC, 'package.json'), 'utf8'));
  let file = { releases: {} };
  try {
    file = JSON.parse(fs.readFileSync(RESULTS_FILE, 'utf8'));
  } catch {
    // first run
  }
  const previous = file.releases[version]?.scenarios ?? [];
  const measured = results.filter(Boolean);
  const names = new Set(measured.map((result) => result.name));
  file.releases[version] = {
    measuredAt: new Date().toISOString(),
    machine: describeMachine(),
    samples: SAMPLES,
    scenarios: [...previous.filter((result) => !names.has(result.name)), ...measured],
  };
  fs.mkdirSync(path.dirname(RESULTS_FILE), { recursive: true });
  fs.writeFileSync(RESULTS_FILE, `${JSON.stringify(file, null, 2)}\n`);
  console.log(`\nWrote ${path.relative(path.join(__dirname, '..'), RESULTS_FILE)} (${version})`);
}

main().then((results) => {
  if (options.json) writeResults(results);
});
