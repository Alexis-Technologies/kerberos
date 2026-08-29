/**
 * Cross-library comparison benchmark: the same authorization scenario —
 * role-gated actions plus an ownership (ABAC) condition — implemented in
 * Kerberos, CASL (@casl/ability) and casbin.
 *
 * Run: pnpm bench:compare
 *
 * Honesty notes, also published with the results in docs/guide/benchmarks.md:
 * - the libraries have different feature sets; the scenario is the overlap
 *   (RBAC + one attribute condition), NOT a claim of equivalence — none of
 *   the others have policy versions/scopes, query plans or ReBAC;
 * - CASL abilities are built PER USER: `check (prebuilt)` measures the pure
 *   check against a shared ability, `build + check` measures the realistic
 *   per-request path (define rules for the request's user, then check);
 * - casbin's enforce() is async and model-interpreted; the in-memory model
 *   here (RBAC with an ABAC ownership matcher) is its idiomatic equivalent;
 * - @cerbos/embedded and OPA-WASM are absent by necessity: their policy
 *   bundles cannot be built from open tooling alone (Cerbos Hub / the opa
 *   compiler), so honest numbers cannot be produced here.
 */
const { performance } = require('node:perf_hooks');

const { Kerberos, Effect } = require('../src/index.js');
const { AbilityBuilder, createMongoAbility, subject } = require('@casl/ability');
const { newEnforcer, newModelFromString, StringAdapter } = require('casbin');

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
  console.log(`${name.padEnd(56)} ${opsPerSec.toLocaleString('en-US').padStart(12)} ops/sec`);
  return { name, opsPerSec };
}

// The shared scenario: USERs may view documents they own; EDITORs may view
// and publish any document. The check asked of every library: may this USER
// view this document they own?
const user = { id: 'u1', roles: ['USER'] };
const document = { id: 'd1', kind: 'document', attr: { ownerId: 'u1' } };

async function main() {
  console.log('Cross-library comparison — RBAC + ownership condition');
  console.log(`Node ${process.version} · ${new Date().toISOString().slice(0, 10)}\n`);
  const rows = [];

  // --- Kerberos -----------------------------------------------------------
  const kerberos = new Kerberos(
    [
      {
        resourcePolicy: {
          version: 'default',
          resource: 'document',
          rules: [
            {
              actions: ['view'],
              effect: Effect.Allow,
              roles: ['USER'],
              condition: { match: ({ P, R }) => R.attr.ownerId === P.id },
            },
            { actions: ['view', 'publish'], effect: Effect.Allow, roles: ['EDITOR'] },
          ],
        },
      },
    ],
    [],
  );
  rows.push(
    await bench('@alexify/kerberos · isAllowed', () =>
      kerberos.isAllowed({ principal: user, resource: document, action: 'view' })),
  );

  // --- CASL ---------------------------------------------------------------
  function buildAbility(forUser, roles) {
    const { can, build } = new AbilityBuilder(createMongoAbility);
    if (roles.includes('USER')) can('view', 'document', { ownerId: forUser.id });
    if (roles.includes('EDITOR')) can(['view', 'publish'], 'document');
    return build();
  }
  const prebuilt = buildAbility(user, user.roles);
  const caslDoc = subject('document', { ownerId: 'u1' });
  rows.push(await bench('@casl/ability · check (prebuilt ability)', () => prebuilt.can('view', caslDoc)));
  rows.push(
    await bench('@casl/ability · build + check (per request)', () => {
      const ability = buildAbility(user, user.roles);
      return ability.can('view', subject('document', { ownerId: 'u1' }));
    }),
  );

  // --- casbin -------------------------------------------------------------
  const model = newModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (g(r.sub.Id, p.sub) || r.sub.Roles.includes(p.sub)) && p.obj == "document" && p.act == r.act && (p.sub != "USER" || r.obj.OwnerId == r.sub.Id)
`);
  const adapter = new StringAdapter(
    ['p, USER, document, view', 'p, EDITOR, document, view', 'p, EDITOR, document, publish'].join('\n'),
  );
  const enforcer = await newEnforcer(model, adapter);
  const casbinSub = { Id: 'u1', Roles: ['USER'] };
  const casbinObj = { OwnerId: 'u1' };
  rows.push(await bench('casbin · enforce (in-memory model)', () => enforcer.enforce(casbinSub, casbinObj, 'view')));

  // Sanity: every library must actually ALLOW the scenario's check.
  const kerberosOk = await kerberos.isAllowed({ principal: user, resource: document, action: 'view' });
  const caslOk = prebuilt.can('view', caslDoc);
  const casbinOk = await enforcer.enforce(casbinSub, casbinObj, 'view');
  if (!kerberosOk || !caslOk || !casbinOk) {
    throw new Error(`scenario mismatch: kerberos=${kerberosOk} casl=${caslOk} casbin=${casbinOk}`);
  }
  const kerberosDeny = await kerberos.isAllowed({
    principal: { id: 'u2', roles: ['USER'] },
    resource: document,
    action: 'view',
  });
  const casbinDeny = await enforcer.enforce({ Id: 'u2', Roles: ['USER'] }, casbinObj, 'view');
  const caslDeny = buildAbility({ id: 'u2' }, ['USER']).can('view', caslDoc);
  if (kerberosDeny || casbinDeny || caslDeny) {
    throw new Error(`deny-scenario mismatch: kerberos=${kerberosDeny} casl=${caslDeny} casbin=${casbinDeny}`);
  }

  console.log('\n| Library · path | ops/sec |');
  console.log('| -------------- | -------:|');
  for (const row of rows) console.log(`| ${row.name} | ${row.opsPerSec.toLocaleString('en-US')} |`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
