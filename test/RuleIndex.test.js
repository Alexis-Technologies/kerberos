const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { Effect, Kerberos, PrincipalPolicy, ResourcePolicy, RolePolicy } = require('../src/index.js');
const { createKeyedSelector, createRuleIndex, MAX_CACHED_KEYS, SPLIT_THRESHOLD } = require('../src/ruleIndex.js');
const { compileMatcher } = require('../src/matching.js');

/** mulberry32 — tiny deterministic PRNG (same as test/Fuzz.test.js). */
function createRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = (random, items) => items[Math.floor(random() * items.length)];

function pickSome(random, items, max) {
  const count = 1 + Math.floor(random() * max);
  const picked = [];
  for (let i = 0; i < count; i++) picked.push(pick(random, items));
  return picked;
}

function compiledRule(shape) {
  const rule = { ...shape };
  Object.defineProperty(rule, 'actionsMatcher', { value: compileMatcher(shape.actions) });
  if (Array.isArray(shape.roles)) Object.defineProperty(rule, 'rolesMatcher', { value: compileMatcher(shape.roles) });
  return rule;
}

// The pre-index evaluation loop, kept verbatim as the reference the index
// must reproduce: scan EVERY rule for every action.
function referenceEvaluate(policy, req, derivedRoles) {
  const outputs = new Map();
  const actions = new Map();
  const principalRoles = req.P.roles ?? [];
  const rules = policy.rules;
  for (const action of req.actions) {
    const perAction = { firedAllows: [], firedDenies: [], conditionFailed: false };
    actions.set(action, perAction);
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!rule.actionsMatcher.matches(action)) continue;
      let rolesMatch = rule.rolesMatcher ? rule.rolesMatcher.matchesAny(principalRoles) : false;
      if (!rolesMatch && rule.rolesMatcher && principalRoles.length === 0 && rule.rolesMatcher.matches('*')) {
        rolesMatch = true;
      }
      let derivedRolesMatch = false;
      if (!rolesMatch && Array.isArray(rule.derivedRoles)) {
        derivedRolesMatch = rule.derivedRoles.some((role) => derivedRoles.has(role));
      }
      if (!rolesMatch && !derivedRolesMatch) continue;
      const fulfilled = rule.condition ? rule.condition.isFulfilled(req) : true;
      const src = `${policy.srcBase}#${rule.name || 'UNNAMED_RULE' + `_${i + 1}`}`;
      if (rule.output) {
        const output = rule.output.build(req, fulfilled, src);
        if (output) outputs.set(output.src, output);
      }
      if (!fulfilled) {
        perAction.conditionFailed = true;
        continue;
      }
      if (rule.effect === Effect.Deny) perAction.firedDenies.push(src);
      else perAction.firedAllows.push(src);
    }
  }
  return { outputs, actions };
}

function comparable(result) {
  const actions = {};
  for (const [action, perAction] of result.actions) {
    actions[action] = {
      firedAllows: perAction.firedAllows.map((fired) => fired.src ?? fired),
      firedDenies: perAction.firedDenies.map((fired) => fired.src ?? fired),
      conditionFailed: perAction.conditionFailed,
    };
  }
  return { actions, outputs: [...result.outputs.entries()] };
}

const ACTION_NAMES = ['view', 'edit', 'delete', 'approve', 'view:public', 'view:private', 'archive:all'];
const ACTION_PATTERNS = [...ACTION_NAMES, '*', 'view:*', 'v*', '**', 'a*'];
const ROLE_NAMES = ['USER', 'ADMIN', 'MANAGER', 'team_a', 'team_b', 'GUEST'];
const ROLE_PATTERNS = [...ROLE_NAMES, '*', 'team_*', 'MAN*'];
const DERIVED_NAMES = ['OWNER', 'APPROVER', 'REVIEWER'];

function randomRule(random, index) {
  const rule = {
    actions: pickSome(random, ACTION_PATTERNS, 3),
    effect: random() < 0.3 ? Effect.Deny : Effect.Allow,
  };
  const reach = random();
  if (reach < 0.6) rule.roles = pickSome(random, random() < 0.8 ? ROLE_NAMES : ROLE_PATTERNS, 3);
  else if (reach < 0.85) rule.derivedRoles = pickSome(random, DERIVED_NAMES, 2);
  else {
    rule.roles = pickSome(random, ROLE_PATTERNS, 2);
    rule.derivedRoles = pickSome(random, DERIVED_NAMES, 2);
  }
  const condition = random();
  if (condition < 0.2) rule.condition = { match: ({ R }) => R.attr.flag === true };
  else if (condition < 0.3) rule.condition = { match: () => false };
  if (random() < 0.25) {
    rule.output = {
      when: {
        ruleActivated: ({ R }) => `hit:${index}:${R.id}`,
        conditionNotMet: () => `miss:${index}`,
      },
    };
  }
  if (random() < 0.5) rule.name = `rule_${index}`;
  return rule;
}

describe('Rule index', () => {
  it('returns every rule of an action in rule order while the list is short', () => {
    const rules = [
      compiledRule({ actions: ['view'], roles: ['A'] }),
      compiledRule({ actions: ['edit'], roles: ['A'] }),
      compiledRule({ actions: ['*'], roles: ['B'] }),
      compiledRule({ actions: ['view'], roles: ['C'] }),
    ];
    const index = createRuleIndex(rules);
    assert.deepEqual(index.forAction('view'), [0, 2, 3]);
    assert.deepEqual(index.candidates('view', ['A']), [0, 2, 3]);
    assert.deepEqual(index.forAction('nope'), [2]);
    assert.equal(index.forAction('view'), index.forAction('view'), 'cached per action');
  });

  it('splits long action lists by role, keeping rule order and dropping duplicates', () => {
    const rules = [];
    for (let i = 0; i <= SPLIT_THRESHOLD; i++) rules.push(compiledRule({ actions: ['view'], roles: [`R${i}`] }));
    rules.push(compiledRule({ actions: ['view'], roles: ['R0', 'R1'] })); // index SPLIT_THRESHOLD + 1
    rules.push(compiledRule({ actions: ['view'], roles: ['team_*'] }));
    rules.push(compiledRule({ actions: ['view'], derivedRoles: ['OWNER'] }));
    rules.push(compiledRule({ actions: ['view'] })); // reaches nobody
    const index = createRuleIndex(rules);
    const last = SPLIT_THRESHOLD + 1;

    assert.deepEqual(index.candidates('view', ['R1', 'R0', 'R1']), [0, 1, last, last + 1, last + 2]);
    assert.deepEqual(index.candidates('view', ['R3']), [3, last + 1, last + 2]);
    assert.deepEqual(index.candidates('view', []), [last + 1, last + 2]);
    assert.deepEqual(index.candidates('edit', ['R0']), []);
  });

  it('collects the derived roles referenced by an action', () => {
    const rules = [
      compiledRule({ actions: ['view'], derivedRoles: ['OWNER'] }),
      compiledRule({ actions: ['edit'], derivedRoles: ['EDITOR', 'OWNER'] }),
      compiledRule({ actions: ['*'], roles: ['A'] }),
    ];
    const index = createRuleIndex(rules);
    assert.deepEqual([...index.referencedDerivedRoles('view')], ['OWNER']);
    assert.deepEqual([...index.referencedDerivedRoles('edit')], ['EDITOR', 'OWNER']);
    assert.deepEqual([...index.referencedDerivedRoles('delete')], []);
  });

  it('bounds the per-policy cache', () => {
    let scans = 0;
    const select = createKeyedSelector(1, () => {
      scans += 1;
      return true;
    });
    for (let i = 0; i <= MAX_CACHED_KEYS; i++) select(`key${i}`);
    assert.equal(scans, MAX_CACHED_KEYS + 1);
    select(`key${MAX_CACHED_KEYS}`);
    assert.equal(scans, MAX_CACHED_KEYS + 1, 'the newest key is still cached');
    select('key0');
    assert.equal(scans, MAX_CACHED_KEYS + 2, 'the oldest key was evicted');
  });

  it('matches the full-scan reference on random policies and requests', () => {
    const random = createRandom(0x5eed1d);
    for (let round = 0; round < 150; round++) {
      const rules = [];
      const ruleCount = 1 + Math.floor(random() * 40);
      for (let i = 0; i < ruleCount; i++) rules.push(randomRule(random, i));
      const policy = new ResourcePolicy({
        resourcePolicy: { version: 'default', resource: 'doc', importDerivedRoles: ['set'], rules },
      });

      for (let r = 0; r < 20; r++) {
        const roles = [];
        const roleCount = Math.floor(random() * 5);
        for (let i = 0; i < roleCount; i++) roles.push(pick(random, ROLE_NAMES));
        const derivedRoles = new Map();
        for (const name of DERIVED_NAMES) if (random() < 0.4) derivedRoles.set(name, ['USER']);
        const req = {
          P: { id: 'p', roles },
          R: { id: `r${r}`, kind: 'doc', attr: { flag: random() < 0.5 } },
          actions: pickSome(random, [...ACTION_NAMES, 'unknown'], 3),
        };
        assert.deepEqual(
          comparable(policy.evaluateRules(req, derivedRoles)),
          comparable(referenceEvaluate(policy, req, derivedRoles)),
          `round ${round}, request ${r}`,
        );
      }
    }
  });

  it('keeps decisions and meta attribution identical for a policy past the split threshold', async () => {
    const rules = [];
    for (let i = 0; i < 30; i++) {
      rules.push({ name: `allow_${i}`, actions: ['view'], effect: Effect.Allow, roles: [`R${i}`] });
    }
    rules.push({
      name: 'deny_all',
      actions: ['view'],
      effect: Effect.Deny,
      roles: ['*'],
      condition: { match: ({ R }) => R.attr.locked },
    });
    const engine = new Kerberos([{ resourcePolicy: { version: 'default', resource: 'doc', rules } }], []);
    const check = (roles, locked) =>
      engine.checkResources({
        principal: { id: 'p', roles },
        resources: [{ resource: { id: 'd', kind: 'doc', attr: { locked } }, actions: ['view'] }],
        includeMeta: true,
      });

    const allowed = await check(['R29', 'R3'], false);
    assert.equal(allowed.results[0].actions.view, 'EFFECT_ALLOW');
    assert.equal(allowed.results[0].meta.actions.view.matchedRule, 'resource.doc.vdefault#allow_29');

    const denied = await check(['R29'], true);
    assert.equal(denied.results[0].actions.view, 'EFFECT_DENY');
    assert.equal(denied.results[0].meta.actions.view.matchedRule, 'resource.doc.vdefault#deny_all');

    const unknownRole = await check(['nobody'], false);
    assert.equal(unknownRole.results[0].actions.view, 'EFFECT_DENY');
  });

  it('filters principal- and role-policy rules by kind', () => {
    const principalPolicy = new PrincipalPolicy({
      principalPolicy: {
        principal: 'p',
        version: 'default',
        rules: [
          { resource: 'doc', actions: [{ action: 'view', effect: Effect.Allow }] },
          { resource: 'invoice', actions: [{ action: 'view', effect: Effect.Deny }] },
          { resource: 'do*', actions: [{ action: 'edit', effect: Effect.Allow }] },
        ],
      },
    });
    const req = { P: { id: 'p', roles: [] }, R: { id: '1', kind: 'doc' }, actions: ['view', 'edit'] };
    assert.deepEqual(
      [...principalPolicy.check(req).effects],
      [
        ['view', Effect.Allow],
        ['edit', Effect.Allow],
      ],
    );
    const invoice = { ...req, R: { id: '2', kind: 'invoice' } };
    assert.deepEqual([...principalPolicy.check(invoice).effects], [['view', Effect.Deny]]);

    const rolePolicy = new RolePolicy({
      rolePolicy: {
        role: 'USER',
        version: 'default',
        rules: [
          { resource: 'invoice', allowActions: ['view'] },
          { resource: 'doc', allowActions: ['edit'] },
        ],
      },
    });
    assert.deepEqual([...rolePolicy.evaluateAllowlist(req).allowed], ['edit']);
    assert.deepEqual([...rolePolicy.evaluateAllowlist(invoice).allowed], ['view']);
  });
});
