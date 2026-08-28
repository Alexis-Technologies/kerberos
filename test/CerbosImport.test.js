const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const jsep = require('jsep');
jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));
jsep.addUnaryOp('typeof');

const { Kerberos, createSafeExprCodec, deserializePolicy } = require('../index.js');
const { KerberosImportError, importCerbosPolicies, celToExpr, parseYamlDocuments } = require('../cerbos.js');

const codec = createSafeExprCodec({ jsep });

function buildEngine({ policies, derivedRoles }) {
  return new Kerberos(
    policies.map((policy) => deserializePolicy(policy, codec)),
    derivedRoles.map((roles) => deserializePolicy(roles, codec)),
  );
}

const EXPENSE_POLICY = `
---
apiVersion: api.cerbos.dev/v1
description: Expense report policy
resourcePolicy:
  version: default
  resource: expense
  importDerivedRoles:
    - expense_roles
  variables:
    local:
      isApproved: request.resource.attr.status == "APPROVED"
  rules:
    - actions: ['view']
      effect: EFFECT_ALLOW
      derivedRoles:
        - owner
    - actions: ['view', 'approve']
      effect: EFFECT_ALLOW
      roles: ['MANAGER']
      condition:
        match:
          expr: request.resource.attr.amount <= 10000 || V.isApproved
    - actions: ['*']
      effect: EFFECT_DENY
      roles: ['*']
      condition:
        match:
          expr: R.attr.locked == true
`;

const EXPENSE_ROLES = `
apiVersion: api.cerbos.dev/v1
derivedRoles:
  name: expense_roles
  definitions:
    - name: owner
      parentRoles: ['USER']
      condition:
        match:
          expr: request.resource.attr.ownerId == request.principal.id
`;

const AUDITOR_POLICY = `
apiVersion: api.cerbos.dev/v1
principalPolicy:
  principal: auditor_amy
  version: default
  rules:
    - resource: expense
      actions:
        - action: view
          effect: EFFECT_ALLOW
`;

describe('importCerbosPolicies — end to end', () => {
  const imported = importCerbosPolicies([EXPENSE_POLICY, EXPENSE_ROLES, AUDITOR_POLICY]);

  it('splits policies from derived roles', () => {
    assert.equal(imported.policies.length, 2);
    assert.equal(imported.derivedRoles.length, 1);
  });

  it('translates conditions and variables to { $expr }', () => {
    const [resourceDoc] = imported.policies;
    assert.deepEqual(resourceDoc.resourcePolicy.variables, {
      isApproved: { $expr: 'R.attr.status === "APPROVED"' },
    });
    assert.deepEqual(resourceDoc.resourcePolicy.rules[1].condition, {
      match: { $expr: 'R.attr.amount <= 10000 || V.isApproved' },
    });
  });

  it('produces serializable JSON documents', () => {
    assert.deepEqual(JSON.parse(JSON.stringify(imported)), imported);
  });

  it('decides like the source policies', async () => {
    const kerberos = buildEngine(imported);
    const owner = { id: 'u1', roles: ['USER'] };
    const manager = { id: 'm1', roles: ['MANAGER'] };
    const amy = { id: 'auditor_amy', roles: ['AUDITOR'] };
    const expense = (attr) => ({ kind: 'expense', id: 'e1', attr });

    const cases = [
      [owner, expense({ ownerId: 'u1' }), 'view', true],
      [owner, expense({ ownerId: 'u2' }), 'view', false],
      [manager, expense({ amount: 500 }), 'approve', true],
      [manager, expense({ amount: 50000, status: 'PENDING' }), 'approve', false],
      [manager, expense({ amount: 50000, status: 'APPROVED' }), 'approve', true],
      [manager, expense({ amount: 500, locked: true }), 'approve', false],
      [amy, expense({}), 'view', true],
      [amy, expense({}), 'approve', false],
    ];
    for (const [principal, resource, action, expected] of cases) {
      assert.equal(
        await kerberos.isAllowed({ principal, resource, action }),
        expected,
        `${principal.id} ${action} ${JSON.stringify(resource.attr)}`,
      );
    }
  });
});

describe('importCerbosPolicies — document handling', () => {
  it('accepts a multi-document YAML string', () => {
    const { policies, derivedRoles } = importCerbosPolicies(
      `${EXPENSE_POLICY}\n---\n${EXPENSE_ROLES.replace('---', '')}`,
    );
    assert.equal(policies.length, 1);
    assert.equal(derivedRoles.length, 1);
  });

  it('accepts already-parsed document objects', () => {
    const [doc] = parseYamlDocuments(AUDITOR_POLICY);
    const { policies } = importCerbosPolicies(doc);
    assert.equal(policies.length, 1);
    assert.equal(policies[0].principalPolicy.principal, 'auditor_amy');
  });

  it('accepts JSON text', () => {
    const json = JSON.stringify({
      apiVersion: 'api.cerbos.dev/v1',
      resourcePolicy: {
        version: 'default',
        resource: 'doc',
        rules: [{ actions: ['view'], effect: 'EFFECT_ALLOW', roles: ['USER'] }],
      },
    });
    const { policies } = importCerbosPolicies(json);
    assert.equal(policies[0].resourcePolicy.resource, 'doc');
  });

  it('skips disabled policies, as the Cerbos loader does', () => {
    const { policies } = importCerbosPolicies(`
apiVersion: api.cerbos.dev/v1
disabled: true
resourcePolicy:
  version: default
  resource: doc
  rules: []
`);
    assert.equal(policies.length, 0);
  });

  it('imports role policies with the implicit default version', () => {
    const { policies } = importCerbosPolicies(`
apiVersion: api.cerbos.dev/v1
rolePolicy:
  role: READER
  scopePermissions: SCOPE_PERMISSIONS_OVERRIDE_PARENT
  rules:
    - resource: doc
      allowActions: ['view']
`);
    assert.equal(policies[0].rolePolicy.version, 'default');
    assert.equal(policies[0].rolePolicy.role, 'READER');
  });

  it('translates output expr and output.when blocks', () => {
    const { policies } = importCerbosPolicies(`
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ['view']
      effect: EFFECT_ALLOW
      roles: ['USER']
      name: with-output
      output:
        when:
          ruleActivated: '"seen:" + request.principal.id'
          conditionNotMet: '"denied:" + request.principal.id'
`);
    assert.deepEqual(policies[0].resourcePolicy.rules[0].output, {
      when: {
        ruleActivated: { $expr: '"seen:" + P.id' },
        conditionNotMet: { $expr: '"denied:" + P.id' },
      },
    });
  });

  it('translates nested all/any/none condition combinators', () => {
    const { policies } = importCerbosPolicies(`
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  rules:
    - actions: ['view']
      effect: EFFECT_ALLOW
      roles: ['USER']
      condition:
        match:
          all:
            of:
              - expr: R.attr.a == 1
              - any:
                  of:
                    - expr: R.attr.b == 2
                    - none:
                        of:
                          - expr: R.attr.c == 3
`);
    const { condition } = policies[0].resourcePolicy.rules[0];
    assert.deepEqual(condition, {
      match: {
        all: [
          { $expr: 'R.attr.a === 1' },
          { any: [{ $expr: 'R.attr.b === 2' }, { none: [{ $expr: 'R.attr.c === 3' }] }] },
        ],
      },
    });
  });

  it('drops schemas only when explicitly asked to', () => {
    const withSchemas = `
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: doc
  schemas:
    resourceSchema:
      ref: cerbos:///doc.json
  rules:
    - actions: ['view']
      effect: EFFECT_ALLOW
      roles: ['USER']
`;
    assert.throws(() => importCerbosPolicies(withSchemas), /attribute schema enforcement/);
    const { policies } = importCerbosPolicies(withSchemas, { drop: ['schemas'] });
    assert.equal(policies.length, 1);
    assert.equal('schemas' in policies[0].resourcePolicy, false);
  });
});

describe('importCerbosPolicies — refuses to guess', () => {
  const rejected = [
    [
      'scopePermissions REQUIRE_PARENTAL_CONSENT',
      `resourcePolicy:\n  version: default\n  resource: doc\n  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS\n  rules: []`,
      /scopePermissions/,
    ],
    [
      'exportVariables documents',
      `exportVariables:\n  name: shared\n  definitions:\n    x: "1"`,
      /exported variable sets/,
    ],
    [
      'exportConstants documents',
      `exportConstants:\n  name: shared\n  definitions:\n    x: 1`,
      /exported constant sets/,
    ],
    [
      'imported variable sets',
      `resourcePolicy:\n  version: default\n  resource: doc\n  variables:\n    import:\n      - shared\n  rules: []`,
      /imported variable sets/,
    ],
    [
      'unknown top-level keys',
      `resourcePolicy:\n  version: default\n  resource: doc\n  rules: []\nmystery: 1`,
      /unrecognized top-level key/,
    ],
    [
      'unknown policy keys',
      `resourcePolicy:\n  version: default\n  resource: doc\n  mystery: 1\n  rules: []`,
      /unrecognized key `mystery`/,
    ],
    [
      'unknown rule keys',
      `resourcePolicy:\n  version: default\n  resource: doc\n  rules:\n    - actions: ['view']\n      effect: EFFECT_ALLOW\n      roles: ['USER']\n      mystery: 1`,
      /unrecognized key `mystery`/,
    ],
    [
      'unknown effects',
      `resourcePolicy:\n  version: default\n  resource: doc\n  rules:\n    - actions: ['view']\n      effect: EFFECT_MAYBE\n      roles: ['USER']`,
      /effect `EFFECT_MAYBE`/,
    ],
    [
      'script conditions',
      `resourcePolicy:\n  version: default\n  resource: doc\n  rules:\n    - actions: ['view']\n      effect: EFFECT_ALLOW\n      roles: ['USER']\n      condition:\n        script: "true"`,
      /script conditions/,
    ],
    [
      'foreign apiVersion',
      `apiVersion: api.example.dev/v9\nresourcePolicy:\n  version: default\n  resource: doc\n  rules: []`,
      /apiVersion/,
    ],
    ['documents with no policy body', `description: nothing here`, /declares no policy body/],
    [
      'untranslatable CEL',
      `resourcePolicy:\n  version: default\n  resource: doc\n  rules:\n    - actions: ['view']\n      effect: EFFECT_ALLOW\n      roles: ['USER']\n      condition:\n        match:\n          expr: R.attr.tags.exists(t, t == "x")`,
      /macro/,
    ],
    [
      'top-level legacy variables',
      `resourcePolicy:\n  version: default\n  resource: doc\n  rules: []\nvariables:\n  x: "1"`,
      /legacy/,
    ],
  ];

  for (const [label, text, pattern] of rejected) {
    it(`rejects ${label}`, () => {
      const doc = text.startsWith('apiVersion') ? text : `apiVersion: api.cerbos.dev/v1\n${text}`;
      assert.throws(() => importCerbosPolicies(doc), pattern);
    });
  }

  it('rejects unknown drop entries', () => {
    assert.throws(() => importCerbosPolicies({}, { drop: ['scopePermissions'] }), /not a droppable feature/);
  });

  it('throws KerberosImportError instances', () => {
    try {
      importCerbosPolicies('mystery: 1');
      assert.fail('expected a throw');
    } catch (error) {
      assert.equal(error instanceof KerberosImportError, true);
      assert.equal(error.name, 'KerberosImportError');
    }
  });

  it('prefixes CEL errors with the document location', () => {
    assert.throws(
      () =>
        importCerbosPolicies(
          `resourcePolicy:\n  version: default\n  resource: doc\n  rules:\n    - actions: ['view']\n      effect: EFFECT_ALLOW\n      roles: ['USER']\n      condition:\n        match:\n          expr: globals.x == 1`,
        ),
      /document\.resourcePolicy\.rules\[0\].*globals/,
    );
  });
});

describe('importCerbosPolicies — conformance corpus round-trip', () => {
  it('imports every corpus policy document', () => {
    const dir = path.join(__dirname, '..', 'conformance', 'policies');
    let policies = 0;
    let derivedRoles = 0;
    for (const file of fs.readdirSync(dir).sort()) {
      if (!/\.ya?ml$/.test(file)) continue;
      const result = importCerbosPolicies(fs.readFileSync(path.join(dir, file), 'utf8'));
      policies += result.policies.length;
      derivedRoles += result.derivedRoles.length;
    }
    // The corpus is the living definition of "Cerbos-shaped": every document
    // in it must go through the public importer without loss.
    assert.ok(policies >= 25, `expected the corpus policies to import, got ${policies}`);
    assert.ok(derivedRoles >= 1, `expected the corpus derived roles to import, got ${derivedRoles}`);
  });
});

describe('celToExpr re-export', () => {
  it('is exposed on the /cerbos subpath', () => {
    assert.equal(celToExpr('R.attr.owner == P.id'), 'R.attr.owner === P.id');
  });
});
