'use strict';

/**
 * Runs the whole conformance corpus through the PUBLIC Cerbos importer
 * (`@alexify/kerberos/cerbos`) instead of the structural test loader
 * (lib/load.js), and asserts that the resulting engine decides and plans
 * exactly like the corpus expectations.
 *
 * This is the compatibility claim of the importer in executable form: real
 * Cerbos policy YAML, translated end-to-end (YAML parsing included, CEL
 * conditions translated to `$expr` rather than passed through), produces the
 * decisions a live Cerbos PDP was verified to produce. No PDP is needed here —
 * decisions.test.js/plans.test.js already pin these expectations against one;
 * this suite pins the importer against those same expectations.
 */

const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { Kerberos, createSafeExprCodec, deserializePolicy } = require('../index.js');
const { importCerbosPolicies } = require('../cerbos.js');
const jsep = require('jsep');
const jsepObject = require('@jsep-plugin/object');
const jsepTernary = require('@jsep-plugin/ternary');
const jsepNew = require('@jsep-plugin/new');

const { loadSuites } = require('./lib/suite.js');
const { canonicalizeFilter, usesKerberosOnlyOperators } = require('./lib/canonical.js');

jsep.plugins.register(jsepObject.default ?? jsepObject, jsepTernary.default ?? jsepTernary, jsepNew.default ?? jsepNew);
jsep.addUnaryOp('typeof');
const codec = createSafeExprCodec({ jsep });

const POLICY_DIR = path.join(__dirname, 'policies');
const SUITE_DIR = path.join(__dirname, 'suites');

const policies = [];
const derivedRoles = [];
for (const file of fs.readdirSync(POLICY_DIR).sort()) {
  if (!/\.ya?ml$/.test(file)) continue;
  const imported = importCerbosPolicies(fs.readFileSync(path.join(POLICY_DIR, file), 'utf8'));
  policies.push(...imported.policies);
  derivedRoles.push(...imported.derivedRoles);
}

const kerberos = new Kerberos(
  policies.map((policy) => deserializePolicy(policy, codec)),
  derivedRoles.map((roles) => deserializePolicy(roles, codec)),
);

describe('Cerbos conformance — via the public importer', () => {
  it('imports the whole corpus (nothing silently skipped)', () => {
    assert.ok(policies.length >= 2, `expected corpus policies, got ${policies.length}`);
    assert.ok(derivedRoles.length >= 1, `expected corpus derived roles, got ${derivedRoles.length}`);
  });

  describe('decisions', () => {
    for (const { file, cases } of loadSuites(SUITE_DIR)) {
      describe(file, () => {
        for (const testCase of cases) {
          it(testCase.label, async () => {
            const { results } = await kerberos.checkResources({
              principal: testCase.principal,
              resources: [{ resource: testCase.resource, actions: testCase.actions }],
            });
            assert.deepEqual(
              results[0].actions,
              testCase.expected,
              'importer-loaded engine differs from the corpus expectation',
            );
          });
        }
      });
    }
  });

  describe('query plans', () => {
    const planSuites = fs
      .readdirSync(SUITE_DIR)
      .filter((file) => file.endsWith('_plan.yaml'))
      .sort()
      .map((file) => ({
        file,
        suite: importParseYaml(fs.readFileSync(path.join(SUITE_DIR, file), 'utf8')),
      }));

    for (const { file, suite } of planSuites) {
      describe(file, () => {
        for (const [index, test] of (suite.tests ?? []).entries()) {
          const actions = test.actions ?? (test.action ? [test.action] : null);
          it(test.description ?? `tests[${index}]`, async () => {
            const response = await kerberos.planResources({
              principal: suite.principal,
              resource: test.resource,
              ...(actions.length === 1 ? { action: actions[0] } : { actions }),
            });
            assert.equal(usesKerberosOnlyOperators(response.filter), false);
            assert.deepEqual(
              canonicalizeFilter(response.filter),
              canonicalizeFilter(test.want.filter),
              `importer-loaded plan differs from the corpus expectation\n  actual: ${JSON.stringify(response.filter)}`,
            );
          });
        }
      });
    }
  });
});

/** The suites are plain YAML too — read them with the importer's own parser. */
function importParseYaml(text) {
  const { parseYamlDocuments } = require('../src/cerbos/yaml.js');
  const [doc] = parseYamlDocuments(text);
  return doc;
}
