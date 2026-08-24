'use strict';

const { before, describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const path = require('node:path');

const { Kerberos, createSafeExprCodec, deserializePolicy } = require('../index.js');
const jsep = require('jsep');
const jsepObject = require('@jsep-plugin/object');
const jsepTernary = require('@jsep-plugin/ternary');
const jsepNew = require('@jsep-plugin/new');

const { loadCorpus } = require('./lib/load.js');
const { loadSuites } = require('./lib/suite.js');
const pdp = require('./lib/pdp.js');

const POLICY_DIR = path.join(__dirname, 'policies');
const SUITE_DIR = path.join(__dirname, 'suites');

// Set CERBOS_URL to additionally run every case against a real Cerbos PDP
// serving conformance/policies. Without it the suite still runs in full against
// the expectations recorded in the corpus.
const CERBOS_URL = process.env.CERBOS_URL;

jsep.plugins.register(jsepObject.default ?? jsepObject, jsepTernary.default ?? jsepTernary, jsepNew.default ?? jsepNew);
jsep.addUnaryOp('typeof');
const codec = createSafeExprCodec({ jsep });

const { policies, derivedRoles } = loadCorpus(POLICY_DIR);
const kerberos = new Kerberos(
  policies.map((policy) => deserializePolicy(policy, codec)),
  derivedRoles.map((roles) => deserializePolicy(roles, codec)),
);

const suites = loadSuites(SUITE_DIR);

describe('Cerbos conformance — decisions', () => {
  if (CERBOS_URL) {
    before(async () => {
      await pdp.waitUntilReady(CERBOS_URL);
    });
  }

  it('loads the whole corpus (nothing silently skipped)', () => {
    // The loader throws on anything outside the supported subset, so reaching
    // here means every document translated. Guard the counts too: a corpus file
    // that stopped being picked up would otherwise pass vacuously.
    assert.ok(policies.length >= 2, `expected corpus policies, got ${policies.length}`);
    assert.ok(derivedRoles.length >= 1, `expected derived roles, got ${derivedRoles.length}`);
    assert.ok(suites.length >= 1, 'expected at least one test suite');
    assert.ok(
      suites.every((entry) => entry.cases.length > 0),
      'every suite must expand to at least one case',
    );
  });

  for (const { file, cases } of suites) {
    describe(file, () => {
      for (const testCase of cases) {
        it(testCase.label, async () => {
          const { results } = await kerberos.checkResources({
            principal: testCase.principal,
            resources: [{ resource: testCase.resource, actions: testCase.actions }],
          });
          const actual = results[0].actions;

          assert.deepEqual(
            actual,
            testCase.expected,
            `Kerberos decision differs from the corpus expectation\n` +
              `  principal: ${JSON.stringify(testCase.principal)}\n` +
              `  resource:  ${JSON.stringify(testCase.resource)}`,
          );

          if (!CERBOS_URL) return;

          // The corpus expectation is only half the claim — assert the live PDP
          // agrees with it too, so a wrong expectation cannot make both engines
          // look compatible.
          const [cerbosActions] = await pdp.checkResources(CERBOS_URL, {
            principal: testCase.principal,
            resources: [{ resource: testCase.resource, actions: testCase.actions }],
            requestId: `${testCase.suite}/${testCase.test}`,
          });
          const cerbosSubset = Object.fromEntries(
            Object.keys(testCase.expected).map((action) => [action, cerbosActions[action]]),
          );
          assert.deepEqual(cerbosSubset, testCase.expected, 'live Cerbos PDP differs from the corpus expectation');
          assert.deepEqual(actual, cerbosSubset, 'Kerberos and the live Cerbos PDP disagree');
        });
      }
    });
  }
});
