'use strict';

const { before, describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const YAML = require('yaml');

const { Kerberos, createSafeExprCodec, deserializePolicy } = require('../index.js');
const jsep = require('jsep');
const jsepObject = require('@jsep-plugin/object');
const jsepTernary = require('@jsep-plugin/ternary');
const jsepNew = require('@jsep-plugin/new');

const { loadCorpus } = require('./lib/load.js');
const { canonicalizeFilter, usesKerberosOnlyOperators } = require('./lib/canonical.js');
const pdp = require('./lib/pdp.js');

const CERBOS_URL = process.env.CERBOS_URL;

jsep.plugins.register(jsepObject.default ?? jsepObject, jsepTernary.default ?? jsepTernary, jsepNew.default ?? jsepNew);
jsep.addUnaryOp('typeof');
const codec = createSafeExprCodec({ jsep });

const { policies, derivedRoles } = loadCorpus(path.join(__dirname, 'policies'));
const kerberos = new Kerberos(
  policies.map((policy) => deserializePolicy(policy, codec)),
  derivedRoles.map((roles) => deserializePolicy(roles, codec)),
);

const SUITE_DIR = path.join(__dirname, 'suites');
const planSuites = fs
  .readdirSync(SUITE_DIR)
  .filter((file) => file.endsWith('_plan.yaml'))
  .sort()
  .map((file) => ({ file, suite: YAML.parse(fs.readFileSync(path.join(SUITE_DIR, file), 'utf8')) }));

describe('Cerbos conformance — query plans', () => {
  if (CERBOS_URL) {
    before(async () => {
      await pdp.waitUntilReady(CERBOS_URL);
    });
  }

  it('found plan suites to run', () => {
    assert.ok(planSuites.length > 0, 'no *_plan.yaml suites found');
    assert.ok(
      planSuites.every((entry) => (entry.suite.tests ?? []).length > 0),
      'every plan suite must declare tests',
    );
  });

  for (const { file, suite } of planSuites) {
    describe(file, () => {
      for (const [index, test] of (suite.tests ?? []).entries()) {
        const actions = test.actions ?? (test.action ? [test.action] : null);
        const label = test.description ?? `tests[${index}]`;

        it(label, async () => {
          assert.ok(actions, `${label}: declares neither \`action\` nor \`actions\``);

          const response = await kerberos.planResources({
            principal: suite.principal,
            resource: test.resource,
            ...(actions.length === 1 ? { action: actions[0] } : { actions }),
          });

          assert.equal(
            usesKerberosOnlyOperators(response.filter),
            false,
            'plan uses a Kerberos-only operator (opaque/relation) and cannot be compared to Cerbos',
          );

          assert.deepEqual(
            canonicalizeFilter(response.filter),
            canonicalizeFilter(test.want.filter),
            `Kerberos filter differs from the corpus expectation\n  actual: ${JSON.stringify(response.filter)}`,
          );

          if (!CERBOS_URL) return;

          const cerbosFilter = await pdp.planResources(CERBOS_URL, {
            principal: suite.principal,
            resource: test.resource,
            actions,
            requestId: `plan/${file}/${index}`,
          });
          assert.deepEqual(
            canonicalizeFilter(cerbosFilter),
            canonicalizeFilter(test.want.filter),
            'live Cerbos PDP differs from the corpus expectation',
          );
          assert.deepEqual(
            canonicalizeFilter(response.filter),
            canonicalizeFilter(cerbosFilter),
            'Kerberos and the live Cerbos PDP produce different filters',
          );
        });
      }
    });
  }
});
