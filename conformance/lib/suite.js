'use strict';

/**
 * Reads Cerbos TestSuite documents and expands them into flat cases.
 *
 * A suite entry may name a single `principal`/`resource` or lists of them; the
 * cross product is expanded here so both the Kerberos run and the live-PDP run
 * iterate exactly the same cases in the same order.
 */

const fs = require('node:fs');
const path = require('node:path');
const YAML = require('yaml');

function resolveRefs(kind, entry, fixtures, where) {
  const single = entry[kind];
  const many = entry[`${kind}s`];
  const names = single !== undefined ? [single] : Array.isArray(many) ? many : null;
  if (!names || names.length === 0) {
    throw new Error(`${where}: expectation names neither \`${kind}\` nor \`${kind}s\``);
  }
  return names.map((name) => {
    if (!fixtures[name]) throw new Error(`${where}: unknown ${kind} fixture \`${name}\``);
    return { name, value: fixtures[name] };
  });
}

/** @returns {Array<{suite, test, principalName, resourceName, principal, resource, actions, expected}>} */
function expandSuite(suite, file) {
  const cases = [];
  for (const [testIndex, test] of (suite.tests ?? []).entries()) {
    const where = `${file} › ${test.name ?? `tests[${testIndex}]`}`;
    if (test.skip) continue;
    const inputActions = test.input?.actions;
    if (!Array.isArray(inputActions) || inputActions.length === 0) {
      throw new Error(`${where}: input.actions is required`);
    }

    for (const [expIndex, expectation] of (test.expected ?? []).entries()) {
      const at = `${where} › expected[${expIndex}]`;
      const principals = resolveRefs('principal', expectation, suite.principals ?? {}, at);
      const resources = resolveRefs('resource', expectation, suite.resources ?? {}, at);
      if (!expectation.actions || Object.keys(expectation.actions).length === 0) {
        throw new Error(`${at}: expectation carries no actions`);
      }

      for (const principal of principals) {
        for (const resource of resources) {
          cases.push({
            suite: suite.name,
            test: test.name ?? `tests[${testIndex}]`,
            label: `${test.name ?? testIndex} [${principal.name} → ${resource.name}]`,
            principalName: principal.name,
            resourceName: resource.name,
            principal: principal.value,
            resource: resource.value,
            actions: Object.keys(expectation.actions),
            expected: expectation.actions,
            // Present only for a recorded divergence: what a real Cerbos PDP
            // returns instead. See DIVERGENCES.md.
            cerbosExpected: expectation.cerbosActions ?? null,
          });
        }
      }
    }
  }
  return cases;
}

function loadSuites(dir, suffix = '_test.yaml') {
  const suites = [];
  for (const file of fs.readdirSync(dir).sort()) {
    if (!file.endsWith(suffix)) continue;
    const parsed = YAML.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
    suites.push({ file, suite: parsed, cases: expandSuite(parsed, file) });
  }
  return suites;
}

module.exports = { expandSuite, loadSuites };
