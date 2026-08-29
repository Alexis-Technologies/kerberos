#!/usr/bin/env node
'use strict';

/**
 * The Kerberos policy CLI — policy-as-code workflows without hand-written
 * test harnesses:
 *
 *   kerberos test <policiesDir> <testsDir>    run Cerbos-TestSuite-format
 *                                             suites against the policies
 *   kerberos bundle <policiesDir> -o <file>   bake a hash-stamped bundle
 *
 * Policies load through `@alexify/kerberos/loader` (Kerberos JSON and Cerbos
 * YAML/JSON mix freely; `_schemas/` wires attribute schemas). Test suites are
 * Cerbos's own `TestSuite` shape, in YAML or JSON, so policy tests stay
 * engine-agnostic, reviewable artifacts.
 *
 * `{ $expr }` policies need jsep: the CLI resolves `jsep` and the
 * `@jsep-plugin/object|ternary|new` plugins from the CURRENT project (the
 * documented dynamic-policy setup) and tells you what to install when they
 * are missing.
 */

const path = require('node:path');
const fs = require('node:fs');
const { createRequire } = require('node:module');

const { Kerberos, createSafeExprCodec, Effect } = require('../index.js');
const { loadPolicyDirectory, writePolicyBundle, KerberosLoaderError } = require('../loader.js');
const { parseYamlDocuments } = require('../src/cerbos/yaml.js');
const { KerberosImportError } = require('../src/cerbos/errors.js');

const EXIT_OK = 0;
const EXIT_TEST_FAILURES = 1;
const EXIT_USAGE = 2;

const USAGE = `Usage:
  kerberos test <policiesDir> <testsDir> [--schemas none|warn|reject] [--json]
  kerberos bundle <policiesDir> --out <file> [--reproducible]
  kerberos --version | --help

test    Runs every *_test.{yaml,yml,json} suite (Cerbos TestSuite format)
        under <testsDir> against the policies under <policiesDir>.
        --schemas wires <policiesDir>/_schemas into attribute-schema
        enforcement (default: none). --json prints a machine-readable report.
bundle  Loads <policiesDir> and writes a hash-stamped policy bundle
        (see the /loader subpath). --reproducible omits the timestamp.
`;

function fail(message, code = EXIT_USAGE) {
  process.stderr.write(`kerberos: ${message}\n`);
  process.exit(code);
}

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const green = (text) => (useColor ? `\x1b[32m${text}\x1b[0m` : text);
const red = (text) => (useColor ? `\x1b[31m${text}\x1b[0m` : text);
const dim = (text) => (useColor ? `\x1b[2m${text}\x1b[0m` : text);

/** Minimal flag parser: positional args + --flag / --flag value. */
function parseArgs(argv, flags) {
  const positional = [];
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const name = arg.slice(2);
    const spec = flags[name];
    if (!spec) fail(`unknown option --${name}\n\n${USAGE}`);
    if (spec === 'boolean') options[name] = true;
    else options[name] = argv[++i] ?? fail(`--${name} needs a value`);
  }
  return { positional, options };
}

/**
 * Resolves the documented jsep setup from the current project. Returns a
 * codec, or null when jsep is absent (fine for policies without `$expr`).
 */
function resolveCodec() {
  const requirers = [];
  try {
    requirers.push(createRequire(path.join(process.cwd(), 'package.json')));
  } catch {
    // No resolvable project root — fall through to the CLI's own resolution.
  }
  requirers.push(require);

  let jsep = null;
  for (const localRequire of requirers) {
    try {
      const mod = localRequire('jsep');
      jsep = mod.default ?? mod;
      for (const plugin of ['@jsep-plugin/object', '@jsep-plugin/ternary', '@jsep-plugin/new']) {
        try {
          const pluginMod = localRequire(plugin);
          jsep.plugins.register(pluginMod.default ?? pluginMod);
        } catch {
          // Optional plugin not installed — expressions needing it will fail with the codec's own error.
        }
      }
      try {
        jsep.addUnaryOp('typeof');
      } catch {
        // Already registered.
      }
      break;
    } catch {
      // Try the next resolver.
    }
  }
  return jsep ? createSafeExprCodec({ jsep }) : null;
}

function loadPolicies(dir, { schemas: schemasMode }) {
  const codec = resolveCodec();
  let loaded;
  try {
    loaded = loadPolicyDirectory(dir, { codec: codec ?? undefined });
  } catch (error) {
    if (!codec && /\$expr/.test(String(error?.message))) {
      fail(
        `${error.message}\n` +
          'These policies use { $expr } conditions, which need jsep. Install the documented setup:\n' +
          '  npm i jsep @jsep-plugin/object @jsep-plugin/ternary @jsep-plugin/new',
      );
    }
    throw error;
  }
  if (loaded.policies.length + loaded.derivedRoles.length === 0) {
    fail(`${dir}: no policy documents found`);
  }

  const options = {};
  if (schemasMode && schemasMode !== 'none') {
    if (!['warn', 'reject'].includes(schemasMode)) fail(`--schemas expects none, warn or reject (got ${schemasMode})`);
    if (Object.keys(loaded.schemas).length === 0) {
      fail(`--schemas ${schemasMode}: no _schemas/ directory found under ${dir}`);
    }
    let Ajv;
    try {
      Ajv = createRequire(path.join(process.cwd(), 'package.json'))('ajv');
    } catch {
      try {
        Ajv = require('ajv');
      } catch {
        fail('--schemas needs ajv to compile JSON Schemas: npm i ajv');
      }
    }
    const AjvCtor = Ajv.default ?? Ajv;
    options.ajv = new AjvCtor({ allErrors: true, strict: false });
    options.schemas = { enforcement: schemasMode, definitions: loaded.schemas };
  }
  return { engine: new Kerberos(loaded.policies, loaded.derivedRoles, options), loaded };
}

// ---------------------------------------------------------------------------
// `kerberos test` — Cerbos TestSuite runner
// ---------------------------------------------------------------------------

function collectSuiteFiles(dir) {
  const files = [];
  const walk = (current, relative) => {
    for (const entry of fs
      .readdirSync(current, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      if (entry.name.startsWith('.') || entry.name.startsWith('_')) continue;
      const entryRelative = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        walk(path.join(current, entry.name), entryRelative);
        continue;
      }
      if (/_test\.(ya?ml|json)$/i.test(entry.name)) files.push(entryRelative);
    }
  };
  walk(dir, '');
  return files;
}

function parseSuiteFile(dir, file) {
  const text = fs.readFileSync(path.join(dir, file), 'utf8');
  if (file.endsWith('.json')) {
    try {
      return JSON.parse(text);
    } catch (error) {
      fail(`${file}: invalid JSON — ${error.message}`);
    }
  }
  try {
    const documents = parseYamlDocuments(text);
    if (documents.length !== 1) fail(`${file}: expected exactly one YAML document, found ${documents.length}`);
    return documents[0];
  } catch (error) {
    if (error instanceof KerberosImportError) fail(`${file}: ${error.message}`);
    throw error;
  }
}

function resolveRefs(kind, entry, fixtures, where) {
  const single = entry[kind];
  const many = entry[`${kind}s`];
  const names = single !== undefined ? [single] : Array.isArray(many) ? many : null;
  if (!names || names.length === 0) fail(`${where}: expectation names neither \`${kind}\` nor \`${kind}s\``);
  return names.map((name) => {
    if (!fixtures[name]) fail(`${where}: unknown ${kind} fixture \`${name}\``);
    return { name, value: fixtures[name] };
  });
}

/** Expands one Cerbos TestSuite document into flat check cases. */
function expandSuite(suite, file) {
  const cases = [];
  for (const [testIndex, test] of (suite.tests ?? []).entries()) {
    const where = `${file} › ${test.name ?? `tests[${testIndex}]`}`;
    if (test.skip) continue;
    const inputActions = test.input?.actions;
    if (!Array.isArray(inputActions) || inputActions.length === 0) fail(`${where}: input.actions is required`);

    for (const [expIndex, expectation] of (test.expected ?? []).entries()) {
      const at = `${where} › expected[${expIndex}]`;
      // Refuse to guess: an expectation feature this runner does not check
      // (e.g. `outputs`) must not silently pass.
      for (const key of Object.keys(expectation)) {
        if (!['principal', 'principals', 'resource', 'resources', 'actions'].includes(key)) {
          fail(`${at}: unsupported expectation key \`${key}\``);
        }
      }
      if (!expectation.actions || Object.keys(expectation.actions).length === 0) {
        fail(`${at}: expectation carries no actions`);
      }
      for (const principal of resolveRefs('principal', expectation, suite.principals ?? {}, at)) {
        for (const resource of resolveRefs('resource', expectation, suite.resources ?? {}, at)) {
          cases.push({
            label: `${test.name ?? testIndex} [${principal.name} → ${resource.name}]`,
            principal: principal.value,
            resource: resource.value,
            actions: Object.keys(expectation.actions),
            expected: expectation.actions,
          });
        }
      }
    }
  }
  return cases;
}

async function runTests(policiesDir, testsDir, options) {
  if (!fs.existsSync(testsDir) || !fs.statSync(testsDir).isDirectory()) fail(`${testsDir}: not a directory`);
  const { engine } = loadPolicies(policiesDir, options);
  const suiteFiles = collectSuiteFiles(testsDir);
  if (suiteFiles.length === 0) fail(`${testsDir}: no *_test.{yaml,yml,json} suites found`);

  const report = { suites: [], passed: 0, failed: 0 };
  for (const file of suiteFiles) {
    const suite = parseSuiteFile(testsDir, file);
    const cases = expandSuite(suite, file);
    const suiteReport = { file, name: suite.name ?? file, cases: [] };
    for (const testCase of cases) {
      const { results } = await engine.checkResources({
        principal: testCase.principal,
        resources: [{ resource: testCase.resource, actions: testCase.actions }],
      });
      const actual = results[0].actions;
      const mismatches = [];
      for (const [action, expected] of Object.entries(testCase.expected)) {
        if (actual[action] !== expected) {
          mismatches.push({ action, expected, actual: actual[action] ?? Effect.Deny });
        }
      }
      const ok = mismatches.length === 0;
      report[ok ? 'passed' : 'failed']++;
      suiteReport.cases.push({ label: testCase.label, ok, mismatches });
    }
    report.suites.push(suiteReport);
  }

  if (options.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    for (const suite of report.suites) {
      process.stdout.write(`${suite.name} ${dim(`(${suite.file})`)}\n`);
      for (const testCase of suite.cases) {
        process.stdout.write(`  ${testCase.ok ? green('✓') : red('✗')} ${testCase.label}\n`);
        for (const mismatch of testCase.mismatches) {
          process.stdout.write(
            `      ${red(`${mismatch.action}: expected ${mismatch.expected}, got ${mismatch.actual}`)}\n`,
          );
        }
      }
    }
    const summary = `${report.passed} passed, ${report.failed} failed`;
    process.stdout.write(`\n${report.failed ? red(summary) : green(summary)}\n`);
  }
  process.exit(report.failed ? EXIT_TEST_FAILURES : EXIT_OK);
}

// ---------------------------------------------------------------------------
// `kerberos bundle`
// ---------------------------------------------------------------------------

function runBundle(policiesDir, options) {
  const outFile = options.out;
  if (!outFile) fail('bundle needs --out <file>');
  // Bundles hold serialized documents — never load with a codec here.
  const loaded = loadPolicyDirectory(policiesDir);
  const bundle = writePolicyBundle(outFile, loaded, options.reproducible ? { createdAt: null } : {});
  process.stdout.write(
    `wrote ${outFile}\n  version:      ${bundle.version}\n  policies:     ${bundle.counts.policies}\n  derivedRoles: ${bundle.counts.derivedRoles}\n`,
  );
}

// ---------------------------------------------------------------------------

async function main() {
  const [command, ...rest] = process.argv.slice(2);

  if (!command || command === '--help' || command === 'help') {
    process.stdout.write(USAGE);
    process.exit(command ? EXIT_OK : EXIT_USAGE);
  }
  if (command === '--version') {
    process.stdout.write(`${require('../package.json').version}\n`);
    process.exit(EXIT_OK);
  }

  if (command === 'test') {
    const { positional, options } = parseArgs(rest, { schemas: 'value', json: 'boolean' });
    if (positional.length !== 2) fail(`test needs <policiesDir> and <testsDir>\n\n${USAGE}`);
    await runTests(positional[0], positional[1], options);
    return;
  }
  if (command === 'bundle') {
    const { positional, options } = parseArgs(rest, { out: 'value', reproducible: 'boolean' });
    if (positional.length !== 1) fail(`bundle needs <policiesDir>\n\n${USAGE}`);
    runBundle(positional[0], options);
    return;
  }
  fail(`unknown command \`${command}\`\n\n${USAGE}`);
}

main().catch((error) => {
  if (error instanceof KerberosLoaderError || error instanceof KerberosImportError) {
    fail(error.message);
  }
  process.stderr.write(`kerberos: ${error?.stack ?? error}\n`);
  process.exit(EXIT_USAGE);
});
