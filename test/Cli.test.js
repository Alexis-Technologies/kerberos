const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const CLI = path.join(__dirname, '..', 'bin', 'kerberos.js');
const REPO = path.join(__dirname, 'fixtures', 'policy-repo');
const TESTS = path.join(__dirname, 'fixtures', 'policy-tests');

const { loadPolicyBundle } = require('../loader.js');

function run(args, options = {}) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8', ...options });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    return { status: error.status, stdout: error.stdout ?? '', stderr: error.stderr ?? '' };
  }
}

describe('kerberos CLI — test command', () => {
  it('runs a passing suite and exits 0', () => {
    const result = run(['test', REPO, TESTS]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /DocumentSuite/);
    assert.match(result.stdout, /5 passed, 0 failed/);
  });

  it('reports mismatches and exits 1', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kerberos-cli-'));
    const failing = fs
      .readFileSync(path.join(TESTS, 'document_test.yaml'), 'utf8')
      .replace('          view: EFFECT_ALLOW', '          view: EFFECT_DENY');
    fs.writeFileSync(path.join(dir, 'failing_test.yaml'), failing);
    const result = run(['test', REPO, dir]);
    assert.equal(result.status, 1);
    assert.match(result.stdout, /view: expected EFFECT_DENY, got EFFECT_ALLOW/);
    assert.match(result.stdout, /4 passed, 1 failed/);
  });

  it('emits a machine-readable report with --json', () => {
    const result = run(['test', REPO, TESTS, '--json']);
    assert.equal(result.status, 0);
    const report = JSON.parse(result.stdout);
    assert.equal(report.passed, 5);
    assert.equal(report.failed, 0);
    assert.equal(report.suites[0].name, 'DocumentSuite');
    assert.equal(
      report.suites[0].cases.every((testCase) => testCase.ok),
      true,
    );
  });

  it('wires _schemas enforcement with --schemas reject', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kerberos-cli-'));
    // The owner would be allowed to view (the condition only reads ownerId),
    // but the resource violates _schemas/document.json (status must be a
    // string) — so the expectation below holds ONLY under reject enforcement.
    fs.writeFileSync(
      path.join(dir, 'schema_test.yaml'),
      `name: SchemaSuite
principals:
  owner:
    id: u1
    roles: ['USER']
resources:
  bad_doc:
    kind: document
    id: d9
    attr:
      ownerId: u1
      status: 42
tests:
  - name: invalid attributes are rejected
    input:
      actions: ['view']
    expected:
      - principal: owner
        resource: bad_doc
        actions:
          view: EFFECT_DENY
`,
    );
    const withEnforcement = run(['test', REPO, dir, '--schemas', 'reject']);
    assert.equal(withEnforcement.status, 0, withEnforcement.stderr);
    assert.match(withEnforcement.stdout, /1 passed, 0 failed/);
    // The flag is load-bearing: without it the same suite fails (view allows).
    const withoutEnforcement = run(['test', REPO, dir]);
    assert.equal(withoutEnforcement.status, 1);
  });

  it('refuses expectation features it does not check', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kerberos-cli-'));
    fs.writeFileSync(
      path.join(dir, 'outputs_test.yaml'),
      `name: OutputsSuite
principals:
  u:
    id: u1
    roles: ['USER']
resources:
  d:
    kind: document
    id: d1
tests:
  - name: with outputs
    input:
      actions: ['view']
    expected:
      - principal: u
        resource: d
        actions:
          view: EFFECT_DENY
        outputs:
          - src: x
`,
    );
    const result = run(['test', REPO, dir]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /unsupported expectation key `outputs`/);
  });

  it('fails usage errors with exit 2', () => {
    assert.equal(run(['test', REPO]).status, 2);
    assert.equal(run(['frobnicate']).status, 2);
    assert.equal(run(['test', REPO, path.join(REPO, 'nope')]).status, 2);
  });
});

describe('kerberos CLI — bundle command', () => {
  it('writes a verifiable hash-stamped bundle', () => {
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'kerberos-cli-')), 'bundle.json');
    const result = run(['bundle', REPO, '--out', out]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /version:\s+[0-9a-f]{64}/);
    const bundle = loadPolicyBundle(out); // verifies the stamp
    assert.equal(bundle.policies.length, 3);
  });

  it('--reproducible omits the timestamp (byte-stable output)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kerberos-cli-'));
    const a = path.join(dir, 'a.json');
    const b = path.join(dir, 'b.json');
    run(['bundle', REPO, '--out', a, '--reproducible']);
    run(['bundle', REPO, '--out', b, '--reproducible']);
    assert.equal(fs.readFileSync(a, 'utf8'), fs.readFileSync(b, 'utf8'));
  });
});

describe('kerberos CLI — general', () => {
  it('prints the version', () => {
    const result = run(['--version']);
    assert.equal(result.status, 0);
    assert.equal(result.stdout.trim(), require('../package.json').version);
  });

  it('prints usage on help', () => {
    const result = run(['help']);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /kerberos test <policiesDir>/);
  });
});
