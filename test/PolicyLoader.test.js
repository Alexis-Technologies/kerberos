const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const jsep = require('jsep');
jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));
jsep.addUnaryOp('typeof');

const { Kerberos, Effect, createSafeExprCodec } = require('../index.js');
const {
  KerberosLoaderError,
  loadPolicyFile,
  loadPolicyDirectory,
  createPolicyBundle,
  writePolicyBundle,
  loadPolicyBundle,
} = require('../loader.js');

const codec = createSafeExprCodec({ jsep });
const REPO = path.join(__dirname, 'fixtures', 'policy-repo');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'kerberos-loader-'));
}

describe('loadPolicyDirectory', () => {
  const loaded = loadPolicyDirectory(REPO);

  it('loads Kerberos JSON, Cerbos JSON and Cerbos YAML documents together', () => {
    // document.json (Kerberos), auditor.json (Cerbos JSON via apiVersion),
    // roles/reader.yaml (Cerbos YAML) → 3 policies; derived.json → 1 set.
    assert.equal(loaded.policies.length, 3);
    assert.equal(loaded.derivedRoles.length, 1);
    assert.deepEqual(loaded.files, ['auditor.json', 'derived.json', 'document.json', 'roles/reader.yaml']);
  });

  it('skips `_`-prefixed directories and hidden files', () => {
    assert.equal(
      loaded.files.some((file) => file.includes('_ignored') || file.includes('.hidden')),
      false,
    );
  });

  it('collects _schemas definitions under both bare and cerbos:/// keys', () => {
    assert.deepEqual(Object.keys(loaded.schemas).sort(), ['cerbos:///document.json', 'document.json']);
    assert.equal(loaded.schemas['document.json'].type, 'object');
  });

  it('returns serialized documents without a codec', () => {
    assert.deepEqual(JSON.parse(JSON.stringify(loaded.policies)), loaded.policies);
  });

  it('builds a working engine end to end (codec + schemas wiring)', async () => {
    const Ajv = require('ajv');
    const withCodec = loadPolicyDirectory(REPO, { codec });
    const kerberos = new Kerberos(withCodec.policies, withCodec.derivedRoles, {
      ajv: new Ajv({ allErrors: true }),
      schemas: { enforcement: 'reject', definitions: loaded.schemas },
    });

    const owner = { id: 'u1', roles: ['USER'] };
    const editor = { id: 'e1', roles: ['EDITOR'] };
    const reader = { id: 'r1', roles: ['READER'] };
    const doc = (attr) => ({ kind: 'document', id: 'd1', attr });

    assert.equal(
      await kerberos.isAllowed({ principal: owner, resource: doc({ ownerId: 'u1' }), action: 'view' }),
      true,
    );
    assert.equal(
      await kerberos.isAllowed({ principal: owner, resource: doc({ ownerId: 'x' }), action: 'view' }),
      false,
    );
    assert.equal(
      await kerberos.isAllowed({ principal: editor, resource: doc({ status: 'READY' }), action: 'publish' }),
      true,
    );
    // READER's role policy allowlists only view — publish is filtered out.
    assert.equal(
      await kerberos.isAllowed({ principal: reader, resource: doc({ status: 'READY' }), action: 'publish' }),
      false,
    );
    // The _schemas definition rejects a non-string status via the schemas option.
    const { results } = await kerberos.checkResources({
      principal: editor,
      resources: [{ resource: doc({ status: 42 }), actions: ['publish'] }],
    });
    assert.equal(results[0].actions.publish, Effect.Deny);
    assert.equal(results[0].validationErrors[0].source, 'SOURCE_RESOURCE');
  });

  it('cerbos: false treats apiVersion documents as unrecognized', () => {
    assert.throws(() => loadPolicyDirectory(REPO, { cerbos: false }), KerberosLoaderError);
  });

  it('recursive: false skips nested directories', () => {
    const flat = loadPolicyDirectory(REPO, { recursive: false });
    assert.equal(flat.files.includes('roles/reader.yaml'), false);
  });

  it('throws on a missing directory', () => {
    assert.throws(() => loadPolicyDirectory(path.join(REPO, 'nope')), KerberosLoaderError);
  });
});

describe('loadPolicyFile', () => {
  it('loads a single Kerberos JSON document', () => {
    const { policies } = loadPolicyFile(path.join(REPO, 'document.json'));
    assert.equal(policies[0].resourcePolicy.resource, 'document');
  });

  it('loads a single Cerbos YAML document', () => {
    const { policies } = loadPolicyFile(path.join(REPO, 'roles', 'reader.yaml'));
    assert.equal(policies[0].rolePolicy.role, 'READER');
  });

  it('loads arrays of documents from one JSON file', () => {
    const dir = tempDir();
    const file = path.join(dir, 'all.json');
    const doc = JSON.parse(fs.readFileSync(path.join(REPO, 'document.json'), 'utf8'));
    const derived = JSON.parse(fs.readFileSync(path.join(REPO, 'derived.json'), 'utf8'));
    fs.writeFileSync(file, JSON.stringify([doc, derived]));
    const loaded = loadPolicyFile(file);
    assert.equal(loaded.policies.length, 1);
    assert.equal(loaded.derivedRoles.length, 1);
  });

  it('reports the file for invalid JSON', () => {
    const dir = tempDir();
    const file = path.join(dir, 'broken.json');
    fs.writeFileSync(file, '{ nope');
    assert.throws(
      () => loadPolicyFile(file),
      (error) => {
        assert.equal(error.name, 'KerberosLoaderError');
        assert.equal(error.file, file);
        return true;
      },
    );
  });

  it('wraps Cerbos importer failures with the file name', () => {
    const dir = tempDir();
    const file = path.join(dir, 'bad.yaml');
    fs.writeFileSync(file, 'apiVersion: api.cerbos.dev/v1\nmystery: 1\n');
    assert.throws(() => loadPolicyFile(file), /bad\.yaml.*Cerbos import failed/);
  });

  it('rejects unrecognized documents', () => {
    const dir = tempDir();
    const file = path.join(dir, 'odd.json');
    fs.writeFileSync(file, JSON.stringify({ something: 'else' }));
    assert.throws(() => loadPolicyFile(file), /unrecognized document/);
  });
});

describe('policy bundles', () => {
  const content = loadPolicyDirectory(REPO);

  it('stamps a content-addressed version', () => {
    const bundleA = createPolicyBundle(content, { createdAt: null });
    const bundleB = createPolicyBundle(
      { policies: [...content.policies], derivedRoles: [...content.derivedRoles] },
      { createdAt: null },
    );
    assert.match(bundleA.version, /^[0-9a-f]{64}$/);
    assert.equal(bundleA.version, bundleB.version); // reproducible
    assert.equal('createdAt' in bundleA, false);
    assert.deepEqual(bundleA.counts, { policies: 3, derivedRoles: 1 });

    const changed = createPolicyBundle({ policies: content.policies.slice(1), derivedRoles: content.derivedRoles });
    assert.notEqual(changed.version, bundleA.version);
  });

  it('the version is key-order independent (canonical hash input)', () => {
    const a = createPolicyBundle({ policies: [{ x: 1, y: 2 }], derivedRoles: [] });
    const b = createPolicyBundle({ policies: [{ y: 2, x: 1 }], derivedRoles: [] });
    assert.equal(a.version, b.version);
  });

  it('round-trips through write + load with verification', async () => {
    const file = path.join(tempDir(), 'bundle.json');
    const written = writePolicyBundle(file, content);
    const loaded = loadPolicyBundle(file, { codec });
    assert.equal(loaded.version, written.version);
    assert.equal(loaded.createdAt, written.createdAt);
    assert.equal(loaded.policies.length, 3);

    const kerberos = new Kerberos(loaded.policies, loaded.derivedRoles);
    assert.equal(
      await kerberos.isAllowed({
        principal: { id: 'u1', roles: ['USER'] },
        resource: { kind: 'document', id: 'd1', attr: { ownerId: 'u1' } },
        action: 'view',
      }),
      true,
    );
  });

  it('detects tampered content', () => {
    const file = path.join(tempDir(), 'bundle.json');
    writePolicyBundle(file, content);
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    raw.policies.push({ rolePolicy: { role: 'SNEAKY', version: 'default', rules: [] } });
    fs.writeFileSync(file, JSON.stringify(raw));
    assert.throws(() => loadPolicyBundle(file), /integrity check failed/);
    // verify: false opts out explicitly (and sees the tampered content).
    assert.equal(loadPolicyBundle(file, { verify: false }).policies.length, 4);
  });

  it('rejects non-bundle JSON', () => {
    const file = path.join(tempDir(), 'not-bundle.json');
    fs.writeFileSync(file, JSON.stringify({ policies: [] }));
    assert.throws(() => loadPolicyBundle(file), /not a Kerberos policy bundle/);
  });

  it('accepts an already-parsed bundle object', () => {
    const bundle = createPolicyBundle(content);
    assert.equal(loadPolicyBundle(bundle).version, bundle.version);
  });

  it('refuses to bundle deserialized (live) policies', () => {
    const live = loadPolicyDirectory(REPO, { codec });
    assert.throws(() => createPolicyBundle(live), /SERIALIZED/);
  });
});

describe('browser stub', () => {
  it('every loader function throws a clear error in browsers', () => {
    const browserLoader = require('../src/loader/browser.js');
    for (const name of [
      'loadPolicyFile',
      'loadPolicyDirectory',
      'createPolicyBundle',
      'writePolicyBundle',
      'loadPolicyBundle',
    ]) {
      assert.throws(() => browserLoader[name](), /not available in browsers/);
    }
  });
});
