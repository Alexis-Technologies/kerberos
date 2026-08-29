/**
 * File/directory policy loader + versioned bundles — `@alexify/kerberos/loader`.
 *
 * The core package never touches the filesystem (policies come from the
 * constructor or a read-only cache); this Node-only subpath is the boot-time
 * bridge for policy-as-code repositories:
 *
 * - `loadPolicyDirectory(dir)` reads a directory of policy documents —
 *   Kerberos serialized JSON, and (via the `/cerbos` importer) Cerbos
 *   YAML/JSON — plus Cerbos-style `_schemas/` attribute schemas;
 * - `createPolicyBundle` / `writePolicyBundle` / `loadPolicyBundle` turn the
 *   result into a single hash-stamped artifact for GitOps pipelines: the
 *   bundle's `version` is the SHA-256 of its canonical content, and loading
 *   verifies it, so a tampered or truncated bundle fails loudly.
 *
 * All functions are synchronous (boot-time work). This subpath is the ONE
 * deliberate exception to the "src/ stays platform-neutral" invariant: it
 * uses `node:fs`/`node:path`/`node:crypto` directly, and browser bundlers
 * resolve `src/loader/browser.js` (throwing stubs) via the package.json
 * `browser` map instead.
 */

const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const { KerberosLoaderError } = require('./errors.js');
const { importCerbosPolicies } = require('../cerbos/importer.js');
const { KerberosImportError } = require('../cerbos/errors.js');
const { deserializePolicy } = require('../caching/codec.js');

const BUNDLE_MARKER = 'kerberosPolicyBundle';
const BUNDLE_FORMAT_VERSION = 1;

const POLICY_ROOTS = ['resourcePolicy', 'principalPolicy', 'rolePolicy'];

function fail(message, file) {
  throw new KerberosLoaderError(message, { file });
}

/** Deterministic JSON with lexicographically sorted object keys — the hash input. */
function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

/** Rejects live (deserialized) policies: only SERIALIZED documents bundle faithfully. */
function assertNoFunctions(value, at) {
  if (typeof value === 'function') {
    fail(
      `bundle content contains a function at ${at} — bundle SERIALIZED documents ({ $expr }), not deserialized policies`,
    );
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) assertNoFunctions(value[i], `${at}[${i}]`);
  } else if (value && typeof value === 'object') {
    for (const key of Object.keys(value)) assertNoFunctions(value[key], `${at}.${key}`);
  }
}

function contentHash({ policies, derivedRoles }) {
  return createHash('sha256').update(stableStringify({ policies, derivedRoles })).digest('hex');
}

/** Splits parsed Kerberos serialized documents into policies vs derived roles. */
function classifyDocument(doc, file, into) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    fail(`expected a policy document object, got ${Array.isArray(doc) ? 'an array' : typeof doc}`, file);
  }
  if (POLICY_ROOTS.some((root) => doc[root] !== undefined)) {
    into.policies.push(doc);
    return;
  }
  if (typeof doc.name === 'string' && Array.isArray(doc.definitions)) {
    into.derivedRoles.push(doc);
    return;
  }
  fail(
    'unrecognized document — expected { resourcePolicy | principalPolicy | rolePolicy } or a derived-roles ' +
      'document ({ name, definitions })',
    file,
  );
}

function isCerbosJson(doc) {
  return Boolean(doc) && typeof doc === 'object' && typeof doc.apiVersion === 'string';
}

function loadOneFile(filePath, displayName, { cerbos, drop }, into) {
  const text = fs.readFileSync(filePath, 'utf8');
  const extension = path.extname(filePath).toLowerCase();

  try {
    if (extension === '.yaml' || extension === '.yml') {
      // Cerbos policies are the only YAML documents in scope.
      if (cerbos === false) {
        fail('YAML policies need the Cerbos importer, but the `cerbos` option is false', displayName);
      }
      const imported = importCerbosPolicies(text, { drop });
      into.policies.push(...imported.policies);
      into.derivedRoles.push(...imported.derivedRoles);
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (error) {
      fail(`invalid JSON — ${error.message}`, displayName);
    }
    const documents = Array.isArray(parsed) ? parsed : [parsed];
    for (const doc of documents) {
      // `cerbos: true` forces the importer; 'auto' routes on the apiVersion
      // key, which the Cerbos policy schema requires and Kerberos documents
      // never carry.
      if (cerbos === true || (cerbos === 'auto' && isCerbosJson(doc))) {
        const imported = importCerbosPolicies(doc, { drop });
        into.policies.push(...imported.policies);
        into.derivedRoles.push(...imported.derivedRoles);
      } else {
        if (isCerbosJson(doc)) {
          fail('document carries `apiVersion` (Cerbos format), but the `cerbos` option is false', displayName);
        }
        classifyDocument(doc, displayName, into);
      }
    }
  } catch (error) {
    if (error instanceof KerberosImportError) {
      fail(`Cerbos import failed — ${error.message}`, displayName);
    }
    throw error;
  }
}

function normalizeOptions(options = {}) {
  const { codec = null, cerbos = 'auto', drop = [], recursive = true } = options;
  if (cerbos !== 'auto' && typeof cerbos !== 'boolean') {
    fail("invalid `cerbos` option — expected 'auto', true or false");
  }
  return { codec, cerbos, drop, recursive };
}

function maybeDeserialize({ policies, derivedRoles }, codec) {
  if (!codec) return { policies, derivedRoles };
  return {
    policies: policies.map((doc) => deserializePolicy(doc, codec)),
    derivedRoles: derivedRoles.map((doc) => deserializePolicy(doc, codec)),
  };
}

/**
 * Loads one policy file (`.json` Kerberos/Cerbos document(s), or `.yaml`
 * Cerbos document(s)).
 *
 * @param {string} filePath
 * @param {{ codec?: object, cerbos?: 'auto' | boolean, drop?: string[] }} [options]
 * @returns {{ policies: unknown[], derivedRoles: unknown[] }}
 */
function loadPolicyFile(filePath, options = {}) {
  const { codec, cerbos, drop } = normalizeOptions(options);
  const into = { policies: [], derivedRoles: [] };
  loadOneFile(filePath, filePath, { cerbos, drop }, into);
  return maybeDeserialize(into, codec);
}

/** Recursively collects policy files, skipping `_`-prefixed and hidden entries. */
function collectFiles(dir, recursive, relative = '') {
  const files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en'));
  for (const entry of entries) {
    // Cerbos convention: `_`-prefixed directories (`_schemas`, test data) are
    // not policies; hidden files are editor/VCS noise.
    if (entry.name.startsWith('_') || entry.name.startsWith('.')) continue;
    const entryRelative = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (recursive) files.push(...collectFiles(path.join(dir, entry.name), recursive, entryRelative));
      continue;
    }
    if (/\.(json|ya?ml)$/i.test(entry.name)) files.push(entryRelative);
  }
  return files;
}

/** Loads `_schemas/**` JSON files into a ref → schema map (both bare and `cerbos:///` keys). */
function loadSchemaDefinitions(dir) {
  const schemasDir = path.join(dir, '_schemas');
  if (!fs.existsSync(schemasDir) || !fs.statSync(schemasDir).isDirectory()) return {};
  const definitions = {};
  const walk = (current, relative) => {
    for (const entry of fs
      .readdirSync(current, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      const entryRelative = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        walk(path.join(current, entry.name), entryRelative);
        continue;
      }
      if (!entry.name.endsWith('.json')) continue;
      let parsed;
      try {
        parsed = JSON.parse(fs.readFileSync(path.join(current, entry.name), 'utf8'));
      } catch (error) {
        fail(`invalid JSON schema — ${error.message}`, `_schemas/${entryRelative}`);
      }
      // Cerbos policies reference schemas as `cerbos:///<path>`; expose the
      // bare path too so hand-written Kerberos policies can use either.
      definitions[entryRelative] = parsed;
      definitions[`cerbos:///${entryRelative}`] = parsed;
    }
  };
  walk(schemasDir, '');
  return definitions;
}

/**
 * Loads every policy document under `dir` (recursively by default; `_`- and
 * `.`-prefixed entries skipped). Returns Kerberos constructor inputs plus the
 * relative file list and any `_schemas/` attribute-schema definitions, keyed
 * for the engine's `schemas.definitions` option.
 *
 * @param {string} dir
 * @param {{ codec?: object, cerbos?: 'auto' | boolean, drop?: string[], recursive?: boolean }} [options]
 * @returns {{ policies: unknown[], derivedRoles: unknown[], files: string[], schemas: Record<string, unknown> }}
 */
function loadPolicyDirectory(dir, options = {}) {
  const { codec, cerbos, drop, recursive } = normalizeOptions(options);
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    fail(`not a directory`, dir);
  }
  const files = collectFiles(dir, recursive);
  const into = { policies: [], derivedRoles: [] };
  for (const file of files) {
    loadOneFile(path.join(dir, file), file, { cerbos, drop }, into);
  }
  return { ...maybeDeserialize(into, codec), files, schemas: loadSchemaDefinitions(dir) };
}

/**
 * Stamps `{ policies, derivedRoles }` into a versioned bundle: `version` is
 * the SHA-256 of the canonical (sorted-key) JSON of the content, so the same
 * policies always produce the same version and any change produces a new one.
 * Only SERIALIZED documents can be bundled — live policies contain functions.
 *
 * @param {{ policies?: unknown[], derivedRoles?: unknown[] }} input
 * @param {{ createdAt?: string | null }} [options] - ISO timestamp for the stamp (`null` omits it)
 * @returns {Record<string, unknown>}
 */
function createPolicyBundle(input, options = {}) {
  if (!input || typeof input !== 'object') fail('createPolicyBundle expects { policies, derivedRoles }');
  const policies = input.policies ?? [];
  const derivedRoles = input.derivedRoles ?? [];
  if (!Array.isArray(policies) || !Array.isArray(derivedRoles)) {
    fail('createPolicyBundle expects `policies` and `derivedRoles` arrays');
  }
  // JSON.stringify silently drops functions, so a deserialized policy would
  // bundle as a hollow shell — scan for them explicitly instead.
  assertNoFunctions({ policies, derivedRoles }, '$');
  const createdAt = options.createdAt === undefined ? new Date().toISOString() : options.createdAt;
  return {
    [BUNDLE_MARKER]: BUNDLE_FORMAT_VERSION,
    version: contentHash({ policies, derivedRoles }),
    ...(createdAt && { createdAt }),
    counts: { policies: policies.length, derivedRoles: derivedRoles.length },
    policies,
    derivedRoles,
  };
}

/**
 * Writes a bundle (or raw `{ policies, derivedRoles }`, which is stamped
 * first) to `filePath` as pretty JSON. Returns the bundle written.
 *
 * @param {string} filePath
 * @param {Record<string, unknown>} input
 * @param {{ createdAt?: string | null }} [options]
 * @returns {Record<string, unknown>}
 */
function writePolicyBundle(filePath, input, options = {}) {
  const bundle = input?.[BUNDLE_MARKER] ? input : createPolicyBundle(input, options);
  fs.writeFileSync(filePath, `${JSON.stringify(bundle, null, 2)}\n`);
  return bundle;
}

/**
 * Loads a bundle from a file path or an already-parsed object, verifying its
 * hash stamp (disable with `verify: false`). A version mismatch — content
 * edited by hand, truncated, or stamped by something else — throws.
 *
 * @param {string | Record<string, unknown>} source
 * @param {{ codec?: object, verify?: boolean }} [options]
 * @returns {{ policies: unknown[], derivedRoles: unknown[], version: string, createdAt?: string }}
 */
function loadPolicyBundle(source, options = {}) {
  const { codec = null, verify = true } = options;
  let bundle = source;
  let file;
  if (typeof source === 'string') {
    file = source;
    try {
      bundle = JSON.parse(fs.readFileSync(source, 'utf8'));
    } catch (error) {
      fail(`failed to read bundle — ${error.message}`, source);
    }
  }
  if (!bundle || typeof bundle !== 'object' || bundle[BUNDLE_MARKER] !== BUNDLE_FORMAT_VERSION) {
    fail('not a Kerberos policy bundle (missing/unknown marker) — create one with createPolicyBundle', file);
  }
  const policies = bundle.policies ?? [];
  const derivedRoles = bundle.derivedRoles ?? [];
  if (verify) {
    const actual = contentHash({ policies, derivedRoles });
    if (actual !== bundle.version) {
      fail(
        `bundle integrity check failed — content hashes to ${actual} but the bundle is stamped ${bundle.version}`,
        file,
      );
    }
  }
  return {
    ...maybeDeserialize({ policies, derivedRoles }, codec),
    version: bundle.version,
    ...(bundle.createdAt && { createdAt: bundle.createdAt }),
  };
}

module.exports = {
  KerberosLoaderError,
  loadPolicyFile,
  loadPolicyDirectory,
  createPolicyBundle,
  writePolicyBundle,
  loadPolicyBundle,
};
