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
 * Two drivers over ONE shared core: the top-level functions are synchronous
 * (the simple boot-time path), and the `promises` namespace exposes the same
 * API asynchronously — `promises.loadPolicyDirectory` additionally reads
 * files CONCURRENTLY (bounded by the `concurrency` option), which is what
 * makes cold starts over large policy repositories fast. Everything that
 * decides — routing, parsing, classification, bundle stamping/verification —
 * lives in the shared core, so the two drivers cannot drift; only the
 * filesystem calls differ. Results are byte-identical between drivers
 * (deterministic sorted order regardless of read-completion order).
 *
 * This subpath is the ONE deliberate exception to the "src/ stays
 * platform-neutral" invariant: it uses `node:fs`/`node:path`/`node:crypto`
 * directly, and browser bundlers resolve `src/loader/browser.js` (throwing
 * stubs) via the package.json `browser` map instead.
 */

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');

const { KerberosLoaderError } = require('./errors.js');
const { importCerbosPolicies } = require('../cerbos/importer.js');
const { KerberosImportError } = require('../cerbos/errors.js');
const { deserializePolicy } = require('../caching/codec.js');
const { createLimiter } = require('../async.js');

const BUNDLE_MARKER = 'kerberosPolicyBundle';
const BUNDLE_FORMAT_VERSION = 1;

const POLICY_ROOTS = ['resourcePolicy', 'principalPolicy', 'rolePolicy'];
const POLICY_FILE_RE = /\.(json|ya?ml)$/i;
const DEFAULT_READ_CONCURRENCY = 64;

// ---------------------------------------------------------------------------
// Shared core — everything that DECIDES. Pure with respect to the filesystem:
// both drivers feed it file lists and text and get identical results.
// ---------------------------------------------------------------------------

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

/** Routes one file's TEXT into `into` — the whole per-file pipeline after the read. */
function ingestPolicyText(text, displayName, { cerbos, drop }, into) {
  const extension = path.extname(displayName).toLowerCase();

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

/** Parses one `_schemas/**` JSON file into the definitions map (bare + `cerbos:///` keys). */
function addSchemaDefinition(definitions, entryRelative, text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    fail(`invalid JSON schema — ${error.message}`, `_schemas/${entryRelative}`);
  }
  // Cerbos policies reference schemas as `cerbos:///<path>`; expose the
  // bare path too so hand-written Kerberos policies can use either.
  definitions[entryRelative] = parsed;
  definitions[`cerbos:///${entryRelative}`] = parsed;
}

// Cerbos convention: `_`-prefixed directories (`_schemas`, test data) are
// not policies; hidden files are editor/VCS noise.
function skipEntry(name) {
  return name.startsWith('_') || name.startsWith('.');
}

function sortDirEntries(entries) {
  return entries.sort((a, b) => a.name.localeCompare(b.name, 'en'));
}

function normalizeOptions(options = {}) {
  const {
    codec = null,
    cerbos = 'auto',
    drop = [],
    recursive = true,
    concurrency = DEFAULT_READ_CONCURRENCY,
  } = options;
  if (cerbos !== 'auto' && typeof cerbos !== 'boolean') {
    fail("invalid `cerbos` option — expected 'auto', true or false");
  }
  if (typeof concurrency !== 'number' || Number.isNaN(concurrency) || concurrency < 1) {
    fail('invalid `concurrency` option — expected a number >= 1');
  }
  return { codec, cerbos, drop, recursive, concurrency };
}

function maybeDeserialize({ policies, derivedRoles }, codec) {
  if (!codec) return { policies, derivedRoles };
  return {
    policies: policies.map((doc) => deserializePolicy(doc, codec)),
    derivedRoles: derivedRoles.map((doc) => deserializePolicy(doc, codec)),
  };
}

/** Assembles a directory result from ingested texts, in deterministic order. */
function assembleDirectory({ files, texts, schemaFiles, schemaTexts, codec, cerbos, drop }) {
  const into = { policies: [], derivedRoles: [] };
  for (let i = 0; i < files.length; i++) {
    ingestPolicyText(texts[i], files[i], { cerbos, drop }, into);
  }
  const schemas = {};
  for (let i = 0; i < schemaFiles.length; i++) {
    addSchemaDefinition(schemas, schemaFiles[i], schemaTexts[i]);
  }
  return { ...maybeDeserialize(into, codec), files, schemas };
}

function buildBundle(input, options = {}) {
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

/** A bundle to write: passed through when already stamped, stamped otherwise. */
function ensureBundle(input, options) {
  return input?.[BUNDLE_MARKER] ? input : buildBundle(input, options);
}

function serializeBundle(bundle) {
  return `${JSON.stringify(bundle, null, 2)}\n`;
}

function parseBundleText(text, file) {
  try {
    return JSON.parse(text);
  } catch (error) {
    return fail(`failed to read bundle — ${error.message}`, file);
  }
}

/** Marker check + hash verification + result assembly — everything after the read. */
function resolveBundle(bundle, file, { codec = null, verify = true } = {}) {
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

// ---------------------------------------------------------------------------
// Synchronous driver
// ---------------------------------------------------------------------------

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
  ingestPolicyText(fs.readFileSync(filePath, 'utf8'), filePath, { cerbos, drop }, into);
  return maybeDeserialize(into, codec);
}

/** Recursively collects policy files, skipping `_`-prefixed and hidden entries. */
function collectFiles(dir, recursive, relative = '') {
  const files = [];
  for (const entry of sortDirEntries(fs.readdirSync(dir, { withFileTypes: true }))) {
    if (skipEntry(entry.name)) continue;
    const entryRelative = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (recursive) files.push(...collectFiles(path.join(dir, entry.name), recursive, entryRelative));
      continue;
    }
    if (POLICY_FILE_RE.test(entry.name)) files.push(entryRelative);
  }
  return files;
}

/** Collects `_schemas/**.json` files (relative to `_schemas/`), or [] when absent. */
function collectSchemaFiles(dir) {
  const schemasDir = path.join(dir, '_schemas');
  if (!fs.existsSync(schemasDir) || !fs.statSync(schemasDir).isDirectory()) return [];
  const files = [];
  const walk = (current, relative) => {
    for (const entry of sortDirEntries(fs.readdirSync(current, { withFileTypes: true }))) {
      const entryRelative = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(path.join(current, entry.name), entryRelative);
      else if (entry.name.endsWith('.json')) files.push(entryRelative);
    }
  };
  walk(schemasDir, '');
  return files;
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
  const schemaFiles = collectSchemaFiles(dir);
  return assembleDirectory({
    files,
    texts: files.map((file) => fs.readFileSync(path.join(dir, file), 'utf8')),
    schemaFiles,
    schemaTexts: schemaFiles.map((file) => fs.readFileSync(path.join(dir, '_schemas', file), 'utf8')),
    codec,
    cerbos,
    drop,
  });
}

/**
 * Stamps `{ policies, derivedRoles }` into a versioned bundle: `version` is
 * the SHA-256 of the canonical (sorted-key) JSON of the content, so the same
 * policies always produce the same version and any change produces a new one.
 * Only SERIALIZED documents can be bundled — live policies contain functions.
 *
 * Pure CPU (no filesystem), so it has no `promises` counterpart.
 *
 * @param {{ policies?: unknown[], derivedRoles?: unknown[] }} input
 * @param {{ createdAt?: string | null }} [options] - ISO timestamp for the stamp (`null` omits it)
 * @returns {Record<string, unknown>}
 */
function createPolicyBundle(input, options = {}) {
  return buildBundle(input, options);
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
  const bundle = ensureBundle(input, options);
  fs.writeFileSync(filePath, serializeBundle(bundle));
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
  if (typeof source !== 'string') return resolveBundle(source, undefined, options);
  let text;
  try {
    text = fs.readFileSync(source, 'utf8');
  } catch (error) {
    fail(`failed to read bundle — ${error.message}`, source);
  }
  return resolveBundle(parseBundleText(text, source), source, options);
}

// ---------------------------------------------------------------------------
// Asynchronous driver (the `promises` namespace) — same shared core; reads
// run concurrently (bounded), results stay in deterministic sorted order.
// ---------------------------------------------------------------------------

async function loadPolicyFileAsync(filePath, options = {}) {
  const { codec, cerbos, drop } = normalizeOptions(options);
  const into = { policies: [], derivedRoles: [] };
  ingestPolicyText(await fsp.readFile(filePath, 'utf8'), filePath, { cerbos, drop }, into);
  return maybeDeserialize(into, codec);
}

async function collectFilesAsync(dir, recursive, relative = '') {
  const entries = sortDirEntries(await fsp.readdir(dir, { withFileTypes: true }));
  // Subdirectories walk concurrently; ordering stays deterministic because
  // results are concatenated in sorted-entry order, not completion order.
  const nested = await Promise.all(
    entries.map(async (entry) => {
      if (skipEntry(entry.name)) return [];
      const entryRelative = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        return recursive ? collectFilesAsync(path.join(dir, entry.name), recursive, entryRelative) : [];
      }
      return POLICY_FILE_RE.test(entry.name) ? [entryRelative] : [];
    }),
  );
  return nested.flat();
}

async function collectSchemaFilesAsync(dir) {
  const schemasDir = path.join(dir, '_schemas');
  let stat;
  try {
    stat = await fsp.stat(schemasDir);
  } catch {
    return [];
  }
  if (!stat.isDirectory()) return [];
  const walk = async (current, relative) => {
    const entries = sortDirEntries(await fsp.readdir(current, { withFileTypes: true }));
    const nested = await Promise.all(
      entries.map(async (entry) => {
        const entryRelative = relative ? `${relative}/${entry.name}` : entry.name;
        if (entry.isDirectory()) return walk(path.join(current, entry.name), entryRelative);
        return entry.name.endsWith('.json') ? [entryRelative] : [];
      }),
    );
    return nested.flat();
  };
  return walk(schemasDir, '');
}

async function loadPolicyDirectoryAsync(dir, options = {}) {
  const { codec, cerbos, drop, recursive, concurrency } = normalizeOptions(options);
  let stat = null;
  try {
    stat = await fsp.stat(dir);
  } catch {
    // Falls through to the same `not a directory` failure as the sync driver.
  }
  if (!stat?.isDirectory()) fail(`not a directory`, dir);

  const [files, schemaFiles] = await Promise.all([collectFilesAsync(dir, recursive), collectSchemaFilesAsync(dir)]);
  // The whole point of the async driver: file contents stream in concurrently
  // (bounded, to stay clear of fd limits) instead of one blocking read at a
  // time — the win that makes cold starts over large repositories fast.
  const limit = createLimiter(concurrency);
  const [texts, schemaTexts] = await Promise.all([
    Promise.all(files.map((file) => limit(() => fsp.readFile(path.join(dir, file), 'utf8')))),
    Promise.all(schemaFiles.map((file) => limit(() => fsp.readFile(path.join(dir, '_schemas', file), 'utf8')))),
  ]);
  return assembleDirectory({ files, texts, schemaFiles, schemaTexts, codec, cerbos, drop });
}

async function writePolicyBundleAsync(filePath, input, options = {}) {
  const bundle = ensureBundle(input, options);
  await fsp.writeFile(filePath, serializeBundle(bundle));
  return bundle;
}

async function loadPolicyBundleAsync(source, options = {}) {
  if (typeof source !== 'string') return resolveBundle(source, undefined, options);
  let text;
  try {
    text = await fsp.readFile(source, 'utf8');
  } catch (error) {
    fail(`failed to read bundle — ${error.message}`, source);
  }
  return resolveBundle(parseBundleText(text, source), source, options);
}

module.exports = {
  KerberosLoaderError,
  loadPolicyFile,
  loadPolicyDirectory,
  createPolicyBundle,
  writePolicyBundle,
  loadPolicyBundle,
  /**
   * The asynchronous driver, mirroring Node's `fs.promises` idiom: the same
   * function names, returning promises, backed by the same shared core.
   * `createPolicyBundle` is pure CPU and therefore lives only at the top
   * level. `loadPolicyDirectory` here reads files concurrently (bounded by
   * the `concurrency` option, default 64).
   */
  promises: {
    loadPolicyFile: loadPolicyFileAsync,
    loadPolicyDirectory: loadPolicyDirectoryAsync,
    writePolicyBundle: writePolicyBundleAsync,
    loadPolicyBundle: loadPolicyBundleAsync,
  },
};
