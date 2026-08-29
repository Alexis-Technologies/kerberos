# Loading policies from files

The core package never touches the filesystem — policies come from the constructor or a read-only cache. The **Node-only** `@alexify/kerberos/loader` subpath is the boot-time bridge for **policy-as-code repositories**: load a directory of policy files at startup, or bake it into a hash-stamped bundle in CI and ship that.

```js
import { loadPolicyDirectory } from '@alexify/kerberos/loader';
import { Kerberos, createSafeExprCodec } from '@alexify/kerberos';

const codec = createSafeExprCodec({ jsep }); // the usual dynamic-policy setup

const { policies, derivedRoles, schemas } = loadPolicyDirectory('./policies', { codec });
const kerberos = new Kerberos(policies, derivedRoles, {
  ajv,
  schemas: { enforcement: 'reject', definitions: schemas }, // _schemas/ wired in one line
});
```

What `loadPolicyDirectory` does:

- reads every `.json` / `.yaml` / `.yml` under the directory (recursively by default), in **deterministic sorted order**, skipping `_`-prefixed and hidden entries (the Cerbos repo convention);
- routes each document by format: Kerberos serialized JSON is taken as-is; `.yaml` files and JSON documents carrying `apiVersion` go through the [Cerbos importer](/guide/cerbos-import) — one directory can mix both. `cerbos: true` forces the importer, `cerbos: false` disables it (Cerbos-format files then fail loudly);
- loads `_schemas/**.json` into a ref → schema map keyed both as `expense.json` and `cerbos:///expense.json`, ready for the engine's [`schemas.definitions`](/guide/schema-validation#attribute-schemas-cerbos-schemas) option;
- with `codec`, deserializes every document (`{ $expr }` → live functions) so the result plugs straight into the constructor; without it you get the serialized documents (cache- and bundle-ready).

`loadPolicyFile(path, options)` is the single-file variant. Everything is synchronous (boot-time work) and throws a typed `KerberosLoaderError` naming the offending file.

## Versioned bundles (GitOps)

A bundle is one JSON artifact holding the whole policy set, stamped with a **content-addressed version** — the SHA-256 of the canonical (sorted-key) JSON of its documents. The same policies always produce the same version; any change produces a new one; nothing about the stamp is trust-based:

```js
import { loadPolicyDirectory, writePolicyBundle, loadPolicyBundle } from '@alexify/kerberos/loader';

// CI: bake the repo into an artifact.
const content = loadPolicyDirectory('./policies'); // no codec — serialized documents
const bundle = writePolicyBundle('./dist/policies.bundle.json', content);
console.log(bundle.version); // e.g. '9f2c…' — tag the release with it

// Boot: load and VERIFY (a hand-edited, truncated or foreign bundle throws).
const { policies, derivedRoles, version } = loadPolicyBundle('./dist/policies.bundle.json', { codec });
const kerberos = new Kerberos(policies, derivedRoles);
```

The same artifact is one command away: `npx kerberos bundle ./policies --out dist/policies.bundle.json` (add `--reproducible` for byte-stable output). `loadPolicyBundle` recomputes the hash on load (`verify: false` opts out) and accepts either a file path or an already-parsed object — so the same verification works for a bundle fetched from S3 or a database. `createPolicyBundle(content, { createdAt: null })` produces byte-reproducible output for content-addressed storage.

Bundles hold **serialized** documents only (`{ $expr }` descriptors) — trying to bundle deserialized policies (live functions) throws instead of silently producing a hollow artifact.

## Browsers

There is no filesystem in a browser: bundlers substitute a stub whose functions all throw with a clear message. Fetch a bundle over the network instead and hand its `policies` / `derivedRoles` to `deserializePolicy` + the `Kerberos` constructor directly; verify the hash stamp where the loader runs — in CI when the bundle is built, or on the server that serves it.
