/**
 * Browser counterpart of `@alexify/kerberos/loader`. The loader reads policy
 * files and directories from a filesystem, which browsers do not have — every
 * function throws with the same message so a bundled call site fails loudly
 * and immediately instead of half-working.
 *
 * In the browser, load policies over the network (fetch a bundle created by
 * `createPolicyBundle` at build time) and hand the parsed documents to
 * `deserializePolicy` + the `Kerberos` constructor directly.
 */

const { KerberosLoaderError } = require('./errors.js');

function unavailable(name) {
  return () => {
    throw new KerberosLoaderError(
      `${name} is not available in browsers — the /loader subpath needs a filesystem. ` +
        'Fetch a policy bundle over the network instead and deserialize its documents directly.',
    );
  };
}

module.exports = {
  KerberosLoaderError,
  loadPolicyFile: unavailable('loadPolicyFile'),
  loadPolicyDirectory: unavailable('loadPolicyDirectory'),
  createPolicyBundle: unavailable('createPolicyBundle'),
  writePolicyBundle: unavailable('writePolicyBundle'),
  loadPolicyBundle: unavailable('loadPolicyBundle'),
};
