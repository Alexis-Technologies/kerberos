/**
 * OPA compiled to WebAssembly and evaluated in-process with the official
 * @open-policy-agent/opa-wasm SDK. The .wasm module is built by the pinned
 * `opa` image (services.js) and its path arrives in KERBEROS_BENCH_OPA_WASM.
 */
const fs = require('node:fs');
const { OPA_ENTRYPOINTS } = require('../policies.js');

module.exports = {
  id: 'opa-wasm',
  name: 'OPA',
  packageName: '@open-policy-agent/opa-wasm',
  variant: 'Rego compiled to WebAssembly, in-process',
  runtime: 'in-process',
  coldStart: true,
  requires: 'opa-wasm',
  load() {
    return require('@open-policy-agent/opa-wasm');
  },
  async setup({ loadPolicy }, scenario, env) {
    const policy = await loadPolicy(fs.readFileSync(env.KERBEROS_BENCH_OPA_WASM));
    const entrypoint = policy.entrypoints[OPA_ENTRYPOINTS[scenario.id]];
    return {
      prepare: (request) => () => policy.evaluate(request, entrypoint)[0]?.result === true,
      prepareBatch(principal) {
        const input = { principal, resources: scenario.resources };
        return () => policy.evaluate(input, entrypoint)[0]?.result ?? [];
      },
    };
  },
};
