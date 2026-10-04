/**
 * OPA as a sidecar: the pinned `opa` image serving the same Rego over its
 * REST Data API on localhost. Each call serializes its input, as a real
 * client must; fetch keeps the connection alive.
 */
const { OPA_ENTRYPOINTS } = require('../policies.js');

module.exports = {
  id: 'opa-server',
  name: 'OPA server',
  packageName: null,
  variant: 'REST Data API, sidecar on localhost',
  runtime: 'service',
  coldStart: false,
  requires: 'opa-server',
  load() {
    return globalThis.fetch;
  },
  setup(fetch, scenario, env) {
    const url = `${env.KERBEROS_BENCH_OPA_URL}/v1/data/${OPA_ENTRYPOINTS[scenario.id]}`;
    const query = async (input) => {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ input }),
      });
      if (!response.ok) throw new Error(`OPA answered ${response.status}: ${await response.text()}`);
      return (await response.json()).result;
    };
    return {
      prepare: (request) => async () => (await query(request)) === true,
      prepareBatch(principal) {
        const input = { principal, resources: scenario.resources };
        return async () => (await query(input)) ?? [];
      },
    };
  },
};
