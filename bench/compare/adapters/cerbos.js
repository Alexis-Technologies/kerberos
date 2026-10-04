/**
 * Cerbos as a sidecar: the pinned PDP image (the version the conformance job
 * uses) on localhost, called through the official gRPC SDK, the faster of its
 * two transports. checkResources sends a whole batch in one request.
 */
module.exports = {
  id: 'cerbos',
  name: 'Cerbos PDP',
  packageName: '@cerbos/grpc',
  variant: 'gRPC SDK, sidecar on localhost',
  runtime: 'service',
  coldStart: false,
  requires: 'cerbos',
  load() {
    return require('@cerbos/grpc');
  },
  setup({ GRPC }, scenario, env) {
    const cerbos = new GRPC(env.KERBEROS_BENCH_CERBOS_GRPC, { tls: false });
    return {
      prepare:
        ({ principal, resource, action }) =>
        () =>
          cerbos.isAllowed({ principal, resource, action }),
      prepareBatch(principal) {
        const resources = scenario.resources.map((resource) => ({ resource, actions: [scenario.action] }));
        return async () => {
          const response = await cerbos.checkResources({ principal, resources });
          const ids = [];
          for (const result of response.results) if (result.isAllowed(scenario.action)) ids.push(result.resource.id);
          return ids;
        };
      },
      close: () => cerbos.close(),
    };
  },
};
