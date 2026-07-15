import {
  Effect,
  Kerberos,
  type KerberosDerivedRoles,
  type KerberosPolicy,
  type KerberosTelemetryApi,
  type KerberosTelemetryOptions,
} from '../index.js';

const policy = {
  resourcePolicy: {
    version: 'default',
    resource: 'report_manager_global_settings',
    importDerivedRoles: ['report_manager_roles'],
    rules: [
      {
        actions: ['read', 'update'],
        effect: Effect.Allow,
        derivedRoles: ['SYSTEM_TENANT_ADMIN'],
      },
    ],
  },
} as const;

// Must compile without assertion:
const _policyCheck: KerberosPolicy = policy;

const derivedRoles = {
  name: 'report_manager_roles',
  definitions: [
    {
      name: 'ADMIN',
      parentRoles: ['admin'],
      condition: { match: () => true },
    },
  ],
} as const;

// Must compile without `as unknown as`:
const _derivedCheck: KerberosDerivedRoles = derivedRoles;

new Kerberos([policy], [derivedRoles]);

// Backward compatibility: mutable policy objects without `as const`
const mutablePolicy: KerberosPolicy = {
  resourcePolicy: {
    version: 'default',
    resource: 'expense',
    rules: [
      {
        actions: ['view'],
        effect: Effect.Allow,
        roles: ['USER'],
      },
    ],
  },
};

const mutableDerivedRoles: KerberosDerivedRoles = {
  name: 'common_roles',
  definitions: [
    {
      name: 'ADMIN',
      parentRoles: ['admin'],
      condition: { match: () => true },
    },
  ],
};

new Kerberos([mutablePolicy], [mutableDerivedRoles]);

// telemetry option accepts the api-module shape and the instances shape
declare const otelApi: KerberosTelemetryApi;
const telemetryApiMode: KerberosTelemetryOptions = { api: otelApi, includeIdentity: false };
const telemetryInstancesMode: KerberosTelemetryOptions = {
  tracer: { startSpan: (name: string) => ({ end: () => {} }) },
  meter: {
    createCounter: () => ({ add: () => {} }),
    createHistogram: () => ({ record: () => {} }),
  },
};
new Kerberos([mutablePolicy], [mutableDerivedRoles], { telemetry: telemetryApiMode });
new Kerberos([mutablePolicy], [mutableDerivedRoles], { telemetry: telemetryInstancesMode });

// isAllowed accepts optional reqId
declare const kerberos: Kerberos;
kerberos.isAllowed({
  reqId: 'correlation-id',
  principal: { id: 'user1', roles: ['USER'] },
  action: 'read',
  resource: { id: 'doc1', kind: 'document' },
});
