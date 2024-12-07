import { z } from 'zod';

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import { ResourceMock, ResourcesMock, PrincipalMock, PrincipalsMock } from './Mocks/index.js';
import { Effect } from '../schemas.js';
import { Kerberos } from '../Kerberos.js';

const KerberosTestInputSchema = z
  .object({
    principals: z.union([z.array(z.string()).nonempty(), z.instanceof(PrincipalsMock)]),
    resources: z.union([z.array(z.string()).nonempty(), z.instanceof(ResourcesMock)]),
    actions: z
      .array(z.string())
      .nonempty()
      .transform((actions) => new Set(actions)),
  })
  .strict();

const KerberosTestExpectedItemSchema = z
  .object({
    principal: z.union([z.string(), z.instanceof(PrincipalMock)]),
    resource: z.union([z.string(), z.instanceof(ResourceMock)]),
    actions: z.record(z.string(), z.union([z.nativeEnum(Effect), z.boolean()])),
  })
  .strict();

export const KerberosTestSchema = z
  .object({
    name: z.string(),
    input: KerberosTestInputSchema,
    expected: z.array(KerberosTestExpectedItemSchema).nonempty(),
  })
  .strict()
  .superRefine(({ input, expected }, ctx) => {
    const inputActions = input.actions;
    for (const item of expected) {
      const expectedActions = new Set(Object.keys(item.actions));
      for (const action of expectedActions) {
        if (!inputActions.has(action)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['expected', 'actions'],
            message: `Action "${action}" in expected is not present in input actions`,
          });
        }
      }
    }
  });

export class KerberosTest {
  constructor(schema, kerberos) {
    this.schema = KerberosTestSchema.parse(schema);
    if (kerberos && !(kerberos instanceof Kerberos)) throw new Error('Invalid Kerberos instance!');
    this.kerberos = kerberos;
    this.principals = this.schema.input.principals instanceof PrincipalsMock ? [this.schema.input.principals] : [];
    this.resources = this.schema.input.resources instanceof ResourcesMock ? [this.schema.input.resources] : [];
  }

  run({ kerberos, principals, resources, effectAsBoolean = false }) {
    describe(this.schema.name, () => {
      if (kerberos && !(kerberos instanceof Kerberos)) throw new Error('Invalid Kerberos instance!');
      if (principals && principals?.some((p) => !(p instanceof PrincipalsMock))) {
        throw new Error('Invalid PrincipalsMock instance!');
      }
      if (resources && resources?.some((r) => !(r instanceof ResourcesMock))) {
        throw new Error('Invalid ResourcesMock instance!');
      }

      const kerberosInstance = this.kerberos || kerberos;
      if (!kerberosInstance) throw new Error('Kerberos instance is required!');

      const allPrincipalsMock = new PrincipalsMock([
        ...(principals?.flatMap((p) => p.mocks) || []),
        ...this.principals.flatMap((p) => p.mocks),
      ]);
      const allResourcesMock = new ResourcesMock([
        ...(resources?.flatMap((r) => r.mocks) || []),
        ...this.resources.flatMap((r) => r.mocks),
      ]);

      const principalsMap = new Map(allPrincipalsMock.mocks.map((p) => [p.name, p]));
      const resourcesMap = new Map(allResourcesMock.mocks.map((r) => [r.name, r]));

      // Group expected results by principals
      const expectedByPrincipal = new Map();
      for (const expectedItem of this.schema.expected) {
        const principalName =
          expectedItem.principal instanceof PrincipalMock ? expectedItem.principal.name : expectedItem.principal;
        const resourceName =
          expectedItem.resource instanceof ResourceMock ? expectedItem.resource.name : expectedItem.resource;

        const principal = principalsMap.get(principalName);
        const resource = resourcesMap.get(resourceName);

        if (!principal) {
          throw new Error(`Principal "${principalName}" not found!`);
        }
        if (!resource) {
          throw new Error(`Resource "${resourceName}" not found!`);
        }

        if (!expectedByPrincipal.has(principalName)) {
          expectedByPrincipal.set(principalName, {
            principal,
            resources: new Map(),
          });
        }

        const principalData = expectedByPrincipal.get(principalName);

        // Add resource and actions to the principal's resources map
        if (!principalData.resources.has(resourceName)) {
          principalData.resources.set(resourceName, {
            resource,
            actions: new Set(),
            expectedActions: {},
          });
        }

        const resourceData = principalData.resources.get(resourceName);
        for (const [action, effect] of Object.entries(expectedItem.actions)) {
          resourceData.actions.add(action);
          resourceData.expectedActions[action] = effect;
        }
      }

      // For each principal, call checkResources once with all resources
      for (const [principalName, principalData] of expectedByPrincipal.entries()) {
        const { principal, resources: principalResourcesMap } = principalData;

        it(`should match expected actions for principal "${principalName}"`, () => {
          const resourcesToCheck = [];
          for (const resourceData of principalResourcesMap.values()) {
            resourcesToCheck.push({
              resource: resourceData.resource,
              actions: Array.from(resourceData.actions),
            });
          }

          const { results } = kerberosInstance.checkResources(
            {
              principal,
              resources: resourcesToCheck,
            },
            effectAsBoolean
          );

          // Check results
          for (const result of results) {
            const resource = allResourcesMock.getById(result.resource.id);
            if (!resource) {
              throw new Error(`Resource with ID "${result.resource.id}" not found!`);
            }
            const resourceName = resource.name;
            const resourceData = principalResourcesMap.get(resourceName);

            for (const [action, expectedEffect] of Object.entries(resourceData.expectedActions)) {
              const effect = result.actions[action];
              assert.ok(
                effect !== undefined,
                `Action "${action}" not found in the checked resources response for resource "${resourceName}"!`
              );
              assert.strictEqual(
                effect,
                expectedEffect,
                `Action "${action}" effect for resource "${resourceName}" is not matched! Expected: ${expectedEffect} but got: ${effect}`
              );
            }
          }
        });
      }
    });
  }
}
