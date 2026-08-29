# Testing

The `@alexify/kerberos/tests` subpath ships a Cerbos-style declarative test runner: principals, resources and expected effects are written as data, then run against a live `Kerberos` instance with `node:test`. Use this rather than hand-rolling policy assertions.

```javascript
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { Kerberos } from '@alexify/kerberos';
import { KerberosTests } from '@alexify/kerberos/tests';

describe('KerberosTests', () => {
  describe('Expense Policy (raw mode)', () => {
    const expenseTestPolicy = {
      name: 'Expenses test suite',
      principals: {
        sally: {
          id: 'sally',
          roles: ['USER'],
          attr: {
            department: 'SALES',
            region: 'EMEA',
          },
        },
        // ...
      },
      resources: {
        expense1: {
          id: 'expense1',
          kind: 'expense',
          attr: {
            ownerId: 'sally',
            createdAt: '2022-07-21T14:47:51.063Z',
            vendor: 'Flux Water Gear',
            region: 'EMEA',
            amount: 500,
            status: 'OPEN',
          },
        },
        // ...
      },
      tests: [
        {
          name: 'Sales Roles',
          input: {
            principals: ['sally', 'sydney'],
            resources: ['expense1', 'expense2'],
            actions: ['view', 'view:approver', 'update', 'delete', 'approve'],
          },
          expected: [
            {
              principal: 'sally',
              resource: 'expense1',
              actions: {
                view: 'EFFECT_ALLOW',
                'view:approver': 'EFFECT_DENY',
                delete: 'EFFECT_DENY',
                update: 'EFFECT_ALLOW',
                approve: 'EFFECT_DENY',
              },
            },
            // ...
          ],
        },
      ],
    };

    const kerberos = new Kerberos(policies, derivedRoles, { logger: true });
    const tests = new KerberosTests(kerberos, [expenseTestPolicy]);

    tests.run({}, { describe, it, assert });
    // or -> tests.run({ effectAsBoolean: true }, { describe, it, assert });
  });
});
```

## Testing with Outputs

You can also test policies with outputs functionality:

```javascript
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { Kerberos, Effect } from '@alexify/kerberos';

describe('Outputs functionality', () => {
  const outputsPolicy = {
    resourcePolicy: {
      version: "default",
      resource: "system_access",
      rules: [
        {
          name: "admin-access",
          actions: ['*'],
          effect: Effect.Allow,
          roles: ['admin'],
          output: {
            when: {
              ruleActivated: ({ P }) => ({
                message: "Admin access granted",
                admin: P.id
              })
            }
          }
        }
      ]
    }
  };

  it('should return outputs when rules are activated', async () => {
    const kerberos = new Kerberos([outputsPolicy]);
    
    const results = await kerberos.checkResources({ 
      principal: { id: "alice", roles: ["admin"] }, 
      resources: [{ resource: { id: "system1", kind: "system_access" }, actions: ['login'] }]
    });

    // Check that we get outputs
    assert.ok(results.results[0].outputs);
    assert.strictEqual(results.results[0].outputs.length, 1);
    
    const output = results.results[0].outputs[0];
    assert.strictEqual(output.src, 'resource.system_access.vdefault#admin-access');
    assert.strictEqual(output.val.message, 'Admin access granted');
    assert.strictEqual(output.val.admin, 'alice');
  });
});
```

## Policy testing from the command line

The package ships a `kerberos` CLI, so a **pure policy repository** — no engineering glue, no hand-written test harness — can test itself in CI:

```bash
npx kerberos test ./policies ./tests
```

- Policies load exactly like [`loadPolicyDirectory`](/guide/policy-loader): Kerberos JSON and Cerbos YAML/JSON mix freely, `{ $expr }` conditions resolve `jsep` (+ the documented plugins) from **your** project.
- Test suites are **Cerbos's own [`TestSuite`](https://api.cerbos.dev/latest/cerbos/policy/v1/TestSuite.schema.json) format** (`*_test.yaml` / `*_test.json`): named principal/resource fixtures plus expected effects per action — reviewable, engine-agnostic artifacts.
- `--schemas reject|warn` wires `_schemas/` into [attribute-schema enforcement](/guide/schema-validation#attribute-schemas-cerbos-schemas); `--json` prints a machine-readable report; the exit code is `1` on any failing case (`2` for usage/config errors).
- The runner refuses to guess: an expectation feature it does not check (e.g. `outputs`) fails the run instead of silently passing.

```bash
npx kerberos bundle ./policies --out dist/policies.bundle.json --reproducible
```

bakes the repo into a [hash-stamped bundle](/guide/policy-loader) for GitOps pipelines.

