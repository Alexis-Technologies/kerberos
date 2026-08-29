# Schema Validation

Kerberos.js supports multiple validation backends:

- **Zod** for consumers already using `zod`
- **JSON Schema + Ajv** for standards-based schema validation
- **TypeBox + Ajv** for typed schema builders backed by Ajv

Install only the validation stack you need:

```bash
npm install ajv
npm install @sinclair/typebox ajv
npm install zod
```

## Using Zod

```javascript
import { z } from 'zod';
import { Kerberos } from '@alexify/kerberos';

const kerberos = new Kerberos(policies, derivedRoles, { z });
```

## Using JSON Schema + Ajv

```javascript
import Ajv from 'ajv';
import { Kerberos, registerAjvKeywords } from '@alexify/kerberos';

const ajv = registerAjvKeywords(new Ajv({ strict: false }));
const kerberos = new Kerberos(policies, derivedRoles, { ajv });
```

## Using TypeBox + Ajv

```javascript
import Ajv from 'ajv';
import { Type } from '@sinclair/typebox';
import { Kerberos, registerAjvKeywords } from '@alexify/kerberos';

const ajv = registerAjvKeywords(new Ajv({ strict: false }));
const kerberos = new Kerberos(policies, derivedRoles, {
  ajv,
  typebox: Type,
});
```

## Using Explicit Builders

Kerberos.js also exports first-class schema builders and Ajv adapters if you want to compile validators yourself:

```javascript
import Ajv from 'ajv';
import {
  JsonSchemas,
  KerberosJsonSchemas,
  PrincipalPolicyJsonSchemas,
  ResourcePolicyJsonSchemas,
  createAjvAdapter,
  registerAjvKeywords,
} from '@alexify/kerberos';

const ajv = registerAjvKeywords(new Ajv({ strict: false }));

const requestValidator = createAjvAdapter(ajv, JsonSchemas.buildRequest());
const argsValidator = createAjvAdapter(ajv, KerberosJsonSchemas.buildCheckResourcesArgs());
const resourcePolicyValidator = createAjvAdapter(ajv, ResourcePolicyJsonSchemas.buildShape());
const principalPolicyValidator = createAjvAdapter(ajv, PrincipalPolicyJsonSchemas.buildShape());
```

## Notes About Function Fields

Kerberos policies can contain JavaScript functions in:

- conditions
- variables
- outputs

When using Ajv or TypeBox, Kerberos.js registers custom Ajv keywords so those function-bearing fields can still be validated at runtime. This keeps the DSL usable even though plain JSON Schema doesn't natively understand JavaScript functions.

## Attribute schemas (Cerbos `schemas`)

Conditions read `P.attr` / `R.attr` — and garbage attributes silently flow into them (an undefined comparison quietly denies or allows). Cerbos guards this with per-kind attribute schemas; Kerberos implements the same model:

```javascript
const kerberos = new Kerberos(
  [{
    resourcePolicy: {
      version: 'default',
      resource: 'expense',
      schemas: {
        principalSchema: { ref: 'principal.json' },
        resourceSchema: { ref: 'expense.json', ignoreWhen: { actions: ['create'] } },
      },
      rules: [/* ... */],
    },
  }],
  [],
  {
    ajv: new Ajv({ allErrors: true }),
    schemas: {
      enforcement: 'reject', // 'reject' | 'warn' | 'none'
      definitions: {
        'expense.json': { type: 'object', required: ['amount'], properties: { amount: { type: 'number' } } },
        'principal.json': z.object({ department: z.string() }), // Zod works too
      },
    },
  },
);
```

Semantics (mirroring Cerbos):

- **`reject`** — a request whose attributes fail validation is denied for **every** action (a principal policy cannot rescue it), with the failures reported as `validationErrors: [{ path, message, source: 'SOURCE_PRINCIPAL' | 'SOURCE_RESOURCE' }]` on the `checkResources` result and `reason: 'invalid-attributes'` under `includeMeta`.
- **`warn`** — `validationErrors` are reported (response + audit log) but decisions are unaffected.
- **`none`** / option absent — schema references in policies are inert, matching Cerbos's own default.
- **`ignoreWhen.actions`** (Cerbos globs) skips validation only when **every** requested action matches — one non-matching action in the batch entry re-enables it.
- With scoped policies, the **most specific** policy in the resource scope chain that declares `schemas` wins.
- A policy referencing a ref missing from `definitions` throws `KerberosValidationError` (always — a configuration error never reads as valid *or* invalid).

Definitions may be plain JSON Schema objects (compiled with the engine's `ajv` option), Zod-like schemas (anything with `safeParse`), or validator functions returning error messages. The [Cerbos importer](/guide/cerbos-import) translates `schemas:` blocks verbatim, so an imported policy repo enforces the same rules once you wire its schema files into `definitions`.

