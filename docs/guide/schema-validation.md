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
