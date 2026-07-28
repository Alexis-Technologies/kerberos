# Exports

The full public surface of the package, by entry point.

## Main entry — `@alexify/kerberos`

| Export | Purpose |
| ------ | ------- |
| `Kerberos` | Main authorization engine. |
| `Effect` | `{ Allow: 'EFFECT_ALLOW', Deny: 'EFFECT_DENY' }`. |
| `ResourcePolicy`, `PrincipalPolicy`, `RolePolicy`, `DerivedRoles` | Policy classes (rarely constructed directly). |
| `Conditions`, `Variables`, `Constants`, `Outputs` | DSL building blocks. |
| `createSafeExprCodec`, `serializePolicy`, `deserializePolicy` | Safe AST codec for [dynamic/stored policies](/guide/caching). |
| `PlanKind` | `{ AlwaysAllowed, AlwaysDenied, Conditional }` — [query plan](/guide/query-plans) filter kinds. |
| `expandRelationOperands` | Materializes ReBAC `relation` operands of a [query plan](/guide/query-plans) into id filters. |
| `KerberosValidationError`, `KerberosCacheError`, `KerberosCodecError`, `KerberosExprError`, `KerberosRelationsError` | Typed [error classes](/api/errors). |
| `registerAjvKeywords`, `createAjvAdapter` | [Validation](/guide/schema-validation) helpers. |
| `JsonSchemas`, `TypeBoxSchemas`, `ZodSchemas`, `KerberosJsonSchemas`, `ResourcePolicyJsonSchemas`, `PrincipalPolicyJsonSchemas`, `RolePolicyJsonSchemas`, … | Schema builders for the three backends. |
| `ALL_ACTIONS`, `ALL_ROLES`, `ALL_RESOURCES`, `DEFAULT_VERSION`, `BASE_SCOPE` | Wildcard/default tokens (`'*'`, `'default'`, `''`). |

## `@alexify/kerberos/relations`

Opt-in ReBAC — kept out of the main entry so non-ReBAC bundles do not grow:

| Export | Purpose |
| ------ | ------- |
| `RelationResolver` | The built-in [Zanzibar-lite resolver](/guide/relations-resolver) (check / list / lookupSubjects / lookupResources). |
| `RelationSchema` | Compiles the relation-schema DSL standalone (validated schemas reusable across resolvers). |
| `Relations*Schemas`, parse helpers | Schema builders / parsers for the resolver's shapes (three validation backends). |

## `@alexify/kerberos/tests`

Dev/test only — not loaded by the main entry:

| Export | Purpose |
| ------ | ------- |
| `KerberosTest`, `KerberosTests` | Cerbos-style declarative test runner. |
| `PrincipalMock`, `PrincipalsMock`, `ResourceMock`, `ResourcesMock` | Named fixtures for test suites. |
| `*ZodSchemas`, `*JsonSchemas`, `*TypeBoxSchemas` | Schema builders for the test harness. |
