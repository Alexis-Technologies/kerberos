# Exports

The full public surface of the package, by entry point.

## Main entry — `@alexify/kerberos`

| Export | Purpose |
| ------ | ------- |
| `Kerberos` | Main authorization engine. |
| `Effect` | `{ Allow: 'EFFECT_ALLOW', Deny: 'EFFECT_DENY' }` — a frozen const object, [not an `enum`](/guide/typescript#effect-and-plankind-are-const-objects). |
| `ResourcePolicy`, `PrincipalPolicy`, `RolePolicy`, `DerivedRoles` | Policy classes (rarely constructed directly). |
| `Conditions`, `Variables`, `Constants`, `Outputs` | DSL building blocks. |
| `createSafeExprCodec`, `serializePolicy`, `deserializePolicy` | Safe AST codec for [dynamic/stored policies](/guide/caching). |
| `PlanKind` | `{ AlwaysAllowed, AlwaysDenied, Conditional }` — [query plan](/guide/query-plans) filter kinds (const object, not an `enum`). |
| `expandRelationOperands` | Materializes ReBAC `relation` operands of a [query plan](/guide/query-plans) into id filters. |
| `toCerbosQueryPlan` | Converts a plan to the `@cerbos/core` SDK shape for the [official Cerbos ORM adapters](/guide/query-plans#using-the-official-cerbos-orm-adapters). |
| `KerberosValidationError`, `KerberosCacheError`, `KerberosCodecError`, `KerberosExprError`, `KerberosRelationsError` | Typed [error classes](/api/errors). |
| `registerAjvKeywords`, `createAjvAdapter` | [Validation](/guide/schema-validation) helpers. |
| `JsonSchemas`, `TypeBoxSchemas`, `ZodSchemas`, `KerberosJsonSchemas`, `ResourcePolicyJsonSchemas`, `PrincipalPolicyJsonSchemas`, `RolePolicyJsonSchemas`, … | Schema builders for the three backends. |
| `ALL_ACTIONS`, `ALL_ROLES`, `ALL_RESOURCES`, `DEFAULT_VERSION`, `BASE_SCOPE` | Wildcard/default tokens (`'*'`, `'default'`, `''`). |

Type-only exports for [typed authoring](/guide/typescript) (erased at runtime):

| Type | Purpose |
| ---- | ------- |
| `KerberosSchema`, `AnySchema`, `KerberosResourceContract` | Shape of an application authorization schema, and the permissive default. |
| `ResourceKindOf<S>`, `ActionOf<S, K>`, `ResourceAttrOf<S, K>` | Projections of the declared resource kinds. |
| `PrincipalRoleOf<S>`, `PrincipalAttrOf<S>` | Projections of the declared principal. |
| `RequestPrincipal<S>`, `RequestResource<S, K>`, `BaseRequest<S, K>`, `PolicyEvalRequest<S, K>` | Request shapes, including the `{ P, R, V, C }` callback envelope. |
| `KerberosPolicy<S>`, `ResourcePolicySchema<S>`, `PrincipalPolicySchema<S>`, `RolePolicySchema<S>`, `DerivedRolesSchema<S>` | Policy document shapes. |
| `CheckResourcesArgs<S>`, `CheckResourcesEntry<S>`, `CheckResourcesResult<S, E>`, `CheckResourcesResponse<S, E>` | `checkResources` arguments and response. |
| `PlanResourcesArgs<S, K>`, `PlanResourcesResponse<S>`, `PlanFilter`, `PlanExpressionOperand` | `planResources` arguments and response. |

## `@alexify/kerberos/relations`

Opt-in ReBAC — kept out of the main entry so non-ReBAC bundles do not grow:

| Export | Purpose |
| ------ | ------- |
| `RelationResolver` | The built-in [Zanzibar-lite resolver](/guide/relations-resolver) (check / list / lookupSubjects / lookupResources). |
| `RelationSchema` | Compiles the relation-schema DSL standalone (validated schemas reusable across resolvers). |
| `Relations*Schemas`, parse helpers | Schema builders / parsers for the resolver's shapes (three validation backends). |

## `@alexify/kerberos/cerbos`

The [Cerbos policy importer](/guide/cerbos-import) — kept out of the main entry so bundles that never import Cerbos policies do not grow:

| Export | Purpose |
| ------ | ------- |
| `importCerbosPolicies` | Cerbos YAML/JSON documents → `{ policies, derivedRoles }` serialized Kerberos documents. |
| `celToExpr` | Translates one CEL expression into a `$expr`-compatible JavaScript expression string. |
| `parseYamlDocuments` | The zero-dependency YAML-subset parser, standalone. |
| `KerberosImportError` | Typed error for unsupported constructs (carries `line` for YAML errors). |

## `@alexify/kerberos/loader`

Node-only boot-time [file/directory loader + versioned bundles](/guide/policy-loader) (browser bundlers substitute throwing stubs):

| Export | Purpose |
| ------ | ------- |
| `loadPolicyDirectory`, `loadPolicyFile` | Read Kerberos JSON / Cerbos YAML+JSON policy files (+ `_schemas/`) into constructor inputs. |
| `createPolicyBundle`, `writePolicyBundle`, `loadPolicyBundle` | Hash-stamped (SHA-256, content-addressed) policy bundles with load-time integrity verification. |
| `KerberosLoaderError` | Typed error for I/O, format and bundle-integrity failures (carries `file`). |

## `@alexify/kerberos/tests`

Dev/test only — not loaded by the main entry:

| Export | Purpose |
| ------ | ------- |
| `KerberosTest`, `KerberosTests` | Cerbos-style declarative test runner. |
| `PrincipalMock`, `PrincipalsMock`, `ResourceMock`, `ResourcesMock` | Named fixtures for test suites. |
| `*ZodSchemas`, `*JsonSchemas`, `*TypeBoxSchemas` | Schema builders for the test harness. |
