# Where Kerberos.js and Cerbos differ

"Cerbos-compatible" is a claim about the policy model and the decision/plan semantics — not a promise that every Cerbos feature exists here. This file records the gaps deliberately, so that a conformance failure can be told apart from a known difference.

Each entry says how it is enforced: **corpus** (a test would fail if it changed), **loader** (`lib/load.js` throws rather than mistranslating), or **documented** (not machine-checked yet).

## Expression language

|                 |                                                                                                                                               |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **Cerbos**      | CEL, with Cerbos extension functions (`hierarchy`, `hasIntersection`, `spiffeID`, …), macros (`exists`, `all`), `timestamp()` / `duration()`. |
| **Kerberos**    | JavaScript expressions — either live functions, or `{ $expr }` strings parsed by jsep and walked by an eval-free allowlist interpreter.       |
| **Enforcement** | loader — anything outside the shared subset throws `ConformanceUnsupportedError`.                                                             |

This is the largest and most deliberate difference. The conformance corpus is restricted to the intersection (see [README](./README.md#the-shared-expression-subset)); it is not evidence that arbitrary Cerbos policies port over. The `@alexify/kerberos/cerbos` subpath ships a real CEL→`$expr` importer for the translatable subset (macros, `matches()` and extension functions still throw — see the "Importing Cerbos policies" guide), and `importer.test.js` re-runs this whole suite through it.

#### Relational operators are strict, like CEL

`<`, `<=`, `>` and `>=` would otherwise inherit JavaScript's coercion, which **widens access** whenever an attribute arrives with the wrong type (`"500" < 1000`, `null < 1000`, `[999] < 1000` and `true >= 1` are all `true` in JavaScript). Since v4.2 the interpreter compares like CEL instead — two numbers, two strings or two booleans — and throws `KerberosExprError` for anything else, which the engine then treats like any other condition runtime error (see below). Verified pair by pair against a live 0.55.0 PDP:

| operands                                                                     | CEL                       | `$expr` (default)    | `$expr` with `relational: 'js'` |
| ---------------------------------------------------------------------------- | ------------------------- | -------------------- | ------------------------------- |
| number ↔ number (`int`/`double` mixed)                                       | compares                  | compares             | compares                        |
| string ↔ string                                                              | compares (lexicographic)  | compares             | compares                        |
| bool ↔ bool                                                                  | compares (`false < true`) | compares             | compares                        |
| string ↔ number, null ↔ anything, list ↔ number, map ↔ number, bool ↔ number | error → rule skipped      | error → fails closed | coerces (JavaScript)            |
| a MISSING attribute (`undefined`)                                            | error → rule skipped      | `false`              | `false`                         |

A missing attribute is deliberately not an error here: CEL raises "no such key" and Cerbos skips the rule, while `undefined < 3` and `undefined >= 3` are both `false` — the rule goes unsatisfied either way, so the decision matches without a new error class (and `planResources`, where `P` is fully known, still folds instead of failing).

Still different, by design: `==` / `!=` never raise in CEL (heterogeneous equality is simply `false`) and never raise here either, and arithmetic (`+` on a string and a number) still follows JavaScript. Pass `createSafeExprCodec({ jsep, relational: 'js' })` to restore the old behaviour for every expression a codec compiles.

`planResources` inherits this: when a wrongly-typed value is already known at plan time (a principal attribute, say), the comparison folds and raises, so the call fails — or returns `KIND_ALWAYS_DENIED` under `onError: 'deny'` — where Cerbos emits a filter instead (often `KIND_ALWAYS_DENIED` too, sometimes a condition that can never hold). The decision the plan stands for is the same; only the shape differs.

_Enforcement: corpus (`suites/relational_types_test.yaml`) + `test/RelationalSemantics.test.js`._

## Not implemented

| Cerbos feature                                                                  | Status                                                                                                                                   | Enforcement |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| **`scopePermissions`** (`REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS`)                  | Not implemented. Kerberos implements only the `OVERRIDE_PARENT` behaviour: the first policy in the scope chain to decide an action wins. | loader      |
| **`exportVariables` / `exportConstants`** (imported variable and constant sets) | Not implemented. Variables and constants are policy-scoped only.                                                                         | loader      |
| **`auxData`** (JWT claims in conditions)                                        | Not implemented. Put the claims you need into `principal.attr` before calling.                                                           | documented  |
| **Globals** (`G`) and `engine.globals`                                          | Not implemented. Use policy constants (`C`).                                                                                             | documented  |
| **Admin API, policy storage drivers, PDP server**                               | Out of scope by design — Kerberos is a library. Policies come from the constructor or a read-only cache.                                 | documented  |

## Behavioural differences

### Scope search is always lenient

Cerbos's `engine.lenientScopeSearch` defaults to `false`, which makes a request naming a scope with no matching policy an error, and it requires the scope chain to have no gaps (if `a.b.c` exists, so must `a.b`, `a` and `""`).

Kerberos always walks the chain and falls through to whatever it finds, with no gap requirement. Run the conformance PDP with `--set=engine.lenientScopeSearch=true` (as CI does) to compare like for like.

_Enforcement: documented._

### Attribute schemas — same semantics, different wiring

Implemented since v4: resource policies declare `schemas.principalSchema` / `resourceSchema` refs with `ignoreWhen.actions`, and validation failures surface as Cerbos-shaped `validationErrors` (`{ path, message, source }`); `reject` denies every action, `warn` only reports. The wiring differs by design: Cerbos resolves refs against schema _files_ served from `_schemas/` and picks the level in server config (`schema.enforcement`, default `none`); Kerberos maps refs to validators via the `schemas` engine option (`definitions` accepts JSON Schema / Zod / functions; `enforcement` defaults to `reject` **when the option is set**, and to inert when it is not — matching Cerbos's unconfigured default). The conformance corpus does not carry schemas (the PDP leg would need the files served), so parity is pinned by unit tests (`test/AttributeSchemas.test.js`) mirroring Cerbos's documented behaviour, not by the live-PDP leg.

_Enforcement: documented (unit tests only)._

### Role-policy scope: Cerbos's docs and engine disagree — we follow the engine

Cerbos's role-policies page calls the `scope` field an "optional **principal** scope", but its rule table places role-policy rows in the resource pass (`PolicyKind: KIND_RESOURCE`), matched against the **resource** scope chain and the resource `policyVersion`. A live 0.55.0 PDP confirms the source. With `RT@acme` allowlisting only `other` and `RT@base` allowlisting `ping`:

| request                                    | Cerbos                                                    |
| ------------------------------------------ | --------------------------------------------------------- |
| `principal.scope: acme`, resource unscoped | `ping` = `ALLOW` — the acme role policy did **not** apply |
| principal unscoped, `resource.scope: acme` | `ping` = `DENY` — the acme role policy **did** apply      |

Kerberos follows the observable engine behaviour.

_Enforcement: corpus (`suites/scope_walk_test.yaml`, both directions)._

### Principal-policy version: a Cerbos 0.41+ regression — we follow the API and the docs

A request names two versions, `principal.policyVersion` and `resource.policyVersion`. Cerbos 0.55 selects PRINCIPAL policies with the **resource's**. Its `internal/ruletable/check.go` computes the principal's version and then never passes it to the lookup:

```go
principalVersion := input.Principal.PolicyVersion
if principalVersion == "" {
    principalVersion = evalParams.DefaultPolicyVersion
}
…
bindings = rt.idx.Query(resourceVersion, sanitizedResource, scope, action, parentRoles, pt, pid, bindings[:0])
```

`principalVersion` survives only in a `ScopedPrincipalExists` check; `pt` is `KIND_PRINCIPAL` here, yet the query still receives `resourceVersion`. The same code stands on `main`. Before the rule-table rewrite, 0.40.0 used the principal's version (`internal/engine/engine.go`: `engine.policyAttr(input.Principal.Id, input.Principal.PolicyVersion, input.Principal.Scope, eparams)`), which is also what Cerbos's documentation and its request shape describe. We read that as an unintended regression, so Kerberos keeps the documented behaviour.

Verified on 0.55.0 with `principal.vera.vdefault` allowing `grant` and `principal.vera.vv2` allowing `escalate`:

| `principal.policyVersion` | `resource.policyVersion` | Cerbos             | Kerberos           |
| ------------------------- | ------------------------ | ------------------ | ------------------ |
| `v2`                      | (default)                | `grant` = ALLOW    | `escalate` = ALLOW |
| (default)                 | `v2`                     | `escalate` = ALLOW | `grant` = ALLOW    |
| same on both sides        | same on both sides       | agree              | agree              |

Note the asymmetry this leaves in Kerberos, which is deliberate: principal policies follow the principal's version and scope, while role policies follow the **resource's** (the entry above). Running the same policies through both engines? Send the same value in both fields and the two agree.

_Enforcement: corpus (`suites/principal_version_test.yaml`, both directions, recorded via `cerbosActions`)._

### Wildcard subset

Cerbos compiles patterns with gobwas/glob (`:` separator; a bare `*` is rewritten to `**`), which also accepts `?`, `[...]` and `{a,b}` forms its docs never mention. Kerberos implements exactly the documented subset — bare `*`, segment-scoped `*`, and `**` — and treats anything fancier as literal text. Partial globs in the `roles` field and in `parentRoles` are docs-silent in Cerbos but engine-supported; Kerberos matches the engine (pinned in `suites/wildcards_test.yaml`).

_Enforcement: corpus + `test/Matching.test.js`._

#### Resource kinds are sanitized before any pattern runs

A pattern is only half of a kind comparison. Cerbos passes resource KIND names through `namer.SanitizedResource` (`internal/namer/namer.go`) on both sides — the `resource` field of resource/principal/role policies, and the request's `resource.kind`. For a name matching its legacy shape (`^[[:alpha:]][[:word:]@.\-/]*(:[[:alpha:]][[:word:]@.\-/]*)*$`) every run of `[^\w.]` becomes `_`; other names pass through untouched. Kerberos mirrors this exactly (`sanitizeResourceKind` in `src/matching.js`). Verified on 0.55.0:

| policy field | request kind    | matches | why                                                            |
| ------------ | --------------- | ------- | -------------------------------------------------------------- |
| `gk*`        | `gka:b`, `gk:x` | yes     | the kind is `gka_b` / `gk_x` by the time the glob runs         |
| `doc:*`      | `doc:x`         | **no**  | a pattern with `*` is not sanitized, and no kind keeps its `:` |
| `ka-b`       | `ka_b`, `ka/b`  | yes     | all three are the kind `ka_b`                                  |
| `1a:b`       | `1a_b`          | no      | leading digit → not a legacy-shaped name → no sanitization     |
| `UP-x`       | `up-x`          | no      | matching stays case-sensitive                                  |

Two consequences worth knowing: `resource: 'doc:*'` in a principal or role policy is dead weight in both engines, and two resource policies whose kinds differ only in separators are the same policy — Cerbos rejects them at compile time (`duplicate definition of resource.a_b.vdefault`) and Kerberos throws `Duplicate resource policy` at construction.

Not sanitized on the lookup path, in either engine: principal ids and role names (a role policy for `R-G` does not constrain the role `R_G`).

_Enforcement: corpus (`suites/kind_sanitize_test.yaml`) + `test/Matching.test.js`, `test/KindSanitization.test.js`._

### Condition runtime errors — Cerbos skips the rule, Kerberos fails closed

Verified on 0.55.0 with a DENY rule whose condition raises at runtime (`R.attr.missing.deep`, a CEL "no such key" and a JS `TypeError` respectively), over a resource policy that otherwise allows the action:

|              | default config                                | `strictEvaluation: true` |
| ------------ | --------------------------------------------- | ------------------------ |
| **Cerbos**   | `EFFECT_ALLOW` — the erroring rule is skipped | `EFFECT_DENY`            |
| **Kerberos** | `EFFECT_DENY`                                 | n/a                      |

Cerbos's engine page documents this and warns about it in as many words: the expression is _"treated as not satisfied and the evaluation carries on"_, so _"an `EFFECT_DENY` rule could be silently skipped"_. Its **conditions page contradicts this**, claiming that from v0.55 a DENY rule whose condition errors fails closed — the engine page and the v0.55.0 source are right, and the observed behaviour matches them.

A wrongly-typed operand in a relational comparison reaches this same class: CEL raises, so Cerbos skips the rule, while Kerberos raises and fails closed. Both engines therefore deny an ALLOW rule gated on such a comparison (pinned in `suites/relational_types_test.yaml`); only a DENY rule shows the difference described here.

Kerberos has no per-rule skip-on-error mode. The error surfaces through the request-level `onError` option (`'throw'` propagates it, `'deny'` fails closed), and inside a `checkResources` batch a rejected resource is isolated to a fail-closed `EFFECT_DENY` carrying `reason: 'evaluation-error'`. The divergence is therefore in the safe direction, but it is a real difference in decisions.

_Enforcement: corpus (`suites/conderr_test.yaml`, recorded via `cerbosActions`)._

### Plan operators

Kerberos emits two operators Cerbos has no counterpart for:

- `opaque` — a condition that could not be planned statically, so the caller must post-filter. Cerbos has no equivalent because CEL residuals are expressed differently.
- `relation` — a ReBAC dependency, materialized by `expandRelationOperands`.

Conversely, Cerbos passes through _any_ CEL function name as an operator (`contains`, `startsWith`, `hasIntersection`, …), so its operator vocabulary is open-ended rather than a fixed set.

_Enforcement: corpus — `lib/canonical.js` fails a comparison whose plan contains a Kerberos-only operator instead of silently comparing it._

### Filters are compared after canonicalization

Neither engine promises an operand order — Cerbos emits comparison operands in source order, and the two engines flatten and dedupe `and` / `or` children by their own rules. Filters are therefore compared after sorting the children of `and` / `or` and the two operands of `eq` / `ne`. Nothing else is reordered.

This is a difference in _representation_, not in meaning, but it means a byte-for-byte plan comparison against Cerbos will fail and should not be attempted.

_Enforcement: corpus._

### Conflict resolution across roles — aligned in v4

Recorded here because it is the reason this suite exists, and because it changes decisions for anyone upgrading.

Kerberos used to be **deny-overrides unconditionally**: any matching DENY won, whatever role it targeted. Cerbos >= 0.41 is **deny-overrides _within_ a principal role, allow-overrides _across_ roles** — its evaluation loop runs once per role and returns the first role that independently allows, which is deliberate anti-lockout behaviour so that holding an extra, less privileged role cannot take away access another role grants.

Kerberos now implements the Cerbos rule. A DENY only bites when it covers the role carrying the ALLOW — which a wildcard (`roles: ['*']`) always does, and an enumerated role does explicitly. Derived roles are not a dimension of their own: they collapse into the principal roles listed in their `parentRoles`.

Two traps found while establishing this, worth knowing if you ever re-verify:

- **The behaviour changed in Cerbos 0.41.0** (0.40.0 returns DENY), coinciding with the rule-table engine rewrite. Cerbos's own docs lagged the code until 0.52.0 and the change was not listed as breaking.
- **`ghcr.io/cerbos/cerbos:latest` is stale and serves 0.40.0.** A parity check against `latest` validates the _old_ semantics and hides this entirely, which is why CI pins an explicit version.

_Enforcement: corpus (`suites/ticket_test.yaml`, all four combinations), plus `test/ConflictResolution.test.js` and the multi-role principals in `test/PlanParity.test.js`._

## Documentation audit (Cerbos 0.55.0)

The semantics implemented here were verified two ways: empirically against a live `ghcr.io/cerbos/cerbos:0.55.0` PDP (the conformance suites), and against Cerbos's documentation plus its v0.55.0 source. The doc audit confirmed, with citations:

1. per-role conflict resolution (deny within a role, allow across roles, order-independent) — evaluation page + `internal/ruletable/check.go`;
2. derived-role rules collapsing into their `parentRoles` — `internal/ruletable/ruletable.go` ("merge derived roles as roles");
3. role policies as a non-granting narrowing constraint requiring a resource policy — role-policies page, verbatim;
4. union across the principal's roles — by composition of (1) and per-role narrowing;
5. strictly per-role "no role policy = unrestricted" — `appendRolePolicyDenies` (the cross-bucket case is pinned in `scope_walk_test.yaml`);
6. principal-policy decisions being final — evaluation page, verbatim;
7. `parentRoles` intersection along the chain — role-policies page + recursive closure in the source.

Where the docs and the engine disagree (role-policy scope source; the conditions page's 0.55 fail-closed claim), the engine wins and the disagreement is recorded above.
