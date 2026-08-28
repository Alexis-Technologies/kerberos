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

## Not implemented

| Cerbos feature                                                                                 | Status                                                                                                                                                                                    | Enforcement |
| ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| **Attribute schemas** (`schemas:` with `principalSchema` / `resourceSchema`, NONE/WARN/REJECT) | Not implemented. Kerberos validates _policy_ shapes through Zod/Ajv/TypeBox, but does not validate request attributes against a per-kind schema. Garbage attributes flow into conditions. | loader      |
| **`scopePermissions`** (`REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS`)                                 | Not implemented. Kerberos implements only the `OVERRIDE_PARENT` behaviour: the first policy in the scope chain to decide an action wins.                                                  | loader      |
| **`exportVariables` / `exportConstants`** (imported variable and constant sets)                | Not implemented. Variables and constants are policy-scoped only.                                                                                                                          | loader      |
| **`auxData`** (JWT claims in conditions)                                                       | Not implemented. Put the claims you need into `principal.attr` before calling.                                                                                                            | documented  |
| **Globals** (`G`) and `engine.globals`                                                         | Not implemented. Use policy constants (`C`).                                                                                                                                              | documented  |
| **Admin API, policy storage drivers, PDP server**                                              | Out of scope by design — Kerberos is a library. Policies come from the constructor or a read-only cache.                                                                                  | documented  |

## Behavioural differences

### Scope search is always lenient

Cerbos's `engine.lenientScopeSearch` defaults to `false`, which makes a request naming a scope with no matching policy an error, and it requires the scope chain to have no gaps (if `a.b.c` exists, so must `a.b`, `a` and `""`).

Kerberos always walks the chain and falls through to whatever it finds, with no gap requirement. Run the conformance PDP with `--set=engine.lenientScopeSearch=true` (as CI does) to compare like for like.

_Enforcement: documented._

### Role-policy scope: Cerbos's docs and engine disagree — we follow the engine

Cerbos's role-policies page calls the `scope` field an "optional **principal** scope", but its rule table places role-policy rows in the resource pass (`PolicyKind: KIND_RESOURCE`), matched against the **resource** scope chain and the resource `policyVersion`. A live 0.55.0 PDP confirms the source. With `RT@acme` allowlisting only `other` and `RT@base` allowlisting `ping`:

| request                                    | Cerbos                                                    |
| ------------------------------------------ | --------------------------------------------------------- |
| `principal.scope: acme`, resource unscoped | `ping` = `ALLOW` — the acme role policy did **not** apply |
| principal unscoped, `resource.scope: acme` | `ping` = `DENY` — the acme role policy **did** apply      |

Kerberos follows the observable engine behaviour.

_Enforcement: corpus (`suites/scope_walk_test.yaml`, both directions)._

### Wildcard subset

Cerbos compiles patterns with gobwas/glob (`:` separator; a bare `*` is rewritten to `**`), which also accepts `?`, `[...]` and `{a,b}` forms its docs never mention. Kerberos implements exactly the documented subset — bare `*`, segment-scoped `*`, and `**` — and treats anything fancier as literal text. Partial globs in the `roles` field and in `parentRoles` are docs-silent in Cerbos but engine-supported; Kerberos matches the engine (pinned in `suites/wildcards_test.yaml`).

_Enforcement: corpus + `test/Matching.test.js`._

### Condition runtime errors — Cerbos skips the rule, Kerberos fails closed

Verified on 0.55.0 with a DENY rule whose condition raises at runtime (`R.attr.missing.deep`, a CEL "no such key" and a JS `TypeError` respectively), over a resource policy that otherwise allows the action:

|              | default config                                | `strictEvaluation: true` |
| ------------ | --------------------------------------------- | ------------------------ |
| **Cerbos**   | `EFFECT_ALLOW` — the erroring rule is skipped | `EFFECT_DENY`            |
| **Kerberos** | `EFFECT_DENY`                                 | n/a                      |

Cerbos's engine page documents this and warns about it in as many words: the expression is _"treated as not satisfied and the evaluation carries on"_, so _"an `EFFECT_DENY` rule could be silently skipped"_. Its **conditions page contradicts this**, claiming that from v0.55 a DENY rule whose condition errors fails closed — the engine page and the v0.55.0 source are right, and the observed behaviour matches them.

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
