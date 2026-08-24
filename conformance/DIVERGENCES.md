# Where Kerberos.js and Cerbos differ

"Cerbos-compatible" is a claim about the policy model and the decision/plan semantics — not a promise that every Cerbos feature exists here. This file records the gaps deliberately, so that a conformance failure can be told apart from a known difference.

Each entry says how it is enforced: **corpus** (a test would fail if it changed), **loader** (`lib/load.js` throws rather than mistranslating), or **documented** (not machine-checked yet).

## Expression language

|                 |                                                                                                                                               |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **Cerbos**      | CEL, with Cerbos extension functions (`hierarchy`, `hasIntersection`, `spiffeID`, …), macros (`exists`, `all`), `timestamp()` / `duration()`. |
| **Kerberos**    | JavaScript expressions — either live functions, or `{ $expr }` strings parsed by jsep and walked by an eval-free allowlist interpreter.       |
| **Enforcement** | loader — anything outside the shared subset throws `ConformanceUnsupportedError`.                                                             |

This is the largest and most deliberate difference. The conformance corpus is restricted to the intersection (see [README](./README.md#the-shared-expression-subset)); it is not evidence that arbitrary Cerbos policies port over. A CEL→`$expr` importer is tracked separately as a product item, not a bug.

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

## ⚠️ Conflict resolution across roles — a real incompatibility

This is the one place where the two engines return **different decisions for the same policy and the same request**. It is verified against a real Cerbos PDP, not inferred from documentation.

|     | Rule combination                                                             | Kerberos | Cerbos ≥ 0.41 |
| --- | ---------------------------------------------------------------------------- | -------: | ------------: |
| 1   | ALLOW `roles: [SUPPORT]` + DENY `roles: [AUDITOR]`, principal holds **both** |   `DENY` |   **`ALLOW`** |
| 2   | ALLOW `roles: [SUPPORT]` + DENY `roles: ['*']`                               |   `DENY` |        `DENY` |
| 3   | ALLOW `roles: [SUPPORT]` + DENY `roles: [SUPPORT, AUDITOR]`                  |   `DENY` |        `DENY` |
| 4   | ALLOW + conditional DENY, both on the **same** role                          |   `DENY` |        `DENY` |

**Kerberos is deny-overrides, unconditionally.** Any matching DENY wins, regardless of which role it targets or where it sits in the rule list.

**Cerbos is deny-overrides _within_ a role, allow-overrides _across_ roles.** Its evaluation loop runs once per principal role and returns the first role that independently produces an ALLOW; a DENY recorded by an earlier role is overwritten. This is intentional anti-lockout behaviour — the documented rationale is stopping an admin from locking themselves out because they also hold a less privileged role.

Only row 1 diverges. A DENY still wins whenever it **covers the role that carries the ALLOW** — as a wildcard (row 2) or by enumeration (row 3) — which is why the practical blast radius is narrower than it first looks. All four rows are pinned in `suites/ticket_test.yaml`; row 1 carries a `cerbosActions` override recording the other engine's answer, and the runner asserts the two engines still disagree, so this entry cannot go stale unnoticed.

### Direction of risk

Porting Cerbos policies **to** Kerberos fails closed: Kerberos denies some things Cerbos would allow. Nothing leaks; access is lost. Porting the other way is the dangerous direction — a policy set relied upon to deny in Kerberos may allow under Cerbos.

### Two traps worth knowing

- **The behaviour changed in Cerbos 0.41.0**, bisected empirically (0.40.0 returns `DENY`, 0.41.0 returns `ALLOW`), coinciding with the rule-table engine rewrite. Kerberos matches Cerbos ≤ 0.40.
- **`ghcr.io/cerbos/cerbos:latest` is stale and serves 0.40.0.** Benchmarking parity against `latest` validates the _old_ semantics and hides this entirely — which is why CI pins an explicit version. Cerbos's own docs also lagged the code here until 0.52.0, and the change was not listed as breaking.

_Enforcement: corpus, both engines verified against Cerbos 0.55.0._
