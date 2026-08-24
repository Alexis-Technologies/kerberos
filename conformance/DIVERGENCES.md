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

## Open question: conflict resolution across roles

**Kerberos is deny-overrides, unconditionally.** Verified directly: given a resource policy with an ALLOW rule targeting role `r1` and a DENY rule targeting role `r2`, a principal holding both gets **DENY**, and rule order does not change it. The same holds for an ALLOW and a DENY targeting the same single role.

Cerbos is documented as deny-overrides for resource-policy rules, but is also described in places as having anti-lockout behaviour in which an ALLOW derived from one role wins over a DENY from another. These cannot both be true for the case above, and the difference is exactly the kind that a reimplementation gets wrong silently — every single-role test passes either way.

`suites/ticket_test.yaml` encodes the case as an executable probe with Kerberos's verified behaviour as the expectation. **If the live-PDP leg fails on `a DENY from one role overrides an ALLOW from another`, that is a finding, not a regression:** record the real Cerbos behaviour here and decide whether Kerberos should change, rather than editing the expectation to make the suite green.

_Enforcement: corpus (Kerberos side verified; Cerbos side pending the first live run)._
