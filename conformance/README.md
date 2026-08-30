# Cerbos conformance suite

Kerberos.js claims to be Cerbos-compatible. This directory turns that claim into a check.

One corpus of policies and expectations is executed by **both** engines:

- always against Kerberos, from the recorded expectations — no Docker, no network, runs anywhere;
- additionally against a **real Cerbos PDP** when `CERBOS_URL` is set, which CI does. That second leg matters: without it a wrong expectation could make the two engines look compatible when neither matches Cerbos.

`test/PlanParity.test.js` proves Kerberos's runtime and planner agree with _each other_. This suite is the other half — that both agree with _Cerbos_.

## Running it

```bash
pnpm test:conformance
```

Against a live PDP:

```bash
docker run --rm -d --name cerbos -p 3592:3592 \
  -v "$PWD/conformance/policies:/policies:ro" \
  ghcr.io/cerbos/cerbos:0.55.0 server \
  --set=storage.disk.directory=/policies \
  --set=engine.lenientScopeSearch=true

CERBOS_URL=http://localhost:3592 pnpm test:conformance
```

Because the corpus is written in Cerbos's own formats, the policies can also be checked by Cerbos directly:

```bash
docker run --rm -v "$PWD/conformance/policies:/policies:ro" \
  ghcr.io/cerbos/cerbos:0.55.0 compile --skip-tests /policies
```

## Layout

| Path                 | What it is                                                                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `policies/*.yaml`    | The shared corpus, in Cerbos policy format (`apiVersion: api.cerbos.dev/v1`). Served verbatim to a real PDP.                   |
| `suites/*_test.yaml` | Decision expectations, in Cerbos's [`TestSuite`](https://api.cerbos.dev/latest/cerbos/policy/v1/TestSuite.schema.json) format. |
| `suites/*_plan.yaml` | Query-plan expectations, shaped after Cerbos's internal `QueryPlannerTestSuite` golden files.                                  |
| `importer.test.js`   | Re-runs every suite against an engine built via the public `/cerbos` importer (real YAML parsing + CEL translation).           |
| `lib/load.js`        | Maps Cerbos policy documents onto Kerberos policies (test-harness structural mapper, not the importer).                        |
| `lib/suite.js`       | Expands suite fixtures into flat cases.                                                                                        |
| `lib/canonical.js`   | Canonicalizes plan filters before comparison.                                                                                  |
| `lib/pdp.js`         | Live-PDP HTTP client.                                                                                                          |
| `DIVERGENCES.md`     | Where the two engines genuinely differ, and why.                                                                               |

## The shared expression subset

Cerbos conditions are **CEL**; Kerberos conditions are JavaScript expressions parsed by jsep and walked by an allowlist interpreter. There is deliberately no CEL parser in this harness — the real importer lives in the package, on the [`@alexify/kerberos/cerbos` subpath](../docs/guide/cerbos-import.md), and `importer.test.js` re-runs every suite through it so the two loading paths cannot drift.

Instead the corpus is restricted to expressions that are **simultaneously valid CEL and valid Kerberos `$expr`**, so one source string feeds both engines unchanged:

```yaml
condition:
  match:
    expr: R.attr.ownerId == P.id
```

That intersection covers `P` / `R` / `V` / `C` member access, string and number literals, `== != < <= > >=`, `&& || !`, and the ternary. It does **not** cover CEL macros (`exists`, `all`), `in`, `timestamp()` / `duration()`, or any CEL extension function — those are deliberately out of the corpus rather than silently mistranslated.

`lib/load.js` is a structural mapper, and it **refuses to guess**: any construct outside the supported subset throws `ConformanceUnsupportedError` instead of being dropped. A skipped rule would turn a real conformance failure into a false pass, which is the one outcome this suite must never produce.

## Adding a case

1. Put the policy in `policies/` using Cerbos document format and the shared expression subset.
2. Add expectations to a `suites/*_test.yaml` (decisions) or `suites/*_plan.yaml` (plans).
3. Run `pnpm test:conformance`. If it disagrees with Kerberos, decide which is wrong — the corpus or the engine — and if it turns out to be a genuine semantic difference, record it in [`DIVERGENCES.md`](./DIVERGENCES.md) rather than bending the expectation to match.

Plan filters are compared after canonicalization, because neither engine promises an operand order: `and` / `or` children and the two operands of `eq` / `ne` are sorted by a stable serialization. Nothing else is reordered. A plan containing Kerberos's own `opaque` or `relation` operands has no Cerbos counterpart and fails the scope check rather than being silently compared.

This directory is not published to npm — `package.json`'s `files` field is an explicit allowlist.
