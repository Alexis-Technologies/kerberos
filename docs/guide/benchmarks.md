# Benchmarks

Measured with the zero-dependency harness in [`bench/bench.js`](https://github.com/Alexis-Technologies/kerberos/blob/main/bench/bench.js) (1s timed run after up to 2k warmup iterations, at most 0.5 s, per scenario). Reproduce with:

```bash
pnpm bench
```

Apple Silicon (M-series), Node v24:

| Scenario |  ops/sec |
| -------- |---------:|
| `isAllowed` — simple role match |  ~770,000 |
| `isAllowed` — derived roles + variables + condition |  ~600,000 |
| `checkResources` — 10 resources × 3 actions |   ~58,000 |
| `checkResources` — 10 resources, includeMeta |   ~48,000 |
| `isAllowed` — role policy + 2-level parentRoles chain |  ~395,000 |
| `isAllowed` — 3-segment scoped request (chain walk) |  ~580,000 |
| `isAllowed` — simple role match + Zod validation |  ~445,000 |
| `isAllowed` — simple role match + 1 sync `decision` listener |  ~695,000 |
| `isAllowed` — simple role match + request-level hooks |  ~390,000 |
| `isAllowed` — simple role match + per-resource hooks |  ~335,000 |
| `checkResources` — 10 resources × 3 actions + `decision` listener |   ~52,000 |
| `isAllowed` — cache-backed dynamic policy (`$expr`, in-memory Map) |  ~265,000 |
| `checkResources` — 50 resources, cache-backed |    ~8,300 |
| `planResources` — `$expr` policy (variables + deny rule) |   ~63,000 |
| `relations.check` — direct tuple (flat) |  ~720,000 |
| `relations.check` — deep walk (3 arrows + nested groups) |  ~105,000 |
| `isAllowed` — relation-backed derived role (deep walk) |   ~70,000 |

Scaling sweeps (`node bench/bench.js scaling`) — how decision cost grows with policy shape; 4.2.0 → 4.3.0 on the same machine:

| Scenario | 4.2.0 | 4.3.0 |
| -------- | -----:| -----:|
| 1 000 rules, one per action — match first / last | ~31,000 / ~30,000 | ~730,000 / ~740,000 |
| 1 000 rules, one per role — match last | ~27,000 | ~720,000 |
| 64 principal roles, no role policies | ~37,000 | ~133,000 |
| 32 imported derived-role definitions, 1 referenced | ~190,000 | ~625,000 |
| scope depth 8, decided at the most specific scope | ~170,000 | ~278,000 |
| `checkResources` — 100 documents, relation depth 16 (batches/s) | ~330 | ~1,670 |
| 100 concurrent `relations.check`, shared memo, depth 16 (batches/s) | ~380 | ~3,260 |

Cold start (`pnpm bench:coldstart`: `require` + construction + first decision in a fresh process): ~17 ms.

`checkResources` evaluates resources **concurrently** (`Promise.allSettled`): with a remote policy store, N resources cost one parallel wave of lookups instead of N sequential round-trips (measured ~8x faster with a 2ms-latency cache and 10 resources), and one failing resource never fails the batch — it fail-closes to `EFFECT_DENY` for its actions only.

Numbers vary by hardware and Node version — treat them as relative guidance, not absolutes. The harness exists primarily to catch performance regressions between releases.

## Cross-library comparison

The same scenario — role-gated actions plus one ownership condition — implemented in Kerberos, [CASL](https://casl.js.org) and [casbin](https://casbin.org) (`pnpm bench:compare`; Apple Silicon, Node v24):

| Library · path | ops/sec |
| -------------- | -------:|
| `@alexify/kerberos` · `isAllowed` | ~740,000 |
| `@casl/ability` · check (prebuilt ability) | ~7,300,000 |
| `@casl/ability` · build + check (per request) | ~1,300,000 |
| `casbin` · `enforce` (in-memory model) | ~200,000 |

Read it honestly — the libraries do different amounts of work per call. CASL's prebuilt check is a plain in-memory predicate and is faster because it does dramatically less: no policy documents, versions or scopes, no audit/telemetry path, no batch API, no query planner. Abilities are built **per user**, so the *build + check* row is the realistic per-request path. casbin interprets its model DSL on every call. The Kerberos number includes argument validation, the guarded audit/telemetry seams and the scope-chain walk. `@cerbos/embedded` and OPA-WASM are absent by necessity: their policy bundles cannot be built from open tooling alone (Cerbos Hub / the `opa` compiler), so honest numbers cannot be produced here.

Bundle size for the browser, measured the same way as the table above (`pnpm size:compare`, esbuild, min+gzip):

| Library | min+gzip |
| ------- | --------:|
| `@alexify/kerberos` (main entry) | 38.3 KB |
| `@casl/ability` | 6.6 KB |
| `casbin` | 33.9 KB — does not bundle for the browser (Node builtins); measured as a Node bundle |

CASL is the size floor for a reason (it implements far less); casbin does not run in browsers at all.

## Fuzzing

The security-sensitive surfaces — the `$expr` codec (parse + evaluate), the CEL translator's output contract, the YAML subset parser, and `RelationResolver` — are covered by a deterministic, seeded fuzz suite (`test/Fuzz.test.js`) that runs as part of `pnpm test` and can be cranked with `FUZZ_ITERATIONS=100000`. The properties asserted are the contracts: typed errors only, no leaked functions, no prototype pollution, and every expression the translator emits must compile.
