# Benchmarks

Measured with the zero-dependency harness in [`bench/bench.js`](https://github.com/Alexis-Technologies/kerberos/blob/main/bench/bench.js) (1s timed run after 2k warmup iterations per scenario). Reproduce with:

```bash
pnpm bench
```

Apple Silicon (M-series), Node v24:

| Scenario |  ops/sec |
| -------- |---------:|
| `isAllowed` — simple role match | ~320,000 |
| `isAllowed` — derived roles + variables + condition | ~300,000 |
| `checkResources` — 10 resources × 3 actions |  ~41,000 |
| `isAllowed` — cache-backed dynamic policy (`$expr`, in-memory Map) | ~150,000 |
| `planResources` — `$expr` policy (variables + deny rule) |  ~60,000 |
| `relations.check` — direct tuple (flat) | ~850,000 |
| `relations.check` — deep walk (3 arrows + nested groups) | ~120,000 |
| `isAllowed` — relation-backed derived role (deep walk) |  ~80,000 |

`checkResources` evaluates resources **concurrently** (`Promise.allSettled`): with a remote policy store, N resources cost one parallel wave of lookups instead of N sequential round-trips (measured ~8x faster with a 2ms-latency cache and 10 resources), and one failing resource never fails the batch — it fail-closes to `EFFECT_DENY` for its actions only.

Numbers vary by hardware and Node version — treat them as relative guidance, not absolutes. The harness exists primarily to catch performance regressions between releases.
