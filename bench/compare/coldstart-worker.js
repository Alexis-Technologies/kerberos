/**
 * Cold start of ONE library in a fresh process: loading the library, building
 * the ownership-scenario policy, and the first decision. The adapter and
 * scenario modules are loaded before the clock starts, so only the library's
 * own cost is measured. process.hrtime, not performance.now(): loading
 * node:perf_hooks would hide what a library itself pays for it.
 *
 * Usage (spawned by bench/compare.js): node bench/compare/coldstart-worker.js <adapter>
 */
const { getAdapter } = require('./adapters/index.js');
const { getScenario } = require('./scenarios.js');

const now = () => Number(process.hrtime.bigint()) / 1e6;

async function main() {
  const adapter = getAdapter(process.argv[2]);
  const scenario = getScenario('abac');

  const t0 = now();
  const lib = adapter.load();
  const t1 = now();
  const impl = await adapter.setup(lib, scenario, process.env);
  const decide = impl.prepare(scenario.allow);
  const t2 = now();
  const decision = await decide();
  const t3 = now();

  if (decision !== true) throw new Error(`expected the first decision to allow, got ${decision}`);
  await impl.close?.();
  process.stdout.write(
    `${JSON.stringify({ load: t1 - t0, setup: t2 - t1, firstDecision: t3 - t2, total: t3 - t0 })}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error?.stack ?? error}\n`);
  process.exitCode = 1;
});
