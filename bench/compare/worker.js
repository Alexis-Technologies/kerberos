/**
 * Runs ONE (library, scenario) pair in a fresh process — so no library's
 * JIT feedback, heap or event-loop state leaks into the next — verifies the
 * scenario's expected decisions, then measures. Prints one JSON line.
 *
 * Usage (spawned by bench/compare.js): node bench/compare/worker.js '<json options>'
 */
const { getAdapter } = require('./adapters/index.js');
const { getScenario } = require('./scenarios.js');
const { measure } = require('./measure.js');

function sameIds(actual, expected) {
  const sorted = [...actual].sort();
  const want = [...expected].sort();
  return sorted.length === want.length && sorted.every((id, i) => id === want[i]);
}

async function verify(impl, scenario) {
  if (scenario.type === 'check') {
    const allowed = await impl.prepare(scenario.allow)();
    const denied = await impl.prepare(scenario.deny)();
    if (allowed !== true || denied !== false) {
      throw new Error(`expected allow=true deny=false, got allow=${allowed} deny=${denied}`);
    }
    return;
  }
  for (const expectation of [scenario.allow, scenario.deny]) {
    const ids = await impl.prepareBatch(expectation.principal)();
    if (!sameIds(ids, expectation.expectedIds)) {
      throw new Error(
        `principal ${expectation.principal.id}: expected ${expectation.expectedIds.length} ids, got ${ids.length}`,
      );
    }
  }
}

async function main() {
  const options = JSON.parse(process.argv[2]);
  const adapter = getAdapter(options.adapter);
  const scenario = getScenario(options.scenario);
  const impl = await adapter.setup(adapter.load(), scenario, process.env);
  try {
    await verify(impl, scenario);
    const fn = scenario.type === 'check' ? impl.prepare(scenario.allow) : impl.prepareBatch(scenario.allow.principal);
    const result = await measure(fn, options);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    await impl.close?.();
  }
}

main().catch((error) => {
  process.stderr.write(`${error?.stack ?? error}\n`);
  process.exitCode = 1;
});
