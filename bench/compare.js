/**
 * Cross-library comparison: the scenarios in bench/compare/scenarios.js
 * (role check, ownership condition, 1 000 rules, filtering 100 documents),
 * implemented idiomatically in every library under bench/compare/adapters,
 * plus a cold-start comparison. Results land in bench/results/compare.json,
 * which feeds the docs charts and README tables (pnpm bench:report).
 *
 * Run: pnpm bench:compare [--only kerberos,casl] [--scenarios rbac,abac]
 *        [--samples 5] [--sample-ms 1000] [--warmup-ms 1000] [--cold-runs 20]
 *        [--no-docker] [--no-write]
 *
 * Method, also published with the results in docs/guide/benchmarks.md:
 * - every (library, scenario) pair runs in a FRESH process, so no library's
 *   JIT feedback or heap state leaks into the next measurement;
 * - each adapter must reproduce the scenario's expected allow AND deny
 *   decisions before it is timed — a mismatch aborts the run;
 * - the libraries have different feature sets: a scenario is the overlap
 *   they can all express, NOT a claim of equivalence;
 * - CASL builds abilities per user: `casl` times the check against an ability
 *   built once, `casl-per-request` builds it inside the timed call;
 * - OPA and Cerbos run from pinned Docker images (bench/compare/services.js):
 *   OPA once compiled to WebAssembly and evaluated in-process, once as a
 *   server; Cerbos as a PDP sidecar over gRPC. On Docker Desktop the sidecar
 *   round-trip also crosses the VM's network bridge, so it is slower there
 *   than on a Linux host — but a network hop is never free.
 */
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { parseArgs, promisify } = require('node:util');

const { ADAPTERS } = require('./compare/adapters/index.js');
const { SCENARIOS } = require('./compare/scenarios.js');
const { median } = require('./compare/measure.js');
const services = require('./compare/services.js');
const { describeMachine } = require('./machine.js');

const run = promisify(execFile);
const ROOT = path.join(__dirname, '..');
const OUT = path.join(__dirname, 'results', 'compare.json');

const { values: args } = parseArgs({
  options: {
    only: { type: 'string' },
    scenarios: { type: 'string' },
    samples: { type: 'string', default: '5' },
    'sample-ms': { type: 'string', default: '1000' },
    'warmup-ms': { type: 'string', default: '1000' },
    'cold-runs': { type: 'string', default: '20' },
    'no-docker': { type: 'boolean', default: false },
    'no-write': { type: 'boolean', default: false },
  },
});

const list = (value) => (value ? value.split(',').map((item) => item.trim()) : null);
const method = {
  warmupMs: Number(args['warmup-ms']),
  sampleMs: Number(args['sample-ms']),
  samples: Number(args.samples),
  coldStartRuns: Number(args['cold-runs']),
};

function packageVersion(name) {
  const file = name ? path.join(ROOT, 'node_modules', name, 'package.json') : path.join(ROOT, 'package.json');
  return JSON.parse(fs.readFileSync(file, 'utf8')).version;
}

/**
 * `package`/`version` name the npm package the adapter calls (for a sidecar,
 * its client); `image` the pinned Docker image that runs or compiles the engine.
 */
function libraryInfo(adapter) {
  const images = { 'opa-wasm': services.OPA_IMAGE, 'opa-server': services.OPA_IMAGE, cerbos: services.CERBOS_IMAGE };
  const info = {
    id: adapter.id,
    name: adapter.name,
    package: adapter.packageName,
    version: adapter.packageName ? packageVersion(adapter.id === 'kerberos' ? null : adapter.packageName) : null,
    variant: adapter.variant,
    runtime: adapter.runtime,
  };
  if (images[adapter.id]) info.image = images[adapter.id];
  return info;
}

const format = (value) => Math.round(value).toLocaleString('en-US');

async function worker(script, argv, env) {
  try {
    const { stdout } = await run(process.execPath, [path.join(__dirname, 'compare', script), ...argv], {
      env: { ...process.env, ...env },
      maxBuffer: 1 << 20,
    });
    return JSON.parse(stdout.trim().split('\n').pop());
  } catch (error) {
    throw new Error(`${script} ${argv.join(' ')} failed:\n${error.stderr || error.message}`);
  }
}

async function startServices(adapters, env, cleanups) {
  const needs = new Set(adapters.map((adapter) => adapter.requires).filter(Boolean));
  if (needs.size === 0) return null;
  const dockerVersion = services.dockerVersion();
  if (!dockerVersion) {
    throw new Error('Docker is not available: start it, or pass --no-docker to skip OPA and Cerbos.');
  }
  if (needs.has('opa-wasm')) {
    console.log(`Building the OPA WebAssembly policy (${services.OPA_IMAGE})…`);
    env.KERBEROS_BENCH_OPA_WASM = services.buildOpaWasm();
  }
  if (needs.has('opa-server')) {
    console.log(`Starting an OPA server (${services.OPA_IMAGE})…`);
    const opa = await services.startOpaServer();
    cleanups.push(opa.stop);
    env.KERBEROS_BENCH_OPA_URL = opa.url;
  }
  if (needs.has('cerbos')) {
    console.log(`Starting a Cerbos PDP (${services.CERBOS_IMAGE})…`);
    const cerbos = await services.startCerbos();
    cleanups.push(cerbos.stop);
    env.KERBEROS_BENCH_CERBOS_GRPC = cerbos.grpc;
  }
  return dockerVersion;
}

function printMatrix(libraries, scenarioResults) {
  const header = ['Library', ...scenarioResults.map((scenario) => `${scenario.title} (${scenario.unit})`)];
  console.log(`\n| ${header.join(' | ')} |`);
  console.log(`| ${header.map((_, i) => (i === 0 ? '---' : '---:')).join(' | ')} |`);
  for (const library of libraries) {
    const cells = scenarioResults.map((scenario) => {
      const result = scenario.results[library.id];
      return result ? format(result.median) : '—';
    });
    console.log(`| ${library.name} · ${library.variant} | ${cells.join(' | ')} |`);
  }
}

/** Merges this run into the existing file, so a partial run (--only/--scenarios) keeps the other rows. */
function writeResults(report) {
  let existing = null;
  try {
    existing = JSON.parse(fs.readFileSync(OUT, 'utf8'));
  } catch {
    // first run
  }
  if (existing) {
    const libraries = new Map(existing.libraries.map((library) => [library.id, library]));
    for (const library of report.libraries) libraries.set(library.id, library);
    report.libraries = ADAPTERS.map((adapter) => libraries.get(adapter.id)).filter(Boolean);
    report.scenarios = SCENARIOS.map(({ id }) => {
      const fresh = report.scenarios.find((scenario) => scenario.id === id);
      const old = existing.scenarios.find((scenario) => scenario.id === id);
      if (!fresh) return old;
      return { ...fresh, results: { ...old?.results, ...fresh.results } };
    }).filter(Boolean);
    report.coldStart = { ...existing.coldStart, ...report.coldStart };
  }
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(report, null, 2)}\n`);
  console.log(`\nWrote ${path.relative(ROOT, OUT)}`);
}

async function main() {
  const only = list(args.only);
  const scenarioIds = list(args.scenarios);
  let adapters = ADAPTERS.filter((adapter) => !only || only.includes(adapter.id));
  if (args['no-docker']) adapters = adapters.filter((adapter) => !adapter.requires || adapter.requires === 'opa-wasm');
  const scenarios = SCENARIOS.filter((scenario) => !scenarioIds || scenarioIds.includes(scenario.id));

  const env = {};
  const cleanups = [];
  const cleanup = () => {
    while (cleanups.length) cleanups.pop()();
  };
  process.once('SIGINT', () => {
    cleanup();
    process.exit(130);
  });

  const machine = describeMachine();
  console.log(`Cross-library comparison · ${machine.cpu} · Node ${machine.node}`);
  console.log(
    `${method.samples} × ${method.sampleMs} ms samples after ${method.warmupMs} ms warmup, median reported\n`,
  );

  try {
    machine.docker = await startServices(adapters, env, cleanups);

    const scenarioResults = [];
    for (const scenario of scenarios) {
      console.log(`\n${scenario.title} — ${scenario.description}`);
      const results = {};
      for (const adapter of adapters) {
        const options = { adapter: adapter.id, scenario: scenario.id, ...method };
        const result = await worker('worker.js', [JSON.stringify(options)], env);
        const spread = ((result.max - result.min) / result.median) * 100;
        results[adapter.id] = { median: result.median, min: result.min, max: result.max };
        console.log(
          `  ${`${adapter.name} · ${adapter.variant}`.padEnd(64)} ${format(result.median).padStart(12)} ${scenario.unit}  ±${spread.toFixed(1)}%`,
        );
      }
      const { id, title, description, unit } = scenario;
      scenarioResults.push({ id, title, description, unit, results });
    }

    const coldStart = {};
    const coldAdapters = adapters.filter((adapter) => adapter.coldStart);
    if (method.coldStartRuns > 0 && coldAdapters.length > 0) {
      console.log(
        `\nCold start — load + build the ownership policy + first decision, ${method.coldStartRuns} fresh processes`,
      );
      for (const adapter of coldAdapters) {
        const runs = [];
        for (let i = 0; i < method.coldStartRuns; i++) {
          runs.push(await worker('coldstart-worker.js', [adapter.id], env));
        }
        const phases = {};
        for (const phase of ['load', 'setup', 'firstDecision', 'total']) {
          phases[phase] = median(runs.map((sample) => sample[phase]));
        }
        coldStart[adapter.id] = phases;
        console.log(`  ${adapter.name.padEnd(24)} ${phases.total.toFixed(2).padStart(8)} ms`);
      }
    }

    const libraries = adapters.map(libraryInfo);
    printMatrix(libraries, scenarioResults);
    if (!args['no-write']) {
      writeResults({
        generatedAt: new Date().toISOString(),
        machine,
        method,
        libraries,
        scenarios: scenarioResults,
        coldStart,
      });
    }
  } finally {
    cleanup();
  }
}

main().catch((error) => {
  console.error(error.message ?? error);
  process.exitCode = 1;
});
