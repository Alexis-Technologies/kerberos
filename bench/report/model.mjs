/**
 * Chart models for the benchmark results in bench/results/*.json — the ONE
 * place that decides what a chart shows (rows, order, grouping, scale,
 * formatting). Two renderers consume it: the docs components
 * (docs/.vitepress/theme/components/Bench*.vue, HTML bars) and the README
 * images (bench/report/svg.mjs). ESM so Vite can import it; the CommonJS
 * report script loads it with import().
 */

/** The library every comparison chart emphasizes. */
export const HIGHLIGHT = 'kerberos';

const trim = (value) => String(Number(value.toPrecision(3)));

/** 779878 → "780k", 16685662 → "16.7M", 1219 → "1,219". */
export function compact(value) {
  const abs = Math.abs(value);
  if (abs >= 1e6) return `${trim(value / 1e6)}M`;
  if (abs >= 1e4) return `${trim(value / 1e3)}k`;
  return Math.round(value).toLocaleString('en-US');
}

/** Full integer with thousands separators, for tables. */
export const grouped = (value) => Math.round(value).toLocaleString('en-US');

/** The time one call takes at `perSecond` calls per second. */
export function perCall(perSecond) {
  const seconds = 1 / perSecond;
  if (seconds >= 1e-3) return `${trim(seconds * 1e3)} ms`;
  if (seconds >= 1e-6) return `${trim(seconds * 1e6)} µs`;
  return `${trim(seconds * 1e9)} ns`;
}

export function formatValue(value, unit) {
  if (unit === 'ms') return `${value < 10 ? value.toFixed(1) : Math.round(value)} ms`;
  if (unit === 'KB') return `${value.toFixed(1)} KB`;
  if (unit === '×') return `×${value < 10 ? value.toFixed(1) : Math.round(value)}`;
  return compact(value);
}

// ─── Scales ─────────────────────────────────────────────────────────────────

function niceStep(raw) {
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const residual = raw / magnitude;
  const nice = residual <= 1 ? 1 : residual <= 2 ? 2 : residual <= 5 ? 5 : 10;
  return nice * magnitude;
}

/**
 * `{ ticks: [{ value, label, at }], at(value) }` where `at` maps a value to
 * 0..1 along the bar track. Linear scales start at zero; log scales span whole
 * decades around the data (bars then encode orders of magnitude, which the
 * charts say in their subtitle).
 */
export function createScale(values, kind, unit) {
  const max = Math.max(...values);
  if (kind === 'log') {
    const min = Math.min(...values.filter((value) => value > 0));
    const lo = Math.floor(Math.log10(min));
    const hi = Math.max(lo + 1, Math.ceil(Math.log10(max)));
    const at = (value) => (Math.log10(Math.max(value, 10 ** lo)) - lo) / (hi - lo);
    const ticks = [];
    for (let exp = lo; exp <= hi; exp++) ticks.push({ value: 10 ** exp, label: compact(10 ** exp), at: at(10 ** exp) });
    return { kind, at, ticks };
  }
  const step = niceStep(max / 4);
  const top = Math.ceil(max / step) * step;
  const at = (value) => value / top;
  const ticks = [];
  for (let value = 0; value <= top + step / 2; value += step) {
    let label = compact(value);
    if (unit === '×' && value > 0) label = `×${trim(value)}`;
    else if (unit === 'ms' || unit === 'KB') label = `${trim(value)} ${unit}`;
    ticks.push({ value, label, at: at(value) });
  }
  return { kind, at, ticks };
}

// ─── Captions ───────────────────────────────────────────────────────────────

const day = (iso) => iso.slice(0, 10);

export function machineCaption(machine) {
  const parts = [machine.cpu, `${machine.cores} cores`, `Node ${machine.node}`];
  if (machine.docker) parts.push(`Docker ${machine.docker}`);
  return parts.join(' · ');
}

export function compareCaption(compare) {
  const { method } = compare;
  return `${machineCaption(compare.machine)} · median of ${method.samples} × ${method.sampleMs / 1000} s samples, each library in a fresh process · ${day(compare.generatedAt)}`;
}

// ─── Cross-library comparison ───────────────────────────────────────────────

const byValueDesc = (a, b) => b.value - a.value;
const byValueAsc = (a, b) => a.value - b.value;

function libraryRow(library, value, extra) {
  return {
    id: library.id,
    label: library.name,
    sublabel: library.variant,
    value,
    highlight: library.id === HIGHLIGHT,
    ...extra,
  };
}

function versionNote(library) {
  const parts = [];
  if (library.package) parts.push(`${library.package}@${library.version}`);
  if (library.image) parts.push(library.runtime === 'service' ? library.image : `compiled with ${library.image}`);
  return parts.join(' · ');
}

/** The engine's version as a reader would quote it: a sidecar's image tag, otherwise the npm package version. */
export function engineVersion(library) {
  if (library.runtime === 'service' && library.image) return library.image.split(':').pop();
  return `v${library.version}`;
}

export function compareScenarios(compare) {
  return compare.scenarios.map(({ id, title, description, unit }) => ({ id, title, description, unit }));
}

export function compareModel(compare, scenarioId, scale = 'log') {
  const scenario = compare.scenarios.find((candidate) => candidate.id === scenarioId) ?? compare.scenarios[0];
  const perWhat = scenario.unit === 'batches/s' ? 'per batch' : 'per decision';
  const rows = compare.libraries
    .filter((library) => scenario.results[library.id])
    .map((library) => {
      const result = scenario.results[library.id];
      return libraryRow(library, result.median, {
        runtime: library.runtime,
        details: [
          `${grouped(result.median)} ${scenario.unit}`,
          `${perCall(result.median)} ${perWhat}`,
          `samples ${compact(result.min)} – ${compact(result.max)}`,
          versionNote(library),
        ],
      });
    });
  const groups = [
    { id: 'in-process', label: 'In-process', rows: rows.filter((row) => row.runtime !== 'service').sort(byValueDesc) },
    {
      id: 'service',
      label: 'Sidecar — a network round-trip per call',
      rows: rows.filter((row) => row.runtime === 'service').sort(byValueDesc),
    },
  ].filter((group) => group.rows.length > 0);
  return {
    id: `compare-${scenario.id}`,
    title: scenario.title,
    subtitle: `${scenario.description} ${scenario.unit}, ${scale === 'log' ? 'log scale' : 'linear scale'} — higher is better.`,
    unit: scenario.unit,
    scale,
    groups,
  };
}

export function coldStartModel(compare) {
  const rows = compare.libraries
    .filter((library) => compare.coldStart[library.id])
    .map((library) => {
      const phases = compare.coldStart[library.id];
      return libraryRow(library, phases.total, {
        details: [
          `${phases.total.toFixed(1)} ms in total`,
          `load ${phases.load.toFixed(1)} ms · build policy ${phases.setup.toFixed(1)} ms · first decision ${phases.firstDecision.toFixed(1)} ms`,
          versionNote(library),
        ],
      });
    })
    .sort(byValueAsc);
  return {
    id: 'coldstart',
    title: 'Cold start',
    subtitle: `Load the library, build the ownership policy, first decision — fresh process, median of ${compare.method.coldStartRuns} runs. Lower is better.`,
    unit: 'ms',
    scale: 'linear',
    groups: [{ id: 'all', label: null, rows }],
  };
}

export function sizeModel(size) {
  const rows = size.libraries
    .map((library) => {
      const wasm = library.policyWasm?.gzip ?? 0;
      const kb = (bytes) => `${(bytes / 1024).toFixed(1)} KB`;
      let sublabel = library.package === library.name ? null : library.package;
      if (!library.browser) sublabel = 'Node-only, does not bundle for the browser';
      if (wasm) sublabel = `${kb(library.gzip)} SDK + ${kb(wasm)} compiled policy (.wasm)`;
      return {
        id: library.id,
        label: library.name,
        sublabel,
        value: (library.gzip + wasm) / 1024,
        highlight: library.id === HIGHLIGHT,
        details: [
          `${kb(library.gzip + wasm)} min+gzip`,
          `${kb(library.min)} minified${wasm ? ` + ${kb(library.policyWasm.min)} .wasm` : ''}`,
          library.browser ? 'browser bundle (esbuild)' : 'Node bundle — does not bundle for the browser',
        ],
      };
    })
    .sort(byValueAsc);
  return {
    id: 'size',
    title: 'Bundle size',
    subtitle: 'Main entry bundled with esbuild, min+gzip. Lower is better.',
    unit: 'KB',
    scale: 'linear',
    groups: [{ id: 'all', label: null, rows }],
  };
}

// ─── Kerberos releases ──────────────────────────────────────────────────────

const SCALING = 'scaling — ';

function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

/** Releases in bench/results/engine.json, oldest first. */
export function releaseVersions(engine) {
  return Object.keys(engine.releases).sort(compareVersions);
}

export function latestRelease(engine) {
  const versions = releaseVersions(engine);
  const version = versions[versions.length - 1];
  return { version, ...engine.releases[version] };
}

/** The current release's hot paths (the scaling sweeps go to `releaseModel`), grouped by API. */
export function engineModel(engine) {
  const release = latestRelease(engine);
  const groups = [];
  for (const scenario of release.scenarios) {
    if (scenario.name.startsWith(SCALING)) continue;
    const [api, ...rest] = scenario.name.split(' — ');
    let group = groups.find((candidate) => candidate.id === api);
    if (!group) groups.push((group = { id: api, label: api, rows: [] }));
    group.rows.push({
      id: scenario.name,
      label: rest.join(' — '),
      sublabel: null,
      value: scenario.opsPerSec,
      highlight: true,
      details: [`${grouped(scenario.opsPerSec)} ops/s`, `${perCall(scenario.opsPerSec)} per call`],
    });
  }
  return {
    id: 'engine',
    title: `Kerberos.js ${release.version} hot paths`,
    subtitle: 'ops/s, linear scale — higher is better.',
    unit: 'ops/s',
    scale: 'linear',
    groups,
  };
}

/** Speed-up of every scaling sweep between the two newest releases that both have it. */
export function releaseModel(engine) {
  const versions = releaseVersions(engine);
  const current = versions[versions.length - 1];
  const previous = [...versions]
    .reverse()
    .find(
      (version) =>
        version !== current && engine.releases[version].scenarios.some((scenario) => scenario.name.startsWith(SCALING)),
    );
  if (!previous) return null;
  const before = new Map(engine.releases[previous].scenarios.map((scenario) => [scenario.name, scenario.opsPerSec]));
  const rows = engine.releases[current].scenarios
    .filter((scenario) => scenario.name.startsWith(SCALING) && before.has(scenario.name))
    .map((scenario) => {
      const old = before.get(scenario.name);
      const label = scenario.name.slice(SCALING.length);
      return {
        id: scenario.name,
        label,
        sublabel: `${compact(old)} → ${compact(scenario.opsPerSec)} per second`,
        value: scenario.opsPerSec / old,
        highlight: true,
        details: [
          `×${(scenario.opsPerSec / old).toFixed(1)} faster`,
          `${previous}: ${grouped(old)}/s · ${current}: ${grouped(scenario.opsPerSec)}/s`,
        ],
      };
    })
    .sort(byValueDesc);
  return {
    id: 'releases',
    title: `${previous} → ${current}: how decision cost scales with policy shape`,
    subtitle: 'Speed-up of each scaling sweep, same machine and harness. Higher is better.',
    unit: '×',
    scale: 'linear',
    reference: 1,
    previous,
    current,
    groups: [{ id: 'all', label: null, rows }],
  };
}

export function allRows(model) {
  return model.groups.flatMap((group) => group.rows);
}
