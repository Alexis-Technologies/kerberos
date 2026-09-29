/**
 * Cold-start benchmark: module loading, engine construction and the first
 * decision, each measured in a fresh Node process (the in-process module cache
 * would hide everything after the first run).
 *
 * Run: pnpm bench:coldstart (or: node bench/coldstart.js [runs])
 */
const { execFileSync } = require('node:child_process');
const path = require('node:path');

const RUNS = Number(process.argv[2]) || 30;
const ENTRY = path.join(__dirname, '..', 'index.js');

// The child reads the clock before its first require, so Node's own bootstrap
// is excluded and only the package's cost is measured. It uses
// process.hrtime rather than performance.now(): loading node:perf_hooks here
// would hide what the package itself pays for it.
const CHILD = `
const now = () => Number(process.hrtime.bigint()) / 1e6;
const t0 = now();
const { Kerberos } = require(${JSON.stringify(ENTRY)});
const t1 = now();
const engine = new Kerberos(
  [{ resourcePolicy: { version: 'default', resource: 'expense',
     rules: [{ actions: ['view'], effect: 'EFFECT_ALLOW', roles: ['USER'] }] } }],
  [],
);
const t2 = now();
engine
  .isAllowed({ principal: { id: 'sally', roles: ['USER'] }, action: 'view', resource: { id: 'e1', kind: 'expense' } })
  .then(() => {
    const t3 = now();
    process.stdout.write(JSON.stringify({ require: t1 - t0, construct: t2 - t1, firstDecision: t3 - t2, total: t3 - t0 }));
  });
`;

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

const samples = [];
for (let i = 0; i < RUNS; i++) {
  samples.push(JSON.parse(execFileSync(process.execPath, ['-e', CHILD], { encoding: 'utf8' })));
}

console.log(`Node ${process.version} | ${RUNS} fresh processes | medians in ms\n`);
for (const phase of ['require', 'construct', 'firstDecision', 'total']) {
  const value = median(samples.map((sample) => sample[phase]));
  console.log(`${phase.padEnd(16)} ${value.toFixed(2).padStart(8)} ms`);
}
