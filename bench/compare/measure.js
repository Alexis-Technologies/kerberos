/**
 * The sampling harness the comparison workers share. Calls are timed in
 * chunks (grown during warmup until one chunk takes about a millisecond) so
 * the clock read does not dominate sub-microsecond calls, and a function that
 * returns synchronously is never awaited — awaiting a plain value would charge
 * synchronous libraries a microtask per call that their callers do not pay.
 */
const { performance } = require('node:perf_hooks');

const MAX_CHUNK = 1 << 16;

function isThenable(value) {
  return value !== null && typeof value === 'object' && typeof value.then === 'function';
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function measure(fn, { warmupMs, sampleMs, samples }) {
  let sink = 0;
  const runSync = (count) => {
    for (let i = 0; i < count; i++) if (fn()) sink++;
  };
  const runAsync = async (count) => {
    for (let i = 0; i < count; i++) if (await fn()) sink++;
  };
  const run = isThenable(fn()) ? runAsync : runSync;

  let chunk = 1;
  const warmupEnd = performance.now() + warmupMs;
  while (performance.now() < warmupEnd) {
    const start = performance.now();
    await run(chunk);
    if (performance.now() - start < 1 && chunk < MAX_CHUNK) chunk *= 2;
  }

  const rates = [];
  for (let s = 0; s < samples; s++) {
    let iterations = 0;
    let elapsed = 0;
    const start = performance.now();
    do {
      await run(chunk);
      iterations += chunk;
      elapsed = performance.now() - start;
    } while (elapsed < sampleMs);
    rates.push((iterations / elapsed) * 1000);
  }
  if (sink < 0) throw new Error('unreachable');
  return { median: median(rates), min: Math.min(...rates), max: Math.max(...rates), samples: rates };
}

module.exports = { measure, median, isThenable };
