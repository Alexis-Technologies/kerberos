const { randomUUID } = require('node:crypto');

/**
 * Node.js platform runtime. The browser counterpart (`./browser.js`) is
 * substituted by bundlers via the package.json `browser` field map — keep both
 * modules exporting the exact same interface.
 */

/**
 * Generates a UUID v4 call identifier.
 *
 * @returns {string}
 */
const generateCallId = () => randomUUID();

/**
 * Returns a high-resolution timestamp in milliseconds. Only differences are
 * ever used (durations), so the monotonic `process.hrtime` clock serves as
 * well as `performance.now()` — without loading node:perf_hooks at startup.
 *
 * @returns {number}
 */
const getNow = () => {
  const [seconds, nanoseconds] = process.hrtime();
  return seconds * 1e3 + nanoseconds / 1e6;
};

module.exports = { generateCallId, getNow };
