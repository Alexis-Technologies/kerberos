const { randomUUID } = require('node:crypto');
const { performance } = require('node:perf_hooks');

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
 * Returns a high-resolution timestamp in milliseconds.
 *
 * @returns {number}
 */
const getNow = () => performance.now();

module.exports = { generateCallId, getNow };
