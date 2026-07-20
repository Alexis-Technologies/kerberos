/**
 * Browser platform runtime. Bundlers substitute `./node.js` with this module
 * via the package.json `browser` field map — keep both modules exporting the
 * exact same interface. Globals are read at call time (not captured at module
 * load) so environments that attach `crypto` / `performance` late still work.
 */

/**
 * Pseudo UUID v4 generator (Math.random based, NOT cryptographically secure).
 * Used when `crypto.randomUUID` is unavailable — e.g. insecure (plain-HTTP)
 * contexts or older WebViews. Call IDs are correlation identifiers, not
 * security tokens, so this fallback is acceptable.
 *
 * @returns {string}
 */
const pseudoUuidV4 = () =>
  'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });

/**
 * Generates a UUID v4 call identifier.
 *
 * @returns {string}
 */
const generateCallId = () => (globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : pseudoUuidV4());

/**
 * Returns a high-resolution timestamp in milliseconds.
 *
 * @returns {number}
 */
const getNow = () => (globalThis.performance ? globalThis.performance.now() : Date.now());

module.exports = { generateCallId, getNow };
