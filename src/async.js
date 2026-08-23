/**
 * Races a promise against a timer. Disabled when `timeoutMs` is falsy (the
 * default — hang protection is opt-in, the backend owns its own timeouts
 * otherwise). On timeout the returned promise rejects with `makeError()`; the
 * abandoned promise keeps running, but its eventual rejection is marked
 * handled so it can never surface as an unhandled rejection. The timer is
 * cleared as soon as the race settles.
 *
 * Platform-neutral: relies only on the global `setTimeout`/`clearTimeout`
 * available in both Node.js and browsers (no `src/runtime/` split needed).
 *
 * @param {Promise<unknown>} promise
 * @param {number | undefined | null} timeoutMs
 * @param {() => Error} makeError
 * @returns {Promise<unknown>}
 */
async function withTimeout(promise, timeoutMs, makeError) {
  if (!timeoutMs) return promise;
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => {
        timer = setTimeout(() => {
          Promise.resolve(promise).catch(() => {});
          reject(makeError());
        }, timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { withTimeout };
