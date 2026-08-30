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

/**
 * allSettled with the engine's error rule: every sibling settles (no unawaited
 * rejection — memoized promises stay handled), then the FIRST rejection reason
 * is rethrown; otherwise the fulfilled values are returned in input order.
 * Shared by the engine and the RelationResolver — the documented parallelism
 * policy lives in exactly one place.
 *
 * @param {Promise<unknown>[]} promises
 * @returns {Promise<unknown[]>}
 */
async function settleAll(promises) {
  const settled = await Promise.allSettled(promises);
  const values = new Array(settled.length);
  let firstError = null;
  for (let i = 0; i < settled.length; i++) {
    if (settled[i].status === 'rejected') {
      if (!firstError) firstError = settled[i].reason;
      continue;
    }
    values[i] = settled[i].value;
  }
  if (firstError) throw firstError instanceof Error ? firstError : new Error(String(firstError));
  return values;
}

/**
 * Zero-dependency concurrency limiter: at most `max` thunks run at once,
 * excess callers wait in FIFO order. Used for the opt-in `maxConcurrency`
 * option — fan-out waves (batch evaluation, lookup verification) otherwise
 * launch every task simultaneously.
 *
 * @param {number} max
 * @returns {(fn: () => Promise<unknown>) => Promise<unknown>}
 */
function createLimiter(max) {
  let active = 0;
  const queue = [];
  return async function limit(fn) {
    if (active >= max) await new Promise((resolve) => queue.push(resolve));
    active++;
    try {
      return await fn();
    } finally {
      active--;
      if (queue.length) queue.shift()();
    }
  };
}

module.exports = { createLimiter, settleAll, withTimeout };
