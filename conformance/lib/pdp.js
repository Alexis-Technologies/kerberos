'use strict';

/**
 * Thin client for a live Cerbos PDP, used only when CERBOS_URL is set.
 *
 * Kept dependency-free (global fetch, Node >= 18) and deliberately dumb: it
 * shapes the request, and every comparison happens in the test file so that a
 * divergence is reported as data rather than hidden behind a helper.
 */

const DEFAULT_TIMEOUT_MS = 10_000;

async function post(baseUrl, endpoint, body, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const response = await fetch(`${baseUrl.replace(/\/$/, '')}${endpoint}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Cerbos ${endpoint} responded ${response.status}: ${text.slice(0, 500)}`);
  }
  return JSON.parse(text);
}

/** Polls `/_cerbos/health` until the PDP reports SERVING. */
async function waitUntilReady(baseUrl, { attempts = 60, delayMs = 1000 } = {}) {
  let lastError;
  for (let i = 0; i < attempts; i += 1) {
    try {
      const response = await fetch(`${baseUrl.replace(/\/$/, '')}/_cerbos/health`, {
        signal: AbortSignal.timeout(2000),
      });
      if (response.ok && (await response.text()).includes('SERVING')) return true;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  throw new Error(`Cerbos at ${baseUrl} never became ready: ${lastError?.message ?? 'no SERVING response'}`);
}

/** POST /api/check/resources — note `actions` is per resource entry, not top level. */
async function checkResources(baseUrl, { principal, resources, requestId }) {
  const body = {
    ...(requestId && { requestId }),
    principal,
    resources: resources.map(({ resource, actions }) => ({ actions, resource })),
  };
  const response = await post(baseUrl, '/api/check/resources', body);
  return (response.results ?? []).map((result) => result.actions ?? {});
}

/** POST /api/plan/resources — `resource` here carries no `id`. */
async function planResources(baseUrl, { principal, resource, actions, requestId }) {
  const response = await post(baseUrl, '/api/plan/resources', {
    ...(requestId && { requestId }),
    principal,
    resource,
    actions,
  });
  return response.filter ?? null;
}

module.exports = { checkResources, planResources, waitUntilReady };
