/**
 * Docker plumbing for the engines that are not JavaScript libraries: the OPA
 * WebAssembly build, an OPA server and a Cerbos PDP. Images are pinned — the
 * Cerbos tag matches the conformance job — and the containers publish on
 * uncommon host ports so a locally running PDP is never measured by mistake.
 * Generated policies live in bench/compare/.cache (gitignored).
 */
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { OPA_ENTRYPOINTS, regoModules, cerbosPolicies } = require('./policies.js');

const CERBOS_IMAGE = 'ghcr.io/cerbos/cerbos:0.55.0';
const OPA_IMAGE = 'openpolicyagent/opa:1.21.1';
const CACHE_DIR = path.join(__dirname, '.cache');

const CERBOS = { container: 'kerberos-bench-cerbos', httpPort: 13592, grpcPort: 13593 };
const OPA = { container: 'kerberos-bench-opa', port: 18181 };

function docker(args) {
  return execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function dockerVersion() {
  try {
    return docker(['version', '--format', '{{.Server.Version}}']);
  } catch {
    return null;
  }
}

function writeTree(dir, files) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, contents] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), contents);
}

async function waitUntil(label, probe, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (await probe()) return;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`${label} did not become ready within ${timeoutMs / 1000}s`);
}

function removeContainer(name) {
  try {
    docker(['rm', '-f', name]);
  } catch {
    // already gone
  }
}

/**
 * Compiles Rego modules to policy.wasm and returns its path: by default every
 * scenario's module; scripts/size-compare.js builds the ownership policy alone.
 */
function buildOpaWasm({
  name = 'opa-wasm',
  modules = regoModules(),
  entrypoints = Object.values(OPA_ENTRYPOINTS),
} = {}) {
  const dir = path.join(CACHE_DIR, name);
  writeTree(path.join(dir, 'policies'), modules);
  const flags = entrypoints.flatMap((entrypoint) => ['-e', entrypoint]);
  docker(['run', '--rm', '-v', `${dir}:/work`, '-w', '/work', OPA_IMAGE, 'build', '-t', 'wasm', ...flags, 'policies']);
  execFileSync('tar', ['-xzf', path.join(dir, 'bundle.tar.gz'), '-C', dir], { stdio: 'pipe' });
  return path.join(dir, 'policy.wasm');
}

async function startOpaServer() {
  const dir = path.join(CACHE_DIR, 'opa-server');
  writeTree(dir, regoModules());
  removeContainer(OPA.container);
  docker([
    'run',
    '--rm',
    '-d',
    '--name',
    OPA.container,
    '-v',
    `${dir}:/policies:ro`,
    '-p',
    `${OPA.port}:8181`,
    OPA_IMAGE,
    'run',
    '--server',
    '--addr=0.0.0.0:8181',
    '--log-level=error',
    '/policies',
  ]);
  const url = `http://127.0.0.1:${OPA.port}`;
  await waitUntil('OPA server', async () => (await fetch(`${url}/health`)).ok);
  return { url, stop: () => removeContainer(OPA.container) };
}

async function startCerbos() {
  const dir = path.join(CACHE_DIR, 'cerbos');
  writeTree(dir, cerbosPolicies());
  docker(['run', '--rm', '-v', `${dir}:/policies:ro`, CERBOS_IMAGE, 'compile', '--skip-tests', '/policies']);
  removeContainer(CERBOS.container);
  docker([
    'run',
    '--rm',
    '-d',
    '--name',
    CERBOS.container,
    '-v',
    `${dir}:/policies:ro`,
    '-p',
    `${CERBOS.httpPort}:3592`,
    '-p',
    `${CERBOS.grpcPort}:3593`,
    CERBOS_IMAGE,
    'server',
    '--set=storage.disk.directory=/policies',
    '--set=storage.disk.watchForChanges=false',
    '--set=server.requestLimits.maxResourcesPerRequest=100',
  ]);
  const health = `http://127.0.0.1:${CERBOS.httpPort}/_cerbos/health`;
  await waitUntil('Cerbos PDP', async () => (await (await fetch(health)).text()).includes('SERVING'));
  return { grpc: `127.0.0.1:${CERBOS.grpcPort}`, stop: () => removeContainer(CERBOS.container) };
}

module.exports = { CERBOS_IMAGE, OPA_IMAGE, dockerVersion, buildOpaWasm, startOpaServer, startCerbos };
