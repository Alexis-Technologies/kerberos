/**
 * Cross-library bundle-size comparison for the docs "Benchmarks" page.
 *
 * Bundles each library's main entry for the browser with esbuild (the same
 * method as scripts/size.js) and reports min / min+gzip. A library that
 * cannot be bundled for the browser (Node builtins) is measured with
 * `platform: 'node'` instead and marked — that is itself a finding. OPA's
 * WebAssembly SDK also needs a compiled policy at runtime: when Docker is
 * available, the ownership policy is compiled with the pinned `opa` image and
 * its .wasm size is reported next to the SDK.
 *
 * Run: pnpm size:compare [--json]   (--json writes bench/results/size.json)
 */

const fs = require('node:fs');
const { gzipSync } = require('node:zlib');
const path = require('node:path');
const esbuild = require('esbuild');
const { getAdapter } = require('../bench/compare/adapters/index.js');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'bench', 'results', 'size.json');

// Ids match the comparison adapters (bench/compare/adapters), whose display names the results reuse.
const ENTRIES = [
  { id: 'kerberos', package: '@alexify/kerberos', entry: 'browser.js', resolveDir: ROOT },
  { id: 'casl', package: '@casl/ability', source: "export * from '@casl/ability';" },
  { id: 'casbin', package: 'casbin', source: "export * from 'casbin';" },
  { id: 'accesscontrol', package: 'accesscontrol', source: "export * from 'accesscontrol';" },
  { id: 'easy-rbac', package: 'easy-rbac', source: "export { default } from 'easy-rbac';" },
  { id: 'rbac', package: '@rbac/rbac', source: "export { default } from '@rbac/rbac';" },
  { id: 'opa-wasm', package: '@open-policy-agent/opa-wasm', source: "export * from '@open-policy-agent/opa-wasm';" },
];

async function bundle(entry, platform) {
  const options = {
    bundle: true,
    minify: true,
    platform,
    conditions: platform === 'browser' ? ['browser'] : [],
    write: false,
    logLevel: 'silent',
  };
  if (entry.entry) options.entryPoints = [path.join(entry.resolveDir, entry.entry)];
  else options.stdin = { contents: entry.source, resolveDir: ROOT };
  const result = await esbuild.build(options);
  return Buffer.from(result.outputFiles[0].contents);
}

function kb(bytes) {
  return `${(bytes / 1024).toFixed(1)} KB`;
}

const gzip = (buffer) => gzipSync(buffer, { level: 9 }).length;

/** The ownership policy compiled to WebAssembly, or null without Docker. */
function opaPolicyWasm() {
  const services = require('../bench/compare/services.js');
  if (!services.dockerVersion()) return null;
  const { regoModules, OPA_ENTRYPOINTS } = require('../bench/compare/policies.js');
  const file = services.buildOpaWasm({
    name: 'opa-wasm-size',
    modules: { 'abac.rego': regoModules()['abac.rego'] },
    entrypoints: [OPA_ENTRYPOINTS.abac],
  });
  return fs.readFileSync(file);
}

async function main() {
  const rows = [];
  for (const entry of ENTRIES) {
    let buffer;
    let browser = true;
    try {
      buffer = await bundle(entry, 'browser');
    } catch {
      buffer = await bundle(entry, 'node');
      browser = false;
    }
    const { name } = getAdapter(entry.id);
    rows.push({ id: entry.id, name, package: entry.package, min: buffer.length, gzip: gzip(buffer), browser });
  }

  const wasm = opaPolicyWasm();
  if (wasm) {
    const opa = rows.find((row) => row.id === 'opa-wasm');
    opa.policyWasm = { min: wasm.length, gzip: gzip(wasm) };
  }

  console.log('| Library | min | min+gzip | |');
  console.log('| ------- | ---:| --------:| --- |');
  for (const row of rows) {
    let note = row.browser ? '' : 'does not bundle for the browser (Node builtins) — measured as a Node bundle';
    if (row.policyWasm) note = `+ ${kb(row.policyWasm.gzip)} gzip compiled policy (.wasm, ownership rule only)`;
    console.log(`| ${row.package} | ${kb(row.min)} | ${kb(row.gzip)} | ${note} |`);
  }

  if (process.argv.includes('--json')) {
    fs.mkdirSync(path.dirname(OUT), { recursive: true });
    fs.writeFileSync(OUT, `${JSON.stringify({ generatedAt: new Date().toISOString(), libraries: rows }, null, 2)}\n`);
    console.log(`\nWrote ${path.relative(ROOT, OUT)}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
