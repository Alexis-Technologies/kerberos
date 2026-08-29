/**
 * Cross-library bundle-size comparison for the docs "Benchmarks" page.
 *
 * Bundles each library's main entry for the browser with esbuild (the same
 * method as scripts/size.js) and reports min / min+gzip. A library that
 * cannot be bundled for the browser (Node builtins) is measured with
 * `platform: 'node'` instead and marked — that is itself a finding.
 *
 * Run: pnpm size:compare
 */

const { gzipSync } = require('node:zlib');
const path = require('node:path');
const esbuild = require('esbuild');

const ENTRIES = [
  { label: '@alexify/kerberos (main entry)', entry: 'browser.js', resolveDir: path.join(__dirname, '..') },
  { label: '@casl/ability', source: "export * from '@casl/ability';" },
  { label: 'casbin', source: "export * from 'casbin';" },
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
  else options.stdin = { contents: entry.source, resolveDir: path.join(__dirname, '..') };
  const result = await esbuild.build(options);
  return Buffer.from(result.outputFiles[0].contents);
}

function kb(bytes) {
  return `${(bytes / 1024).toFixed(1)} KB`;
}

async function main() {
  console.log('| Library | min | min+gzip | |');
  console.log('| ------- | ---:| --------:| --- |');
  for (const entry of ENTRIES) {
    let buffer;
    let note = '';
    try {
      buffer = await bundle(entry, 'browser');
    } catch {
      buffer = await bundle(entry, 'node');
      note = 'does not bundle for the browser (Node builtins) — measured as a Node bundle';
    }
    console.log(`| ${entry.label} | ${kb(buffer.length)} | ${kb(gzipSync(buffer, { level: 9 }).length)} | ${note} |`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
