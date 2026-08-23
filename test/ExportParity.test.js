const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const { readFileSync } = require('node:fs');
const path = require('node:path');

// Structural drift guard for the hand-maintained type definitions: every
// runtime export of the three entry points must be declared in its d.ts, and
// every declared VALUE export must exist at runtime. This is the check the
// CLAUDE.md "update the d.ts too" checklist relied on humans for — the
// missing-statics drift shipped precisely because nothing enforced it.

function declaredValueExports(dtsFile) {
  const source = readFileSync(path.join(__dirname, '..', dtsFile), 'utf8');
  const names = new Set();
  // Value exports only — `export type` / `export interface` have no runtime
  // counterpart and are deliberately excluded.
  const exportPattern = /^export (?:declare )?(?:abstract )?(?:class|function|const|enum|let|var) ([A-Za-z0-9_$]+)/gm;
  for (const match of source.matchAll(exportPattern)) names.add(match[1]);
  return names;
}

const entryPoints = [
  ['index.js', 'index.d.ts', () => require('../index.js')],
  ['relations.js', 'relations.d.ts', () => require('../relations.js')],
  ['tests.js', 'tests.d.ts', () => require('../tests.js')],
];

describe('runtime ↔ d.ts export parity', () => {
  for (const [runtimeFile, dtsFile, load] of entryPoints) {
    it(`${runtimeFile} matches ${dtsFile}`, () => {
      const runtime = new Set(Object.keys(load()));
      const declared = declaredValueExports(dtsFile);

      const undeclared = [...runtime].filter((name) => !declared.has(name)).sort();
      const phantom = [...declared].filter((name) => !runtime.has(name)).sort();

      assert.deepEqual(undeclared, [], `runtime exports of ${runtimeFile} missing from ${dtsFile}`);
      assert.deepEqual(phantom, [], `declared in ${dtsFile} but absent from ${runtimeFile} at runtime`);
    });
  }
});
