# Installation

::: code-group

```bash [npm]
npm install @alexify/kerberos
```

```bash [pnpm]
pnpm add @alexify/kerberos
```

```bash [yarn]
yarn add @alexify/kerberos
```

:::

Requires **Node.js ≥ 18** (or any modern browser through a bundler). The package is CommonJS; both `require('@alexify/kerberos')` and `import { Kerberos } from '@alexify/kerberos'` (via Node/bundler ESM interop) work — the examples throughout these docs use `import`.

## Bundle size

Zero runtime dependencies. Measured with `pnpm size` (esbuild browser bundle, fully minified with identifier mangling, then gzipped):

| Entry | min | min+gzip |
| ----- | ---:| --------:|
| `@alexify/kerberos` (main entry, query planner included) | 115.6 KB | **31.9 KB** |
| `@alexify/kerberos/relations` (opt-in ReBAC resolver) | 60.5 KB | 16.3 KB |
| `@alexify/kerberos/cerbos` (opt-in [Cerbos importer](/guide/cerbos-import)) | 34.0 KB | 10.9 KB |

The `/relations` and `/tests` subpaths are only bundled if you import them. Optional tooling (`jsep`, `zod`, `ajv`, `@sinclair/typebox`, `@opentelemetry/api`) is never included — you install what you use.

## Browser usage

The package ships two entrypoints: a Node.js entry (`index.js`, uses `node:crypto` / `node:perf_hooks` directly) and a browser entry (`browser.js`) declared via the package.json `browser` field and the `browser` condition in `exports`. Browser bundlers pick the browser build automatically — **no configuration needed** for webpack 5, Vite, esbuild (`platform: 'browser'`), Parcel or Bun. Rollup users need [`@rollup/plugin-node-resolve`](https://github.com/rollup/plugins/tree/master/packages/node-resolve) with `browser: true`.

The browser build contains **zero Node.js builtins** — the only platform-specific code (`generateCallId`, `getNow`) is swapped to a browser implementation backed by `globalThis.crypto.randomUUID` and `globalThis.performance`.

::: info Notes
- In insecure contexts (plain HTTP), where `crypto.randomUUID` is unavailable, call IDs fall back to a `Math.random`-based pseudo UUID. Call IDs are **correlation identifiers, not security tokens**, so this is safe.
- The package is CommonJS, so browser usage requires a bundler (no bare `<script>` tag).
- Node.js itself ignores the `browser` field entirely — server-side usage (with or without a bundler) always resolves the Node entry.
:::
