# Serialization & security

Kerberos deliberately does **not** serialize raw JavaScript function bodies and **never uses `eval` / `new Function` / `fn.toString()`**. That classic "stringify a function, then eval it back" approach is unsafe and brittle:

- `new Function(body)` is equivalent to `eval(body)`. A denylist of dangerous tokens is weaker than an allowlist by design — it can be bypassed via bracket notation (`P['cons' + 'tructor']`), unicode escapes, `with`, `Reflect`, `Proxy` traps, and so on, with no end to the patches (see the `node-serialize` RCE, CVE-2017-5941).
- `fn.toString()` produces engine/bundler-specific output (V8 vs SpiderMonkey, Babel/esbuild/SWC, `[native code]`), which silently breaks serialization across environments.
- Re-`eval`ing on every cache hit pays a JIT-compilation cost exactly when load is highest.

Instead, the built-in codec (`createSafeExprCodec({ jsep })`) uses an **AST allowlist interpreter** built on the tiny, eval-free [`jsep`](https://ericsmekens.github.io/jsep/) parser. Safe-by-default resource limits are configurable per codec: `createSafeExprCodec({ jsep, maxCachedExprs, maxExprLength, maxDepth })` — defaults `1000` cached ASTs (FIFO eviction), `4096` chars per expression, nesting depth `32` (unrelated to the ReBAC resolver's own `maxDepth: 50` walk limit). How it works:

1. Each `{ $expr }` string is parsed **once** into an AST via your `jsep` instance, which is cached per (jsep instance, expression string) pair (`parse-once`).
2. Evaluation walks the AST per request with a strict allowlist — no `eval`, no `new Function`, no recompilation.
3. Identifiers resolve **only** against the `{ P, R, V, C }` context and curated safe builtins (`Math`, `Date`, `parseInt`, `parseFloat`, ... — so `constructor`, `process`, `require`, `globalThis` simply do not exist as roots). Member keys `__proto__` / `prototype` / `constructor` are blocked at the interpreter level regardless of how they are written. Method calls are limited to a whitelist of safe helpers on string/array/number/`Date` values, plus `Math.*` / `Date.*` static methods. Only `new Date(...)` is permitted as a constructor.
4. This keeps remote policies expressive (comparisons, logic, ternaries, member access, object/array literals, time windows via `Date`, numeric helpers via `Math`, parsing via `parseInt`/`parseFloat`) while remaining non-Turing-complete and safe to load from a shared store.

**`jsep` is not bundled** — you install it separately and pass the pre-configured instance, the same way you pass `ajv` for schema validation. This keeps `@alexify/kerberos` itself zero-dependency.

```javascript
// Using the full createSafeExprCodec helper (serialize + deserialize):
import { createSafeExprCodec, serializePolicy } from '@alexify/kerberos';

const codec = createSafeExprCodec({ jsep });

// Serialize before storing:
await redis.set('resource:document:default:', JSON.stringify(codec.serialize(policyShape)));

// Kerberos deserializes automatically when codec.jsep (or codec.deserialize) is set:
const kerberos = new Kerberos([], [], { cache, codec });
// equivalently: codec: { jsep } — Kerberos creates the built-in evaluator internally
```

## Using a custom codec

The codec is fully pluggable. Supply `{ deserialize }` to use your own deserialization logic:

```javascript
const kerberos = new Kerberos([], [], { cache, codec: { deserialize: myDeserializeFn } });
```

Other eval-free options such as [`jexl`](https://github.com/TomFrost/jexl) or [`cel-js`](https://www.npmjs.com/package/cel-js) (CEL, the same expression language Cerbos uses) are good fits. Function-serializing libraries like `serialize-javascript` can also be wrapped, but only if you fully trust the store and accept the `eval`-based trust boundary they require.

To skip deserialization entirely (e.g. your cached documents are already plain JSON without `{ $expr }` descriptors), simply omit `codec`:

```javascript
const kerberos = new Kerberos([], [], { cache }); // values passed as-is to policy constructors
```
