# Allowed safe builtins

What a `{ $expr }` string in a [dynamic policy](/guide/caching) or a ReBAC caveat is allowed to reference.

The default codec exposes a small, allowlisted subset of JavaScript that is useful in policy conditions without opening an `eval` trust boundary:

| Category | Supported constructs |
| -------- | -------------------- |
| **Math** | `Math.abs`, `Math.min`, `Math.max`, `Math.floor`, `Math.ceil`, `Math.round`, `Math.pow`, ... |
| **Date** | `new Date()`, `new Date(value)`, `Date.now()`, `Date.parse(...)`, `Date.UTC(...)`, and read-only instance methods such as `.getTime()`, `.getHours()`, `.toISOString()` |
| **Coercion / parsing** | `parseInt(...)`, `parseFloat(...)`, `Number(...)`, `String(...)`, `Boolean(...)`, `isNaN(...)`, `isFinite(...)` |
| **Value helpers** | Safe string/array methods such as `.includes()`, `.startsWith()`, `.slice()`, ... |

Anything outside this list — arbitrary constructors (`new Function`, `new Object`, ...), global roots like `process` / `require` / `globalThis`, or member keys such as `constructor` / `__proto__` — is rejected by the AST allowlist interpreter.

Example: a time-window condition in `{ $expr }` form:

```json
{
  "condition": {
    "match": {
      "$expr": "(Date.now() - new Date(R.attr.createdAt).getTime()) < 3600000 && R.attr.status == 'OPEN'"
    }
  }
}
```
