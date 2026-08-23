// Re-exports the handful of public names that live in modules whose FULL export
// surface must stay internal — the codec (its EXPR_META / evalExprAst planner
// seams are private) and the plan-node model (only the filter-kind enum is
// public). Spreading those modules directly into src/index.js would leak the
// internal seams; listing the names here as plain shorthand `module.exports`
// keeps them detectable by cjs-module-lexer (Node's CJS→ESM named-export
// analyzer) when src/index.js re-exports this module with `...require(...)`.
//
// Why a dedicated module and not inline `key: value` properties in index.js:
// cjs-module-lexer follows `...require('./x')` re-exports and shorthand
// identifier keys, but BAILS on `key: obj.member` properties (and on
// `...localVariable` spreads), silently dropping every export after them from
// the ESM named surface. Keeping index.js built only from `...require()`
// spreads is what makes `import { createSafeExprCodec, PlanKind } from
// '@alexify/kerberos'` work under Node ESM.
const { createSafeExprCodec, serializePolicy, deserializePolicy, KerberosExprError } = require('./caching/codec.js');
const { PlanKind } = require('./planning/nodes.js');

module.exports = {
  createSafeExprCodec,
  serializePolicy,
  deserializePolicy,
  KerberosExprError,
  PlanKind,
};
