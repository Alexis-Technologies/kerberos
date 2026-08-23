// Build the package surface only from `...require('./file.js')` re-export
// spreads. cjs-module-lexer (Node's CJS→ESM named-export analyzer) follows
// those and shorthand identifier keys, but BAILS — silently dropping every
// later export from the ESM named surface — on a `...localVariable` spread, a
// `key: obj.member` property, or a bare-directory specifier (`./schemas`
// without `/index.js`). So: explicit `/index.js` paths, no local-var spreads,
// and names whose home module must stay partly internal (codec seams, plan-node
// helpers) are funneled through `./publicExports.js`.
module.exports = {
  ...require('./Constants/index.js'),
  ...require('./Conditions/index.js'),
  ...require('./Outputs/index.js'),
  ...require('./Variables/index.js'),
  ...require('./ResourcePolicy/index.js'),
  ...require('./PrincipalPolicy/index.js'),
  ...require('./RolePolicy/index.js'),
  ...require('./DerivedRoles/index.js'),
  ...require('./Metadata/schemas/index.js'),
  ...require('./Kerberos.js'),
  ...require('./errors.js'),
  ...require('./caching/cache.js'),
  ...require('./planning/expand.js'),
  ...require('./publicExports.js'),
  ...require('./schemas/index.js'),
  ...require('./validation/index.js'),
};
