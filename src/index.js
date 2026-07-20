// EXPR_META / evalExprAst are internal seams between the codec and the query
// planner (src/planning/) — deliberately kept out of the public surface.
const { EXPR_META, evalExprAst, ...codecExports } = require('./caching/codec.js');

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
  ...codecExports,
  ...require('./planning/expand.js'),
  ...require('./schemas'),
  ...require('./validation'),
};
