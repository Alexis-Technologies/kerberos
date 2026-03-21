module.exports = {
  ...require('./Constants/index.js'),
  ...require('./Conditions/index.js'),
  ...require('./Outputs/index.js'),
  ...require('./Variables/index.js'),
  ...require('./ResourcePolicy/index.js'),
  ...require('./DerivedRoles/index.js'),
  ...require('./Kerberos.js'),
  ...require('./schemas'),
  ...require('./validation'),
  Tests: require('./Tests/index.js'),
};
