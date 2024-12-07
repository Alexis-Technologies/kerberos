module.exports = {
  ...require('./ResourcePolicy/index.js'),
  ...require('./DerivedRoles/index.js'),
  ...require('./Kerberos.js'),
  ...require('./schemas.js'),
  Tests: require('./Tests/index.js'),
};
