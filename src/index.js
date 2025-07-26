module.exports = {
  ...require('./Constants/index.js'),
  ...require('./Variables/index.js'),
  ...require('./ResourcePolicy/index.js'),
  ...require('./DerivedRoles/index.js'),
  ...require('./Kerberos.js'),
  ...require('./schemas.js'),
  Tests: require('./Tests/index.js'),
};
