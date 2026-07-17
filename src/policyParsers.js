const { Conditions } = require('./Conditions');
const { Constants } = require('./Constants');
const { Outputs } = require('./Outputs');
const { Variables } = require('./Variables');

/**
 * Shared DSL building-block parsers used by every policy class
 * (ResourcePolicy / PrincipalPolicy / RolePolicy / DerivedRoles). Each policy
 * class exposes thin static wrappers around these for API compatibility.
 */

function parseConstants(constants, options = {}) {
  return constants instanceof Constants ? constants : new Constants(constants, options);
}

function parseVariables(variables, options = {}) {
  return variables instanceof Variables ? variables : new Variables(variables, options);
}

function parseConditions(conditions, options = {}) {
  if (!conditions) return undefined;
  return conditions instanceof Conditions ? conditions : new Conditions(conditions, options);
}

function parseOutputs(outputs, options = {}) {
  if (!outputs) return undefined;
  return outputs instanceof Outputs ? outputs : new Outputs(outputs, options);
}

module.exports = {
  parseConditions,
  parseConstants,
  parseOutputs,
  parseVariables,
};
