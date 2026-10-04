/**
 * casbin with an in-memory model. The principal's roles arrive with the
 * request (as in every other adapter), so the matcher tests them directly
 * instead of through a `g` role-assignment table.
 */
const MODEL = (extraCondition) => `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub.Roles.includes(p.sub) && r.obj.Kind == p.obj && r.act == p.act${extraCondition}
`;

function modelAndPolicy(scenario) {
  switch (scenario.id) {
    case 'rbac':
      return { model: MODEL(''), lines: ['p, USER, post, view'] };
    case 'abac':
    case 'batch':
      return { model: MODEL(' && r.obj.OwnerId == r.sub.Id'), lines: ['p, USER, document, view'] };
    case 'rules':
      return { model: MODEL(''), lines: scenario.ruleActions.map((action) => `p, USER, report, ${action}`) };
    default:
      throw new Error(`no policy for scenario "${scenario.id}"`);
  }
}

const toSub = (principal) => ({ Id: principal.id, Roles: principal.roles });
const toObj = (resource) => ({ Kind: resource.kind, Id: resource.id, OwnerId: resource.attr.ownerId });

module.exports = {
  id: 'casbin',
  name: 'casbin',
  packageName: 'casbin',
  variant: 'enforce · batchEnforce',
  runtime: 'in-process',
  coldStart: true,
  load() {
    return require('casbin');
  },
  async setup({ newEnforcer, newModelFromString, StringAdapter }, scenario) {
    const { model, lines } = modelAndPolicy(scenario);
    const enforcer = await newEnforcer(newModelFromString(model), new StringAdapter(lines.join('\n')));
    return {
      prepare({ principal, resource, action }) {
        const sub = toSub(principal);
        const obj = toObj(resource);
        return () => enforcer.enforce(sub, obj, action);
      },
      prepareBatch(principal) {
        const sub = toSub(principal);
        const requests = scenario.resources.map((resource) => [sub, toObj(resource), scenario.action]);
        return async () => {
          const decisions = await enforcer.batchEnforce(requests);
          const ids = [];
          for (let i = 0; i < decisions.length; i++) if (decisions[i]) ids.push(scenario.resources[i].id);
          return ids;
        };
      },
    };
  },
};
