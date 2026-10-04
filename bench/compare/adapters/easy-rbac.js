/** easy-rbac: operations as `resource:action` strings, ownership as an async `when`. */
module.exports = {
  id: 'easy-rbac',
  name: 'easy-rbac',
  packageName: 'easy-rbac',
  variant: 'can(roles, operation, params)',
  runtime: 'in-process',
  coldStart: true,
  load() {
    return require('easy-rbac');
  },
  setup(RBAC, scenario) {
    let can;
    if (scenario.id === 'rbac') can = ['post:view'];
    else if (scenario.id === 'abac' || scenario.id === 'batch') {
      can = [{ name: 'document:view', when: async (params) => params.ownerId === params.userId }];
    } else if (scenario.id === 'rules') can = scenario.ruleActions.map((action) => `report:${action}`);
    const rbac = new RBAC({ USER: { can }, GUEST: { can: [] } });

    const ask = (principal, resource, action) => {
      const params = { userId: principal.id, ownerId: resource.attr.ownerId };
      const operation = `${resource.kind}:${action}`;
      return () => rbac.can(principal.roles, operation, params);
    };
    return {
      prepare: ({ principal, resource, action }) => ask(principal, resource, action),
      prepareBatch(principal) {
        const checks = scenario.resources.map((resource) => ask(principal, resource, scenario.action));
        return async () => {
          const decisions = await Promise.all(checks.map((check) => check()));
          const ids = [];
          for (let i = 0; i < decisions.length; i++) if (decisions[i]) ids.push(scenario.resources[i].id);
          return ids;
        };
      },
    };
  },
};
