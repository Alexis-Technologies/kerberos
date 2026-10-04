/**
 * @rbac/rbac: `can(role, operation, params)` takes ONE role, so the adapter
 * asks role by role until one allows (every scenario principal has one role).
 */
module.exports = {
  id: 'rbac',
  name: '@rbac/rbac',
  packageName: '@rbac/rbac',
  variant: 'can(role, operation, params)',
  runtime: 'in-process',
  coldStart: true,
  load() {
    return require('@rbac/rbac').default;
  },
  setup(RBAC, scenario) {
    let can;
    if (scenario.id === 'rbac') can = ['post:view'];
    else if (scenario.id === 'abac' || scenario.id === 'batch') {
      can = [{ name: 'document:view', when: async (params) => params.ownerId === params.userId }];
    } else if (scenario.id === 'rules') can = scenario.ruleActions.map((action) => `report:${action}`);
    const rbac = RBAC({ enableLogger: false })({ USER: { can }, GUEST: { can: [] } });

    const ask = (principal, resource, action) => {
      const params = { userId: principal.id, ownerId: resource.attr.ownerId };
      const operation = `${resource.kind}:${action}`;
      const [first, ...rest] = principal.roles;
      if (rest.length === 0) return () => rbac.can(first, operation, params);
      return async () => {
        for (const role of principal.roles) if (await rbac.can(role, operation, params)) return true;
        return false;
      };
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
