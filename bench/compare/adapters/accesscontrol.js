/**
 * AccessControl v3 (ESM-only; loaded through require(esm), Node >= 22.12).
 * Ownership uses its enforced `own` possession with `ownerField`; checks go
 * through `tryCan`, the fail-closed entry point (an unknown role is a denial,
 * not a throw).
 */
module.exports = {
  id: 'accesscontrol',
  name: 'AccessControl',
  packageName: 'accesscontrol',
  variant: 'tryCan(…).do(…)',
  runtime: 'in-process',
  coldStart: true,
  load() {
    return require('accesscontrol');
  },
  setup({ AccessControl }, scenario) {
    const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    const owned = scenario.id === 'abac' || scenario.id === 'batch';
    if (scenario.id === 'rbac') {
      ac.grant('USER').action('view', 'post');
    } else if (owned) {
      ac.grant('USER').action('view:own', 'document');
    } else if (scenario.id === 'rules') {
      for (const action of scenario.ruleActions) ac.grant('USER').action(action, 'report');
    }

    const ask = (principal, resource, action) => {
      const context = owned ? { user: { id: principal.id }, [resource.kind]: resource.attr } : undefined;
      const verb = owned ? `${action}:own` : action;
      return () => ac.tryCan(principal.roles, context).do(verb, resource.kind).granted;
    };
    return {
      prepare: ({ principal, resource, action }) => ask(principal, resource, action),
      prepareBatch(principal) {
        const checks = scenario.resources.map((resource) => ask(principal, resource, scenario.action));
        return () => {
          const ids = [];
          for (let i = 0; i < checks.length; i++) if (checks[i]()) ids.push(scenario.resources[i].id);
          return ids;
        };
      },
    };
  },
};
