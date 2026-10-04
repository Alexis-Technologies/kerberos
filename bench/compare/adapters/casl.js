/**
 * CASL builds an ability per user. Two adapters share this module:
 * `casl` checks against an ability built once for the user (the pure check),
 * `casl-per-request` builds the ability inside the timed call, which is the
 * realistic path when abilities are not cached between requests.
 */
function defineRules(scenario, principal, { AbilityBuilder, createMongoAbility }) {
  const { can, build } = new AbilityBuilder(createMongoAbility);
  if (principal.roles.includes('USER')) {
    if (scenario.id === 'rbac') can('view', 'post');
    else if (scenario.id === 'abac' || scenario.id === 'batch') can('view', 'document', { ownerId: principal.id });
    else if (scenario.id === 'rules') for (const action of scenario.ruleActions) can(action, 'report');
  }
  return build();
}

function createAdapter({ id, variant, perRequest, coldStart }) {
  return {
    id,
    name: 'CASL',
    packageName: '@casl/ability',
    variant,
    runtime: 'in-process',
    coldStart,
    load() {
      return require('@casl/ability');
    },
    setup(casl, scenario) {
      const toSubject = (resource) => casl.subject(resource.kind, { id: resource.id, ...resource.attr });
      return {
        prepare({ principal, resource, action }) {
          const target = toSubject(resource);
          if (perRequest) return () => defineRules(scenario, principal, casl).can(action, target);
          const ability = defineRules(scenario, principal, casl);
          return () => ability.can(action, target);
        },
        prepareBatch(principal) {
          const targets = scenario.resources.map(toSubject);
          const prebuilt = perRequest ? null : defineRules(scenario, principal, casl);
          return () => {
            const ability = prebuilt ?? defineRules(scenario, principal, casl);
            const ids = [];
            for (const target of targets) if (ability.can(scenario.action, target)) ids.push(target.id);
            return ids;
          };
        },
      };
    },
  };
}

module.exports = {
  prebuilt: createAdapter({ id: 'casl', variant: 'ability built once per user', perRequest: false, coldStart: true }),
  perRequest: createAdapter({
    id: 'casl-per-request',
    variant: 'ability built per request',
    perRequest: true,
    coldStart: false,
  }),
};
