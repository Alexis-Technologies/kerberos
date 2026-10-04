const path = require('node:path');

const EFFECT_ALLOW = 'EFFECT_ALLOW';

function policiesFor(scenario) {
  switch (scenario.id) {
    case 'rbac':
      return [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'post',
            rules: [{ actions: ['view'], effect: EFFECT_ALLOW, roles: ['USER'] }],
          },
        },
      ];
    case 'abac':
    case 'batch':
      return [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'document',
            rules: [
              {
                actions: ['view'],
                effect: EFFECT_ALLOW,
                roles: ['USER'],
                condition: { match: ({ P, R }) => R.attr.ownerId === P.id },
              },
            ],
          },
        },
      ];
    case 'rules':
      return [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'report',
            rules: scenario.ruleActions.map((action) => ({ actions: [action], effect: EFFECT_ALLOW, roles: ['USER'] })),
          },
        },
      ];
    default:
      throw new Error(`no policy for scenario "${scenario.id}"`);
  }
}

module.exports = {
  id: 'kerberos',
  name: 'Kerberos.js',
  packageName: '@alexify/kerberos',
  variant: 'isAllowed · checkResources',
  runtime: 'in-process',
  coldStart: true,
  load() {
    return require(path.join(__dirname, '..', '..', '..', 'index.js'));
  },
  setup({ Kerberos }, scenario) {
    const engine = new Kerberos(policiesFor(scenario), []);
    return {
      prepare: (request) => () => engine.isAllowed(request),
      prepareBatch(principal) {
        const resources = scenario.resources.map((resource) => ({ resource, actions: [scenario.action] }));
        return async () => {
          const { results } = await engine.checkResources({ principal, resources }, true);
          const ids = [];
          for (const result of results) if (result.actions[scenario.action]) ids.push(result.resource.id);
          return ids;
        };
      },
    };
  },
};
