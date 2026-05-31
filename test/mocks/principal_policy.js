const { Effect } = require('../../src');

function buildSallyPrincipalPolicy({ version = 'default', scope } = {}) {
  return {
    principalPolicy: {
      principal: 'sally',
      version,
      ...(scope ? { scope } : {}),
      constants: {
        restrictedVendor: 'Flux Water Gear',
      },
      variables: {
        isOpenExpense: ({ R }) => R.kind === 'expense' && R.attr.status === 'OPEN',
        isRestrictedVendor: ({ R, C }) => R.attr.vendor === C.restrictedVendor,
      },
      rules: [
        {
          resource: 'expense',
          actions: [
            {
              name: 'deny_restricted_vendor_view',
              action: 'view',
              effect: Effect.Deny,
              condition: {
                match: ({ V }) => V.isRestrictedVendor === true,
              },
            },
            {
              name: 'allow_open_expense_delete',
              action: 'delete',
              effect: Effect.Allow,
              condition: {
                match: ({ V }) => V.isOpenExpense === true,
              },
              output: {
                when: {
                  ruleActivated: ({ P, R }) => ({
                    principal: P.id,
                    resource: R.id,
                    message: 'Principal override allowed delete',
                  }),
                  conditionNotMet: ({ P, R }) => ({
                    principal: P.id,
                    resource: R.id,
                    message: 'Principal override delete condition not met',
                  }),
                },
              },
            },
          ],
        },
      ],
    },
  };
}

function buildDerekPrincipalPolicy({ version = 'default', scope } = {}) {
  return {
    principalPolicy: {
      principal: 'derek',
      version,
      ...(scope ? { scope } : {}),
      rules: [
        {
          resource: '*',
          actions: [
            {
              name: 'deny_approve_everywhere',
              action: 'approve',
              effect: Effect.Deny,
            },
          ],
        },
      ],
    },
  };
}

function buildSallyScopedViewOverridePolicy({ version = 'default', scope = 'acme.corp' } = {}) {
  return {
    principalPolicy: {
      principal: 'sally',
      version,
      scope,
      rules: [
        {
          resource: 'expense',
          actions: [
            {
              name: 'allow_scoped_view',
              action: 'view',
              effect: Effect.Allow,
            },
          ],
        },
      ],
    },
  };
}

const sallyPrincipalPolicy = buildSallyPrincipalPolicy();
const sallyScopedPrincipalPolicy = buildSallyPrincipalPolicy({ version: '20210210', scope: 'acme.corp' });
const sallyScopedViewOverridePolicy = buildSallyScopedViewOverridePolicy();
const derekPrincipalPolicy = buildDerekPrincipalPolicy();

module.exports = {
  buildSallyPrincipalPolicy,
  buildDerekPrincipalPolicy,
  buildSallyScopedViewOverridePolicy,
  sallyPrincipalPolicy,
  sallyScopedPrincipalPolicy,
  sallyScopedViewOverridePolicy,
  derekPrincipalPolicy,
};
