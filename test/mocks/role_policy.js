function buildUserRolePolicy({ version = 'default', scope } = {}) {
  return {
    rolePolicy: {
      role: 'USER',
      version,
      ...(scope ? { scope } : {}),
      constants: {
        restrictedVendor: 'Flux Water Gear',
      },
      variables: {
        isRestrictedVendor: ({ R, C }) => R.attr.vendor === C.restrictedVendor,
      },
      rules: [
        {
          name: 'allow_create',
          resource: 'expense',
          allowActions: ['create'],
        },
        {
          name: 'allow_view_when_not_restricted',
          resource: 'expense',
          allowActions: ['view'],
          condition: {
            match: ({ V }) => V.isRestrictedVendor === false,
          },
          output: {
            when: {
              ruleActivated: ({ P, R }) => ({
                principal: P.id,
                resource: R.id,
                message: 'Role policy allowed view',
              }),
              conditionNotMet: ({ P, R }) => ({
                principal: P.id,
                resource: R.id,
                message: 'Role policy blocked restricted vendor view',
              }),
            },
          },
        },
      ],
    },
  };
}

function buildScopedUserRolePolicy({ version = 'default', scope = 'acme.corp' } = {}) {
  return {
    rolePolicy: {
      role: 'USER',
      version,
      scope,
      rules: [
        {
          name: 'allow_scoped_delete',
          resource: 'expense',
          allowActions: ['delete'],
        },
      ],
    },
  };
}

function buildManagerRolePolicy({ version = 'default', scope } = {}) {
  return {
    rolePolicy: {
      role: 'MANAGER',
      version,
      ...(scope ? { scope } : {}),
      rules: [
        {
          name: 'allow_delete',
          resource: 'expense',
          allowActions: ['delete'],
        },
      ],
    },
  };
}

function buildLimitedManagerRolePolicy({ version = 'default', scope } = {}) {
  return {
    rolePolicy: {
      role: 'LIMITED_MANAGER',
      version,
      ...(scope ? { scope } : {}),
      parentRoles: ['USER'],
      rules: [
        {
          name: 'try_allow_delete',
          resource: 'expense',
          allowActions: ['delete'],
        },
      ],
    },
  };
}

const userRolePolicy = buildUserRolePolicy();
const scopedUserRolePolicy = buildScopedUserRolePolicy();
const managerRolePolicy = buildManagerRolePolicy();
const limitedManagerRolePolicy = buildLimitedManagerRolePolicy();

module.exports = {
  buildUserRolePolicy,
  buildScopedUserRolePolicy,
  buildManagerRolePolicy,
  buildLimitedManagerRolePolicy,
  userRolePolicy,
  scopedUserRolePolicy,
  managerRolePolicy,
  limitedManagerRolePolicy,
};
