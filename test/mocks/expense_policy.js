const { Effect } = require('../../src');

const expensePolicy = {
  resourcePolicy: {
    version: 'default',
    // Importing `common_roles` so they can be used in the resource policy.
    importDerivedRoles: ['common_roles'],
    // This resource file is reviewed for when checking permissions when a resource
    // is of `kind` "expense:object"
    resource: 'expense',
    rules: [
      // Rule 1: If the principal's role is 'ADMIN', then all actions are allowed.
      {
        actions: ['*'],
        effect: Effect.Allow,
        roles: ['ADMIN'],
      },
      // Rule 2: Principal with derived roles 'OWNER', 'FINANCE', or 'REGION_MANAGER' can perform 'view'.
      {
        actions: ['view'],
        effect: Effect.Allow,
        derivedRoles: ['OWNER', 'FINANCE', 'REGION_MANAGER'],
      },
      // Rule 3: Principal with derived roles 'FINANCE' or 'FINANCE_MANAGER' can perform 'view:approver'.
      {
        actions: ['view:approver'],
        effect: Effect.Allow,
        derivedRoles: ['FINANCE', 'FINANCE_MANAGER'],
      },
      // Rule 4: Owner can 'view:approver' if the resource is 'APPROVED'.
      {
        actions: ['view:approver'],
        effect: Effect.Allow,
        derivedRoles: ['OWNER'],
        condition: {
          match: ({ R }) => R.attr.status === 'APPROVED',
        },
      },
      // Rule 5: Roles 'USER' and 'MANAGER' can 'create'.
      {
        actions: ['create'],
        effect: Effect.Allow,
        roles: ['USER', 'MANAGER'],
      },
      // Rule 6: Owner can 'update' if the resource status is 'OPEN'.
      {
        actions: ['update'],
        effect: Effect.Allow,
        derivedRoles: ['OWNER'],
        condition: {
          match: ({ R }) => R.attr.status === 'OPEN',
        },
      },
      // Rule 7: 'FINANCE' or 'FINANCE_MANAGER' can 'approve' if they did not create it and status is 'OPEN'.
      {
        actions: ['approve'],
        effect: Effect.Allow,
        derivedRoles: ['FINANCE', 'FINANCE_MANAGER'],
        condition: {
          match: {
            all: [
              ({ R, P }) => R.attr.ownerId !== P.id,
              ({ R }) => R.attr.status === 'OPEN',
            ],
          },
        },
      },
      // Rule 8: Deny 'approve' to 'USER' role if not a 'MANAGER' and amount > 10000.
      {
        actions: ['approve'],
        effect: Effect.Deny,
        roles: ['USER'],
        condition: {
          match: {
            all: [
              ({ P }) => !P.roles.includes('MANAGER'),
              ({ R }) => R.attr.amount > 10000,
            ],
          },
        },
        // output: ({ P, R }) => ({
        //   principal: P.id,
        //   resource: R.id,
        //   amount: R.attr.amount,
        //   message: 'Finance team members can only approve up to $10,000',
        // }),
      },
      // Rule 9: 'FINANCE_MANAGER' can 'delete'.
      {
        actions: ['delete'],
        effect: Effect.Allow,
        derivedRoles: ['FINANCE_MANAGER'],
      },
      // Rule 10: Owner can 'delete' if status is 'OPEN' and created within the last hour.
      {
        actions: ['delete'],
        effect: Effect.Allow,
        derivedRoles: ['OWNER'],
        condition: {
          match: {
            all: [
              ({ R }) => R.attr.status === 'OPEN',
              ({ R }) => {
                const createdAt = new Date(R.attr.createdAt);
                const now = new Date();
                const timeSince = now - createdAt; // Time in milliseconds
                const oneHour = 60 * 60 * 1000; // Milliseconds in one hour
                return timeSince < oneHour;
              },
            ],
          },
        },
      },
    ],
  },
};

module.exports = { expensePolicy };
