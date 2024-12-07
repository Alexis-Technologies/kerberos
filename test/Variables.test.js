const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { Variables } = require('../src/Variables/index.js');

const principalMock = {
  id: 'user-123',
  roles: ['admin'],
  attr: {
    account: {
      email: 'test@example.com',
    },
    company: {
      ownerId: 'user-123',
      userRole: 0,
      id: 'company-456',
    },
  },
};
const resourceMock = {
  id: 'resource-abc',
  kind: 'resource',
  attr: {
    ownerId: 'user-123',
    companyId: 'company-456',
    assignee: 'user-789',
    publishedAt: '2021-01-01T00:00:00Z',
  },
};

const variableSchema = {
  isPublished: ({ R }) => R.attr.publishedAt != null && R.attr.publishedAt?.length > 0,
  label: ({ R }) => R.attr.publishedAt ? 'Published' : 'Unpublished',
  teams: () => ['red', 'blue'],
  lookup: () => ({ red: 9001, blue: 0 }),
};

const reqMock = {
  P: principalMock,
  principal: principalMock,
  R: resourceMock,
  resource: resourceMock,
};

describe('Variables', () => {
  it('should return variables', () => {
    const variables = new Variables(variableSchema);

    assert.deepStrictEqual(variables.get(reqMock), {
      isPublished: true,
      label: 'Published',
      teams: ['red', 'blue'],
      lookup: { red: 9001, blue: 0 },
    });
  });

  it('should return variables with a missing value', () => {
    const variables = new Variables({
      ...variableSchema,
      missing: ({ R }) => R.attr.missing != null,
    });

    assert.deepStrictEqual(variables.get(reqMock), {
      isPublished: true,
      label: 'Published',
      teams: ['red', 'blue'],
      lookup: { red: 9001, blue: 0 },
      missing: false,
    });
  });

  it('should throw an error with an invalid schema', () => {
    assert.throws(() => {
      // eslint-disable-next-line no-new
      new Variables({ invalidKey: 'invalidValue' });
    });
  });
});
