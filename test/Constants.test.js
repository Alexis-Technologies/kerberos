const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const { Constants } = require('../src/Constants');

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

const constantsSchema = {
  isPublished: true,
  label: 'Published',
  teams: ['red', 'blue'],
  lookup: { red: 9001, blue: 0 },
};

const reqMock = {
  P: principalMock,
  principal: principalMock,
  R: resourceMock,
  resource: resourceMock,
};

describe('Constants', () => {
  it('should return variables', () => {
    const variables = new Constants(constantsSchema);

    assert.deepStrictEqual(variables.get(reqMock), {
      isPublished: true,
      label: 'Published',
      teams: ['red', 'blue'],
      lookup: { red: 9001, blue: 0 },
    });
  });

  it('should throw an error with an invalid schema', () => {
    assert.throws(() => {
      // eslint-disable-next-line no-new
      new Constants(new Map());
    });
  });
});
