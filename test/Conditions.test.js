const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { Conditions } = require('../src/Conditions');

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
  },
};
const variableMock = {
  isPublished: true,
};
const constantsMock = {
  label: 'Published',
};

const reqMock = {
  P: principalMock,
  principal: principalMock,
  R: resourceMock,
  resource: resourceMock,
  V: variableMock,
  variables: variableMock,
  C: constantsMock,
  constants: constantsMock,
};

describe('Conditions', () => {
  it('should match with a single function', () => {
    const condition = new Conditions({
      match: ({ V }) => V.isPublished,
    });

    assert.strictEqual(condition.isFulfilled(reqMock), true);
  });

  it('should match with any of multiple functions - true case', () => {
    const condition = new Conditions({
      match: {
        any: [({ P }) => P.attr.account.email === 'test@example.com', ({ P }) => P.attr.account.email === 'other@example.com'],
      },
    });

    assert.strictEqual(condition.isFulfilled(reqMock), true);
  });

  it('should match with any of multiple functions - false case', () => {
    const condition = new Conditions({
      match: {
        any: [({ P }) => P.attr.account.email === 'notfound@example.com', ({ P }) => P.attr.account.email === 'other@example.com'],
      },
    });

    assert.strictEqual(condition.isFulfilled(reqMock), false);
  });

  it('should match with all of multiple functions - true case', () => {
    const condition = new Conditions({
      match: {
        all: [({ P }) => P.attr.account.email === 'test@example.com', ({ P }) => P.id === 'user-123'],
      },
    });

    assert.strictEqual(condition.isFulfilled(reqMock), true);
  });

  it('should match with all of multiple functions - false case', () => {
    const condition = new Conditions({
      match: {
        all: [({ P }) => P.attr.account.email === 'test@example.com', ({ P }) => P.id === 'user-999'],
      },
    });

    assert.strictEqual(condition.isFulfilled(reqMock), false);
  });

  it('should match with none of multiple functions - true case', () => {
    const condition = new Conditions({
      match: {
        none: [({ P }) => P.attr.account.email === 'notfound@example.com', ({ P }) => P.id === 'user-999'],
      },
    });

    assert.strictEqual(condition.isFulfilled(reqMock), true);
  });

  it('should match with none of multiple functions - false case', () => {
    const condition = new Conditions({
      match: {
        none: [({ P }) => P.attr.account.email === 'test@example.com', ({ P }) => P.id === 'user-999'],
      },
    });

    assert.strictEqual(condition.isFulfilled(reqMock), false);
  });

  it('should match with invalid schema', () => {
    assert.throws(() => {
      // eslint-disable-next-line no-new
      new Conditions({ invalidKey: 'invalidValue' });
    });
  });

  it('should match with nested conditions - true case', () => {
    const condition = new Conditions({
      match: {
        all: [
          ({ P }) => P.id === 'user-123',
          {
            any: [({ P }) => P.attr.account.email === 'test@example.com', ({ P }) => P.attr.account.email === 'other@example.com'],
            none: [({ P }) => P.attr.account.email === 'test@example.com', ({ P }) => P.id === 'user-999'],
          },
        ],
      },
    });

    assert.strictEqual(condition.isFulfilled(reqMock), true);
  });

  it('should match with nested conditions - false case', () => {
    const condition = new Conditions({
      match: {
        all: [
          ({ P }) => P.id === 'user-123',
          {
            any: [({ P }) => P.attr.account.email === '', ({ P }) => P.attr.account.email === ''],
            none: [({ P }) => P.attr.account.email === '', ({ P }) => P.id === 'user-999'],
          },
        ],
      },
    });

    assert.strictEqual(condition.isFulfilled(reqMock), false);
  });

  it('should match with constants - true case', () => {
    const condition = new Conditions({
      match: ({ C }) => C.label === 'Published',
    });

    assert.strictEqual(condition.isFulfilled(reqMock), true);
  });

  it('should match with constants - false case', () => {
    const condition = new Conditions({
      match: ({ C }) => C.label === 'Unpublished',
    });

    assert.strictEqual(condition.isFulfilled(reqMock), false);
  });
});
