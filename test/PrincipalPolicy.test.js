const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { principalsPolicy, resourcesPolicy, sallyPrincipalPolicy, derekPrincipalPolicy } = require('./mocks/index.js');
const { Effect, PrincipalPolicy } = require('../src/index.js');

describe('PrincipalPolicy', () => {
  const principalPolicy = new PrincipalPolicy(sallyPrincipalPolicy);

  it('should expose principal target and rules', () => {
    assert.strictEqual(principalPolicy.principal, 'sally');
    assert.strictEqual(principalPolicy.version, 'default');
    assert.strictEqual(principalPolicy.rules.length, 1);
  });

  it('should return only explicit effects and keep unmatched actions not applicable', () => {
    const principal = principalsPolicy.sally;
    const resource = resourcesPolicy.expense1;
    const req = { P: principal, principal, R: resource, resource, actions: ['view', 'delete', 'create'] };

    const { effects, outputs, meta } = principalPolicy.check(req);

    assert.deepStrictEqual(Object.fromEntries(effects), {
      view: Effect.Deny,
      delete: Effect.Allow,
    });
    assert.strictEqual(outputs.size, 1);
    assert.strictEqual(outputs.values().next().value.val.message, 'Principal override allowed delete');
    assert.strictEqual(meta.actions.view.matchedPolicy, 'principal.sally.vdefault');
    assert.strictEqual(meta.actions.delete.matchedPolicy, 'principal.sally.vdefault');
    assert.strictEqual(meta.actions.create, undefined);
  });

  it('should keep unmatched conditions as not applicable while emitting conditionNotMet output', () => {
    const principal = principalsPolicy.sally;
    const resource = resourcesPolicy.expense2;
    const req = { P: principal, principal, R: resource, resource, actions: ['delete'] };

    const { effects, outputs, meta } = principalPolicy.check(req);

    assert.deepStrictEqual(Object.fromEntries(effects), {});
    assert.strictEqual(outputs.size, 1);
    assert.strictEqual(outputs.values().next().value.val.message, 'Principal override delete condition not met');
    assert.deepStrictEqual(meta.actions, {});
  });

  it('should support wildcard resource matching', () => {
    const wildcardPolicy = new PrincipalPolicy(derekPrincipalPolicy);
    const principal = principalsPolicy.derek;
    const resource = resourcesPolicy.expense1;
    const req = { P: principal, principal, R: resource, resource, actions: ['approve', 'create'] };

    const { effects } = wildcardPolicy.check(req);

    assert.deepStrictEqual(Object.fromEntries(effects), {
      approve: Effect.Deny,
    });
  });
});
