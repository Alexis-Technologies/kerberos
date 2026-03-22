const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const Ajv = require('ajv');
const { Type } = require('@sinclair/typebox');

const {
  Conditions,
  Constants,
  JsonSchemas,
  Kerberos,
  KerberosJsonSchemas,
  KerberosTypeBoxSchemas,
  PrincipalPolicyJsonSchemas,
  PrincipalPolicyTypeBoxSchemas,
  ResourcePolicyJsonSchemas,
  ResourcePolicyTypeBoxSchemas,
  TypeBoxSchemas,
  createAjvAdapter,
  registerAjvKeywords,
} = require('../src/index.js');
const { commonRolesPolicy, expensePolicy, principalsPolicy, resourcesPolicy, sallyPrincipalPolicy } = require('./mocks/index.js');

function createAjv() {
  return registerAjvKeywords(new Ajv({ allErrors: true, strict: false }));
}

describe('Validation backends', () => {
  it('should validate Constants with Ajv JSON Schema support', () => {
    const ajv = createAjv();

    assert.throws(() => {
      // eslint-disable-next-line no-new
      new Constants(42, { ajv });
    });
  });

  it('should validate Conditions with TypeBox and Ajv support', () => {
    const ajv = createAjv();

    assert.throws(() => {
      // eslint-disable-next-line no-new
      new Conditions({ match: 42 }, { ajv, typebox: Type });
    });
  });

  it('should expose JSON Schema builders that work with Ajv adapters', () => {
    const ajv = createAjv();
    const validator = createAjvAdapter(ajv, JsonSchemas.buildRequest());

    assert.doesNotThrow(() => {
      validator.parse({
        principal: principalsPolicy.sally,
        resource: resourcesPolicy.expense1,
        P: principalsPolicy.sally,
        R: resourcesPolicy.expense1,
        actions: ['view'],
      });
    });

    assert.throws(() => {
      validator.parse({
        principal: principalsPolicy.sally,
      });
    });
  });

  it('should build Kerberos argument schemas for JSON Schema and TypeBox', () => {
    const ajv = createAjv();
    const jsonValidator = createAjvAdapter(ajv, KerberosJsonSchemas.buildCheckResourcesArgs());
    const typeBoxValidator = createAjvAdapter(ajv, KerberosTypeBoxSchemas.buildCheckResourcesArgs(Type));
    const args = {
      principal: principalsPolicy.sally,
      resources: [{ resource: resourcesPolicy.expense1, actions: ['view'] }],
      includeMeta: true,
    };

    assert.doesNotThrow(() => jsonValidator.parse(args));
    assert.doesNotThrow(() => typeBoxValidator.parse(args));
  });

  it('should expose ResourcePolicy builders for JSON Schema and TypeBox', () => {
    const ajv = createAjv();
    const jsonValidator = createAjvAdapter(ajv, ResourcePolicyJsonSchemas.buildShape());
    const typeBoxValidator = createAjvAdapter(ajv, ResourcePolicyTypeBoxSchemas.buildShape(Type));

    assert.doesNotThrow(() => jsonValidator.parse(expensePolicy));
    assert.doesNotThrow(() => typeBoxValidator.parse(expensePolicy));
  });

  it('should expose PrincipalPolicy builders for JSON Schema and TypeBox', () => {
    const ajv = createAjv();
    const jsonValidator = createAjvAdapter(ajv, PrincipalPolicyJsonSchemas.buildShape());
    const typeBoxValidator = createAjvAdapter(ajv, PrincipalPolicyTypeBoxSchemas.buildShape(Type));

    assert.doesNotThrow(() => jsonValidator.parse(sallyPrincipalPolicy));
    assert.doesNotThrow(() => typeBoxValidator.parse(sallyPrincipalPolicy));
  });

  it('should authorize requests with Ajv JSON Schema support', async () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy], { ajv: createAjv() });

    const result = await kerberos.checkResources({
      principal: principalsPolicy.sally,
      resources: [{ resource: resourcesPolicy.expense1, actions: ['view', 'approve'] }],
    });

    assert.deepStrictEqual(result.results[0].actions, {
      view: 'EFFECT_ALLOW',
      approve: 'EFFECT_DENY',
    });
  });

  it('should authorize mixed principal and resource policies with Ajv JSON Schema support', async () => {
    const kerberos = new Kerberos([expensePolicy, sallyPrincipalPolicy], [commonRolesPolicy], { ajv: createAjv() });

    const result = await kerberos.checkResources({
      principal: principalsPolicy.sally,
      resources: [{ resource: resourcesPolicy.expense1, actions: ['view', 'delete', 'create'] }],
    });

    assert.deepStrictEqual(result.results[0].actions, {
      view: 'EFFECT_DENY',
      delete: 'EFFECT_ALLOW',
      create: 'EFFECT_ALLOW',
    });
  });

  it('should authorize requests with TypeBox and Ajv support', async () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy], {
      ajv: createAjv(),
      typebox: Type,
    });

    const isAllowed = await kerberos.isAllowed({
      principal: principalsPolicy.sally,
      resource: resourcesPolicy.expense1,
      action: 'view',
    });

    assert.strictEqual(isAllowed, true);
  });

  it('should expose TypeBox request builders', () => {
    const ajv = createAjv();
    const validator = createAjvAdapter(ajv, TypeBoxSchemas.buildRequest(Type));

    assert.doesNotThrow(() => {
      validator.parse({
        principal: principalsPolicy.sally,
        resource: resourcesPolicy.expense1,
        P: principalsPolicy.sally,
        R: resourcesPolicy.expense1,
        actions: ['view'],
      });
    });
  });
});
