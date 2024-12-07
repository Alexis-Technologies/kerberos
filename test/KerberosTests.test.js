const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { expenseTestPolicy, expensePolicy, commonRolesPolicy } = require('./mocks/index.js');

const { KerberosTests } = require('../src/Tests/index.js');
const { Kerberos } = require('../src/index.js');

describe('KerberosTests', () => {
  describe('Expense Policy (raw mode)', () => {
    const kerberos = new Kerberos([expensePolicy], [commonRolesPolicy], { logger: true });
    const tests = new KerberosTests(kerberos, [expenseTestPolicy]);

    tests.run({}, { describe, it, assert });
  });
});
