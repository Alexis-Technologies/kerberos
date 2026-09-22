const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const {
  Effect,
  Kerberos,
  createSafeExprCodec,
  deserializePolicy,
  serializePolicy,
  KerberosExprError,
} = require('../src/index.js');

const jsepModule = require('jsep');
const jsep = jsepModule.default || jsepModule;
jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));
jsep.addUnaryOp('typeof');

const strictCodec = createSafeExprCodec({ jsep });
const jsCodec = createSafeExprCodec({ jsep, relational: 'js' });

// Pairs CEL compares (verified against a live Cerbos 0.55.0 PDP): number with
// number (int/double mixed), string with string (lexicographic) and boolean
// with boolean (false < true).
const COMPARABLE = [
  { a: 1, b: 2, lt: true, ge: false },
  { a: 2.5, b: 3, lt: true, ge: false },
  { a: 3, b: 3, lt: false, ge: true },
  { a: 'a', b: 'b', lt: true, ge: false },
  { a: '5', b: '10', lt: false, ge: true },
  { a: false, b: true, lt: true, ge: false },
  { a: true, b: false, lt: false, ge: true },
];

// Pairings CEL has no overload for. JavaScript coerces every one of them.
const INCOMPARABLE = [
  { a: '500', b: 1000, js: { lt: true, ge: false } },
  { a: 1000, b: '500', js: { lt: false, ge: true } },
  { a: null, b: 1000, js: { lt: true, ge: false } },
  { a: [999], b: 1000, js: { lt: true, ge: false } },
  { a: true, b: 1, js: { lt: false, ge: true } },
  { a: 1, b: true, js: { lt: false, ge: true } },
  { a: {}, b: 1, js: { lt: false, ge: false } },
  { a: 1, b: null, js: { lt: false, ge: true } },
];

const OPERATORS = ['<', '<=', '>', '>='];

describe('relational operator semantics', () => {
  describe('strict mode (the default, CEL parity)', () => {
    it('compares operands of the same comparable type', () => {
      for (const { a, b, lt, ge } of COMPARABLE) {
        const ctx = { R: { attr: { a, b } } };
        assert.strictEqual(strictCodec.compileExpr('R.attr.a < R.attr.b')(ctx), lt, `${a} < ${b}`);
        assert.strictEqual(strictCodec.compileExpr('R.attr.a >= R.attr.b')(ctx), ge, `${a} >= ${b}`);
      }
    });

    it('throws instead of coercing across types', () => {
      for (const { a, b } of INCOMPARABLE) {
        const ctx = { R: { attr: { a, b } } };
        for (const operator of OPERATORS) {
          assert.throws(
            () => strictCodec.compileExpr(`R.attr.a ${operator} R.attr.b`)(ctx),
            KerberosExprError,
            `${JSON.stringify(a)} ${operator} ${JSON.stringify(b)}`,
          );
        }
      }
    });

    it('names both operand types in the error message', () => {
      assert.throws(() => strictCodec.compileExpr('R.attr.a < R.attr.b')({ R: { attr: { a: '5', b: 10 } } }), {
        name: 'KerberosExprError',
        message: /Cannot compare string with number using "<"/,
      });
      assert.throws(() => strictCodec.compileExpr('R.attr.a < R.attr.b')({ R: { attr: { a: null, b: 1 } } }), {
        message: /Cannot compare null with number/,
      });
      assert.throws(() => strictCodec.compileExpr('R.attr.a < R.attr.b')({ R: { attr: { a: [1], b: 1 } } }), {
        message: /Cannot compare list with number/,
      });
      assert.throws(() => strictCodec.compileExpr('R.attr.a < R.attr.b')({ R: { attr: { a: {}, b: 1 } } }), {
        message: /Cannot compare map with number/,
      });
      // A missing attribute is not a type confusion — see below.
      assert.equal(strictCodec.compileExpr('R.attr.a < R.attr.b')({ R: { attr: { b: 1 } } }), false);
    });

    it('treats a missing attribute as "not satisfied", never as an error', () => {
      // Cerbos reaches the same outcome by a different route: CEL raises "no
      // such key" and the rule is skipped. Both comparison directions are
      // false either way, so an ALLOW rule stays denied and a DENY rule stays
      // unfired — which is why this must not throw (it would also break
      // planResources, where `P` is fully known and the comparison folds).
      const missing = { P: { attr: {} }, R: { attr: {} } };
      for (const operator of OPERATORS) {
        assert.equal(strictCodec.compileExpr(`P.attr.clearance ${operator} 3`)(missing), false);
        assert.equal(strictCodec.compileExpr(`3 ${operator} P.attr.clearance`)(missing), false);
      }
      assert.equal(strictCodec.compileExpr('P.attr.a < R.attr.b')(missing), false);
    });

    it('leaves equality, arithmetic and NaN/Infinity untouched', () => {
      const ctx = { R: { attr: { a: '5', b: 5 } } };
      assert.strictEqual(strictCodec.compileExpr('R.attr.a == R.attr.b')(ctx), true);
      assert.strictEqual(strictCodec.compileExpr('R.attr.a === R.attr.b')(ctx), false);
      assert.strictEqual(strictCodec.compileExpr('R.attr.b + 1')(ctx), 6);
      assert.strictEqual(strictCodec.compileExpr('R.attr.x < 1')({ R: { attr: { x: Number.NaN } } }), false);
      assert.strictEqual(strictCodec.compileExpr('R.attr.x < 1')({ R: { attr: { x: -Infinity } } }), true);
    });

    it('short-circuits before an incomparable branch is reached', () => {
      const ctx = { R: { attr: { a: '5', b: 1 } } };
      assert.strictEqual(strictCodec.compileExpr('false && R.attr.a < R.attr.b')(ctx), false);
      assert.strictEqual(strictCodec.compileExpr('true || R.attr.a < R.attr.b')(ctx), true);
    });
  });

  describe("'js' mode (opt-out)", () => {
    it('keeps JavaScript coercion', () => {
      for (const { a, b, js } of INCOMPARABLE) {
        const ctx = { R: { attr: { a, b } } };
        assert.strictEqual(jsCodec.compileExpr('R.attr.a < R.attr.b')(ctx), js.lt, `${JSON.stringify(a)} < …`);
        assert.strictEqual(jsCodec.compileExpr('R.attr.a >= R.attr.b')(ctx), js.ge, `${JSON.stringify(a)} >= …`);
      }
    });

    it('agrees with strict mode on comparable operands', () => {
      for (const { a, b, lt, ge } of COMPARABLE) {
        const ctx = { R: { attr: { a, b } } };
        assert.strictEqual(jsCodec.compileExpr('R.attr.a < R.attr.b')(ctx), lt);
        assert.strictEqual(jsCodec.compileExpr('R.attr.a >= R.attr.b')(ctx), ge);
      }
    });
  });

  it('rejects an unknown relational mode at construction', () => {
    assert.throws(() => createSafeExprCodec({ jsep, relational: 'cel' }), {
      name: 'KerberosExprError',
      message: /must be 'strict' or 'js'/,
    });
  });
});

// The policy mirrors conformance/policies/expense.yaml: an ALLOW rule gated on
// a numeric comparison. A wrongly-typed attribute must not widen access.
const expensePolicy = {
  resourcePolicy: {
    version: 'default',
    resource: 'expense',
    rules: [
      {
        actions: ['approve'],
        effect: Effect.Allow,
        roles: ['USER'],
        condition: { match: { $expr: 'R.attr.amount < 1000' } },
      },
    ],
  },
};

const user = { id: 'u1', roles: ['USER'] };

function buildEngine(codec, options = {}) {
  return new Kerberos([deserializePolicy(expensePolicy, codec)], [], options);
}

describe('relational semantics through the engine', () => {
  it('denies (fail-closed) when an attribute arrives with the wrong type', async () => {
    const kerberos = buildEngine(strictCodec, { onError: 'deny' });
    const resource = { id: 'e1', kind: 'expense', attr: { amount: true } };
    assert.strictEqual(await kerberos.isAllowed({ principal: user, action: 'approve', resource }), false);

    const response = await kerberos.checkResources({
      principal: user,
      resources: [{ resource, actions: ['approve'] }],
      includeMeta: true,
    });
    assert.strictEqual(response.results[0].actions.approve, Effect.Deny);
    assert.strictEqual(response.results[0].meta.actions.approve.reason, 'evaluation-error');
  });

  it('propagates the expression error under the default onError', async () => {
    const kerberos = buildEngine(strictCodec);
    await assert.rejects(
      kerberos.isAllowed({
        principal: user,
        action: 'approve',
        resource: { id: 'e1', kind: 'expense', attr: { amount: '500' } },
      }),
      KerberosExprError,
    );
  });

  it('still decides correctly for well-typed attributes', async () => {
    const kerberos = buildEngine(strictCodec);
    const allow = { id: 'e1', kind: 'expense', attr: { amount: 999 } };
    const deny = { id: 'e2', kind: 'expense', attr: { amount: 1000 } };
    assert.strictEqual(await kerberos.isAllowed({ principal: user, action: 'approve', resource: allow }), true);
    assert.strictEqual(await kerberos.isAllowed({ principal: user, action: 'approve', resource: deny }), false);
  });

  it("allows the widened decision only under relational: 'js'", async () => {
    const kerberos = buildEngine(jsCodec);
    assert.strictEqual(
      await kerberos.isAllowed({
        principal: user,
        action: 'approve',
        resource: { id: 'e1', kind: 'expense', attr: { amount: '500' } },
      }),
      true,
    );
  });

  it('is selectable through the engine codec option (cache-backed policies)', async () => {
    // `codec: { jsep, … }` builds the engine's own codec for policies that
    // arrive as serialized documents from the cache — the mode must ride along.
    const cache = {
      async get(key) {
        return key === 'resource:expense:default:' ? serializePolicy(expensePolicy, { jsep }) : undefined;
      },
    };
    const args = {
      principal: user,
      action: 'approve',
      resource: { id: 'e1', kind: 'expense', attr: { amount: '500' } },
    };

    const lenient = new Kerberos([], [], { cache, codec: { jsep, relational: 'js' } });
    assert.strictEqual(await lenient.isAllowed(args), true);

    const strict = new Kerberos([], [], { cache, codec: { jsep }, onError: 'deny' });
    assert.strictEqual(await strict.isAllowed(args), false);
  });
});

describe('query plans keep the runtime comparison semantics', () => {
  it('folds a known wrongly-typed attribute the same way the runtime does', async () => {
    const strictEngine = buildEngine(strictCodec);
    const args = { principal: user, action: 'approve', resource: { kind: 'expense', attr: { amount: '500' } } };
    await assert.rejects(strictEngine.planResources(args), KerberosExprError);

    const jsEngine = buildEngine(jsCodec);
    const plan = await jsEngine.planResources(args);
    assert.strictEqual(plan.filter.kind, 'KIND_ALWAYS_ALLOWED');
  });

  it('leaves an unknown attribute as a conditional filter in both modes', async () => {
    for (const codec of [strictCodec, jsCodec]) {
      const plan = await buildEngine(codec).planResources({
        principal: user,
        action: 'approve',
        resource: { kind: 'expense' },
      });
      assert.strictEqual(plan.filter.kind, 'KIND_CONDITIONAL');
    }
  });
});
