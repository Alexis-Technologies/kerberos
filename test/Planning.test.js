const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const { EXPR_META, evalExprAst } = require('../src/caching/codec.js');
const {
  FALSE,
  TRUE,
  andNode,
  exprNode,
  fromOperand,
  notNode,
  opaqueNode,
  orNode,
  relationNode,
  toDebugString,
  toFilter,
  toOperand,
} = require('../src/planning/nodes.js');
const { createExprPlanner } = require('../src/planning/partialEval.js');
const { createSafeExprCodec } = require('../src/index.js');

const jsepModule = require('jsep');
const jsep = jsepModule.default || jsepModule;
jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));
jsep.addUnaryOp('typeof');

const codec = createSafeExprCodec({ jsep });

const eqExpr = (variable, value) => exprNode({ expression: { operator: 'eq', operands: [{ variable }, { value }] } });

describe('Planning', () => {
  describe('codec seams (EXPR_META / evalExprAst)', () => {
    it('attaches frozen, non-enumerable meta to compiled closures', () => {
      const fn = codec.compileExpr('R.attr.a > 1');
      const meta = fn[EXPR_META];
      assert.ok(meta);
      assert.strictEqual(meta.expr, 'R.attr.a > 1');
      assert.strictEqual(typeof meta.ast, 'object');
      assert.ok(meta.roots.has('R'));
      assert.ok(Object.isFrozen(meta));
      // Non-enumerable: invisible to serialization and key walks.
      assert.deepStrictEqual(Object.keys(fn), []);
      assert.strictEqual(JSON.stringify({ fn }), '{}');
    });

    it('deep-freezes the shared cached AST (cache poisoning impossible)', () => {
      const fn = codec.compileExpr('R.attr.qty > 10 && P.roles.includes("USER")');
      const { ast } = fn[EXPR_META];
      assert.ok(Object.isFrozen(ast));
      // Nested nodes and argument arrays are frozen too.
      assert.ok(Object.isFrozen(ast.left));
      assert.ok(Object.isFrozen(ast.left.right));
      assert.ok(Object.isFrozen(ast.right.arguments));
      // A strict-mode mutation attempt throws instead of silently poisoning
      // every consumer of this cached expression.
      assert.throws(() => {
        'use strict';
        ast.left.right.value = 1;
      }, TypeError);
    });

    it('evalExprAst evaluates an AST with the default roots', () => {
      const { ast } = codec.compileExpr('P.id === "u1" && C.limit > 2')[EXPR_META];
      assert.strictEqual(evalExprAst(ast, { P: { id: 'u1' }, C: { limit: 3 } }), true);
      assert.strictEqual(evalExprAst(ast, { P: { id: 'u2' }, C: { limit: 3 } }), false);
    });

    it('evalExprAst honors custom roots', () => {
      const caveatCodec = createSafeExprCodec({ jsep, roots: ['P', 'ctx'] });
      const { ast } = caveatCodec.compileExpr('ctx.ip === "10.0.0.1"')[EXPR_META];
      assert.strictEqual(evalExprAst(ast, { ctx: { ip: '10.0.0.1' } }, { roots: ['P', 'ctx'] }), true);
    });
  });

  describe('nodes: normalization', () => {
    const a = eqExpr('request.resource.attr.a', 1);
    const b = eqExpr('request.resource.attr.b', 2);

    it('and: absorbing false, identity true, flatten, unwrap', () => {
      assert.strictEqual(andNode([a, FALSE, b]), FALSE);
      assert.deepStrictEqual(andNode([TRUE, a]), a);
      assert.deepStrictEqual(andNode([andNode([a, b]), TRUE]), { t: 'and', children: [a, b] });
      assert.strictEqual(andNode([]), TRUE);
    });

    it('or: absorbing true, identity false, flatten, unwrap', () => {
      assert.strictEqual(orNode([a, TRUE, b]), TRUE);
      assert.deepStrictEqual(orNode([FALSE, a]), a);
      assert.deepStrictEqual(orNode([orNode([a, b]), FALSE]), { t: 'or', children: [a, b] });
      assert.strictEqual(orNode([]), FALSE);
    });

    it('deduplicates identical children but never opaque nodes', () => {
      assert.deepStrictEqual(andNode([a, a, b]), { t: 'and', children: [a, b] });
      const opaque = opaqueNode('[function]', 'js-function');
      const doubled = andNode([opaque, opaqueNode('[function]', 'js-function')]);
      assert.strictEqual(doubled.children.length, 2);
    });

    it('not: folds constants and double negation', () => {
      assert.strictEqual(notNode(TRUE), FALSE);
      assert.strictEqual(notNode(FALSE), TRUE);
      assert.deepStrictEqual(notNode(notNode(a)), a);
      assert.deepStrictEqual(notNode(a), { t: 'not', child: a });
    });

    it('toFilter maps constants to ALWAYS_* and everything else to CONDITIONAL', () => {
      assert.deepStrictEqual(toFilter(TRUE), { kind: 'KIND_ALWAYS_ALLOWED' });
      assert.deepStrictEqual(toFilter(FALSE), { kind: 'KIND_ALWAYS_DENIED' });
      const filter = toFilter(a);
      assert.strictEqual(filter.kind, 'KIND_CONDITIONAL');
      assert.deepStrictEqual(filter.condition, toOperand(a));
    });

    it('serializes opaque and relation nodes as Kerberos operators', () => {
      assert.deepStrictEqual(toOperand(opaqueNode('src', 'js-function')), {
        expression: { operator: 'opaque', operands: [{ value: { src: 'src', reason: 'js-function' } }] },
      });
      assert.deepStrictEqual(toOperand(relationNode('doc_viewer', 'viewer')), {
        expression: { operator: 'relation', operands: [{ value: { name: 'doc_viewer', relation: 'viewer' } }] },
      });
    });

    it('fromOperand round-trips and re-normalizes boolean positions', () => {
      const tree = andNode([a, notNode(orNode([b, relationNode('r', 'rel')]))]);
      assert.deepStrictEqual(fromOperand(toOperand(tree)), tree);
      // A subtree replaced by a constant re-folds through the constructors.
      const withConst = { expression: { operator: 'and', operands: [{ value: false }, toOperand(a)] } };
      assert.strictEqual(fromOperand(withConst), FALSE);
    });

    it('renders a readable s-expression debug string', () => {
      assert.strictEqual(
        toDebugString(andNode([a, notNode(b)])),
        '(and (eq request.resource.attr.a 1) (not (eq request.resource.attr.b 2)))',
      );
      assert.strictEqual(toDebugString(TRUE), 'true');
    });
  });

  describe('partialEval: expression planning', () => {
    const principal = { id: 'u1', roles: ['USER'], attr: { dept: 'sales' } };
    const baseResource = { kind: 'document' };

    function plan(expr, { resource = baseResource, constants, variables } = {}) {
      const planner = createExprPlanner({ principal, resource, actions: ['view'], constants, variables });
      return planner.planCondition({ shape: { match: codec.compileExpr(expr) } });
    }

    it('folds fully-known expressions to constants', () => {
      assert.strictEqual(plan('P.id === "u1"'), TRUE);
      assert.strictEqual(plan('P.attr.dept === "hr"'), FALSE);
      assert.strictEqual(plan('Math.max(1, 2) === 2'), TRUE);
      assert.strictEqual(plan('Date.now() > 0'), TRUE);
    });

    it('folds known resource fields and residualizes unknown ones', () => {
      assert.strictEqual(plan('R.kind === "document"'), TRUE);
      assert.deepStrictEqual(
        plan('R.attr.status === "open"', { resource: { kind: 'document', attr: { status: 'open' } } }),
        TRUE,
      );
      assert.deepStrictEqual(plan('R.attr.status === "open"'), eqExpr('request.resource.attr.status', 'open'));
      assert.deepStrictEqual(plan('R.id === "d1"'), eqExpr('request.resource.id', 'd1'));
      assert.deepStrictEqual(plan('R.attr.meta.level === 3'), eqExpr('request.resource.attr.meta.level', 3));
    });

    it('maps comparison and arithmetic operators to Cerbos names', () => {
      const node = plan('(R.attr.qty + 1) > 10');
      assert.deepStrictEqual(node, {
        t: 'expr',
        e: {
          expression: {
            operator: 'gt',
            operands: [
              {
                expression: {
                  operator: 'add',
                  operands: [{ variable: 'request.resource.attr.qty' }, { value: 1 }],
                },
              },
              { value: 10 },
            ],
          },
        },
      });
      assert.strictEqual(plan('R.attr.a !== 1').e.expression.operator, 'ne');
      assert.strictEqual(plan('R.attr.a < 1').e.expression.operator, 'lt');
      assert.strictEqual(plan('R.attr.a <= 1').e.expression.operator, 'le');
      assert.strictEqual(plan('R.attr.a >= 1').e.expression.operator, 'ge');
      assert.strictEqual(plan('R.attr.a % 2 === 0').e.expression.operands[0].expression.operator, 'mod');
    });

    it('maps includes() to in with membership semantics', () => {
      assert.deepStrictEqual(plan('["a", "b"].includes(R.attr.tag)'), {
        t: 'expr',
        e: {
          expression: {
            operator: 'in',
            operands: [{ variable: 'request.resource.attr.tag' }, { value: ['a', 'b'] }],
          },
        },
      });
      // Residual receiver: assumed to be a list.
      const node = plan('R.attr.tags.includes("x")');
      assert.deepStrictEqual(node.e.expression.operands, [{ value: 'x' }, { variable: 'request.resource.attr.tags' }]);
      // Const STRING receiver would mean substring semantics — opaque.
      assert.strictEqual(plan('"abc".includes(R.attr.s)').t, 'opaque');
      // Residual list literal.
      const listNode = plan('[R.attr.a, 1].includes(R.attr.b)');
      assert.strictEqual(listNode.e.expression.operands[1].expression.operator, 'list');
    });

    it('wraps bare residual values in boolean position as eq(x, true)', () => {
      assert.deepStrictEqual(plan('R.attr.isPublic'), eqExpr('request.resource.attr.isPublic', true));
      assert.deepStrictEqual(plan('!R.attr.isPublic'), notNode(eqExpr('request.resource.attr.isPublic', true)));
    });

    it('preserves && / || laziness against the known side', () => {
      assert.deepStrictEqual(plan('P.id === "u1" && R.attr.qty > 1').e.expression.operator, 'gt');
      assert.strictEqual(plan('P.id === "zzz" && R.attr.qty > 1'), FALSE);
      assert.strictEqual(plan('P.id === "u1" || R.attr.qty > 1'), TRUE);
      assert.deepStrictEqual(plan('P.id === "zzz" || R.attr.qty > 1').e.expression.operator, 'gt');
    });

    it('takes the reachable ternary branch on a known test, opaque otherwise', () => {
      assert.deepStrictEqual(
        plan('P.id === "u1" ? R.attr.a === 1 : R.attr.b === 2'),
        eqExpr('request.resource.attr.a', 1),
      );
      assert.strictEqual(plan('R.attr.flag ? R.attr.a === 1 : R.attr.b === 2').t, 'opaque');
    });

    it('degrades unplannable constructs to opaque (always sound)', () => {
      for (const expr of [
        'R.attr.a ?? 1',
        'R.attr.a ** 2 === 4',
        'typeof R.attr.a === "string"',
        'Math.floor(R.attr.a) > 1',
        'R.attr.a.toLowerCase() === "x"',
        'new Date(R.attr.a).getTime() > 0',
        '({ x: R.attr.a }).x === 1',
        'R.attr["__proto__"] === 1',
        'R === 1',
        'R.attr === 1',
      ]) {
        const node = plan(expr);
        assert.strictEqual(node.t, 'opaque', `expected opaque for: ${expr}`);
        assert.strictEqual(node.reason, 'unsupported-expression');
        assert.strictEqual(node.src, expr);
      }
    });

    it('plans JS-function leaves as opaque', () => {
      const planner = createExprPlanner({ principal, resource: baseResource, actions: ['view'] });
      const named = function myCondition() {
        return true;
      };
      assert.deepStrictEqual(planner.planCondition({ shape: { match: named } }), {
        t: 'opaque',
        src: '[function myCondition]',
        reason: 'js-function',
      });
    });

    it('mirrors Conditions.isFulfilled strategy semantics exactly', () => {
      const planner = createExprPlanner({ principal, resource: baseResource, actions: ['view'] });
      const leaf = codec.compileExpr('R.attr.a === 1');
      const residual = eqExpr('request.resource.attr.a', 1);

      assert.deepStrictEqual(planner.planCondition({ shape: { match: { all: [leaf] } } }), residual);
      assert.deepStrictEqual(planner.planCondition({ shape: { match: { any: [leaf] } } }), residual);
      assert.deepStrictEqual(planner.planCondition({ shape: { match: { none: [leaf] } } }), notNode(residual));
      // Empty / invalid strategy payloads fail closed.
      assert.strictEqual(planner.planCondition({ shape: { match: { all: [] } } }), FALSE);
      assert.strictEqual(planner.planCondition({ shape: { match: {} } }), FALSE);
      assert.strictEqual(planner.planCondition({ shape: { match: { description: 'noop' } } }), FALSE);
      assert.strictEqual(planner.planCondition({ shape: { match: null } }), FALSE);
      // Multiple strategies on one object AND together.
      assert.deepStrictEqual(
        planner.planCondition({ shape: { match: { all: [leaf], none: [codec.compileExpr('R.attr.b === 2')] } } }),
        andNode([residual, notNode(eqExpr('request.resource.attr.b', 2))]),
      );
      // No condition at all → unconditional rule.
      assert.strictEqual(planner.planCondition(undefined), TRUE);
    });

    it('inlines $expr variables (const, residual) and folds through V', () => {
      const variables = {
        shape: {
          isOwner: codec.compileExpr('R.attr.ownerId === P.id'),
          me: codec.compileExpr('P.id'),
          cfg: codec.compileExpr('({ min: 5 })'),
        },
      };
      assert.deepStrictEqual(plan('V.isOwner', { variables }), eqExpr('request.resource.attr.ownerId', 'u1'));
      assert.deepStrictEqual(plan('R.attr.author === V.me', { variables }), {
        t: 'expr',
        e: {
          expression: { operator: 'eq', operands: [{ variable: 'request.resource.attr.author' }, { value: 'u1' }] },
        },
      });
      assert.deepStrictEqual(plan('R.attr.qty > V.cfg.min', { variables }), {
        t: 'expr',
        e: { expression: { operator: 'gt', operands: [{ variable: 'request.resource.attr.qty' }, { value: 5 }] } },
      });
    });

    it('treats V-in-variable as opaque (runtime variables never see V)', () => {
      const variables = {
        shape: {
          a: codec.compileExpr('V.b'),
          b: codec.compileExpr('P.id'),
        },
      };
      assert.strictEqual(plan('V.a === "u1"', { variables }).t, 'opaque');
    });

    it('evaluates plain JS-function variables against known fields only', () => {
      const variables = {
        shape: {
          dept: (req) => req.P.attr.dept,
          kind: (req) => req.R.kind,
          known: (req) => req.R.attr.status,
          unknown: (req) => req.R.attr.secret,
          throwing: () => {
            throw new Error('boom');
          },
        },
      };
      const resource = { kind: 'document', attr: { status: 'open' } };
      assert.strictEqual(plan('V.dept === "sales"', { resource, variables }), TRUE);
      assert.strictEqual(plan('V.kind === "document"', { resource, variables }), TRUE);
      assert.strictEqual(plan('V.known === "open"', { resource, variables }), TRUE);
      assert.strictEqual(plan('V.unknown === "x"', { resource, variables }).t, 'opaque');
      assert.strictEqual(plan('V.throwing === 1', { resource, variables }).t, 'opaque');
    });

    it('treats undeclared variables as undefined (runtime parity)', () => {
      assert.strictEqual(plan('V.nope === undefined2', {}).t, 'opaque'); // unknown identifier stays opaque
      assert.strictEqual(plan('V.nope === null', {}), FALSE); // undefined === null → false, folded
    });

    it('folds constants through C', () => {
      const constants = { get: () => ({ minQty: 10 }) };
      assert.deepStrictEqual(plan('R.attr.qty > C.minQty', { constants }).e.expression.operands[1], { value: 10 });
    });

    it('propagates evaluation errors on fully-known subtrees (runtime parity)', () => {
      const resource = { kind: 'document', attr: { obj: null } };
      assert.throws(() => plan('R.attr.obj.x === 1', { resource }), TypeError);
    });

    describe('wire-safety guard', () => {
      // Folded constants that JSON transport would corrupt must never enter a
      // residual operand — the expression degrades to opaque instead.
      it('degrades undefined folds to opaque (JSON drops the key)', () => {
        assert.strictEqual(plan('R.attr.owner === P.attr.missing').t, 'opaque');
      });

      it('degrades non-finite number folds to opaque (JSON turns them into null)', () => {
        const constants = { get: () => ({ inf: Infinity, nan: NaN }) };
        assert.strictEqual(plan('R.attr.n > C.inf', { constants }).t, 'opaque');
        assert.strictEqual(plan('R.attr.n === C.nan', { constants }).t, 'opaque');
      });

      it('degrades Date folds to opaque (JSON turns them into ISO strings)', () => {
        assert.strictEqual(plan('new Date(0) < R.attr.t').t, 'opaque');
        const constants = { get: () => ({ when: new Date(0) }) };
        assert.strictEqual(plan('R.attr.t > C.when', { constants }).t, 'opaque');
      });

      it('degrades BigInt and object folds to opaque', () => {
        const constants = { get: () => ({ big: 10n, obj: { min: 5 } }) };
        assert.strictEqual(plan('R.attr.n === C.big', { constants }).t, 'opaque');
        assert.strictEqual(plan('R.attr.o === C.obj', { constants }).t, 'opaque');
      });

      it('guards in-lists element-wise', () => {
        assert.strictEqual(plan('[P.attr.missing, "a"].includes(R.attr.x)').t, 'opaque');
        const constants = { get: () => ({ dates: [new Date(0)] }) };
        assert.strictEqual(plan('C.dates.includes(R.attr.x)', { constants }).t, 'opaque');
      });

      it('keeps wire-safe comparisons plannable', () => {
        assert.deepStrictEqual(plan('R.attr.x === null'), {
          t: 'expr',
          e: { expression: { operator: 'eq', operands: [{ variable: 'request.resource.attr.x' }, { value: null }] } },
        });
        // Fully-known folds are unaffected by the guard.
        const constants = { get: () => ({ when: new Date(0) }) };
        assert.strictEqual(plan('C.when.getTime() === 0', { constants }), TRUE);
      });
    });
  });
});
