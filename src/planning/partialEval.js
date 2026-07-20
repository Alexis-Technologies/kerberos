/**
 * Partial evaluator for codec-compiled `{ $expr }` conditions.
 *
 * Bottom-up over the jsep AST: every subtree yields a PlanValue —
 * `{ k: 'const', v }` (fully known), `{ k: 'residual', operand }` (a Cerbos
 * operand over unknown resource fields) or `{ k: 'opaque' }` (not statically
 * plannable). Known at plan time: `P`, `C`, resource `kind`/`scope`/
 * `policyVersion` and the attr keys the caller provided; unknown: `R.id` and
 * every other attr key. Constant folding reuses the codec's own interpreter
 * (`evalExprAst`), so folded semantics are exactly the runtime's, including
 * `&&`/`||`/`?:` laziness (short-circuits are planned explicitly and a branch
 * is only folded once it is known to be reachable).
 *
 * Node/operator dispatch uses prototype-less strategy tables (mirroring the
 * codec's NODE_EVALUATORS) and all collection walks are single-pass loops.
 *
 * Soundness rule: when in doubt, produce `opaque` — never guess a value. The
 * one deliberate exception is a bare residual value in boolean position
 * (`R.attr.isPublic`), which becomes `eq(variable, true)`: Cerbos-compatible,
 * documented as "author boolean attrs explicitly in plannable policies".
 */

const { EXPR_META, evalExprAst } = require('../caching/codec.js');
const { andNode, constNode, createDispatch, exprNode, notNode, opaqueNode, orNode, toOperand } = require('./nodes.js');

const BLOCKED_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

// jsep binary operators that translate 1:1 into Cerbos filter operators.
const JS_TO_CERBOS_BINARY = createDispatch({
  '===': 'eq',
  '==': 'eq',
  '!==': 'ne',
  '!=': 'ne',
  '<': 'lt',
  '<=': 'le',
  '>': 'gt',
  '>=': 'ge',
  '+': 'add',
  '-': 'sub',
  '*': 'mult',
  '/': 'div',
  '%': 'mod',
});

// Operators whose result is boolean-valued: their residuals may stand directly
// in boolean position. `index`/`variable` results have unknown type and get
// the eq(x, true) wrap; arithmetic residuals in boolean position are opaque.
const BOOLEAN_RESULT_OPS = new Set(['and', 'or', 'not', 'eq', 'ne', 'lt', 'le', 'gt', 'ge', 'in']);

const OPAQUE = Object.freeze({ k: 'opaque' });

function constPV(value) {
  return { k: 'const', v: value };
}

function residualPV(operand) {
  return { k: 'residual', operand };
}

function toOp(planValue) {
  return planValue.k === 'const' ? { value: planValue.v } : planValue.operand;
}

function describeFn(fn) {
  return fn.name ? `[function ${fn.name}]` : '[function]';
}

// Sentinel thrown by the throwing-R proxy when a plain JS-function variable
// touches an unknown resource field; any throw downgrades the variable to
// opaque, so the sentinel never escapes the variable-evaluation try block.
class UnknownFieldAccess extends Error {}

/**
 * Proxy over the partially-known resource: known fields answer normally,
 * `id` and unlisted attr keys throw the sentinel. Used only when evaluating
 * plain JS-function variables (the runtime evaluates every variable eagerly
 * per check, so plan-time execution adds no new side-effect surface).
 */
function createThrowingResource(knownR) {
  const attr = new Proxy(knownR.attr, {
    get(target, key) {
      if (typeof key === 'symbol' || Object.prototype.hasOwnProperty.call(target, key)) return target[key];
      throw new UnknownFieldAccess();
    },
  });
  const base = { ...knownR, attr };
  return new Proxy(base, {
    get(target, key) {
      if (typeof key === 'symbol' || Object.prototype.hasOwnProperty.call(target, key)) return target[key];
      throw new UnknownFieldAccess();
    },
  });
}

/**
 * Creates a per-policy expression planner.
 *
 * @param {object} options
 * @param {Record<string, unknown>} options.principal - fully-known P
 * @param {{ kind: string, scope?: string, policyVersion?: string, attr?: Record<string, unknown> }} options.resource
 * @param {string[]} options.actions - requested actions (visible to JS-fn variables, like at runtime)
 * @param {{ get: () => Record<string, unknown> } | undefined} [options.constants] - Constants instance
 * @param {{ shape: Record<string, Function> } | undefined} [options.variables] - Variables instance
 * @returns {{ planCondition: (conditions: { shape: { match: unknown } } | undefined) => import('./nodes.js').PlanNode }}
 */
function createExprPlanner({ principal, resource, actions, constants, variables }) {
  const C = { ...constants?.get() };
  const knownAttr = resource.attr && typeof resource.attr === 'object' ? resource.attr : {};
  const knownR = { kind: resource.kind, attr: knownAttr };
  if (resource.scope !== undefined) knownR.scope = resource.scope;
  if (resource.policyVersion !== undefined) knownR.policyVersion = resource.policyVersion;

  // ctx.V accumulates const-folded variables as they are planned, so a later
  // fold of an AST that references V.<name> resolves through the interpreter.
  const ctx = { P: principal, R: knownR, V: {}, C };

  const variableShapes = variables?.shape ?? {};
  const variablePlans = new Map();
  // Runtime variables are evaluated against a request WITHOUT V (they never
  // see each other) — while planning a variable body, V access is opaque.
  let planningVariable = false;

  // Source of the $expr currently being planned; stamped onto opaque nodes.
  let currentSrc = '';

  function evalConst(node) {
    return evalExprAst(node, ctx);
  }

  function variablePlan(name) {
    if (variablePlans.has(name)) return variablePlans.get(name);
    const fn = variableShapes[name];
    let plan;
    if (typeof fn !== 'function') {
      plan = constPV(undefined); // undeclared variable: V.<name> is undefined at runtime too
    } else if (fn[EXPR_META]) {
      const outerSrc = currentSrc;
      const wasPlanning = planningVariable;
      planningVariable = true;
      currentSrc = fn[EXPR_META].expr;
      try {
        plan = planValue(fn[EXPR_META].ast);
      } finally {
        planningVariable = wasPlanning;
        currentSrc = outerSrc;
      }
    } else {
      // Plain JS function: run it against the known context; touching an
      // unknown field (or any other throw) downgrades to opaque.
      const R = createThrowingResource(knownR);
      const req = { P: principal, R, principal, resource: R, actions, constants: C, C };
      try {
        plan = constPV(fn(req));
      } catch {
        plan = OPAQUE;
      }
    }
    if (plan.k === 'const') ctx.V[name] = plan.v;
    variablePlans.set(name, plan);
    return plan;
  }

  /** Peels a member chain into its base node and ordered segment list. */
  function peelChain(node) {
    const segments = [];
    let current = node;
    while (current.type === 'MemberExpression') {
      segments.unshift(current.computed ? { node: current.property } : { key: current.property.name });
      current = current.object;
    }
    return { base: current, segments };
  }

  /**
   * Resolves computed segments to const keys where possible. One pass also
   * answers "is any segment residual" so callers never re-scan the list.
   * Returns null when a segment makes the whole member unplannable (blocked
   * key, opaque or non-scalar computed key).
   *
   * @returns {{ segments: Array<{ key?: string, residual?: object }>, hasResidual: boolean } | null}
   */
  function resolveSegments(rawSegments) {
    const segments = [];
    let hasResidual = false;
    for (const segment of rawSegments) {
      if (segment.key !== undefined) {
        if (BLOCKED_KEYS.has(segment.key)) return null;
        segments.push({ key: segment.key });
        continue;
      }
      const keyPlan = planValue(segment.node);
      if (keyPlan.k === 'const') {
        const key = keyPlan.v;
        if ((typeof key !== 'string' && typeof key !== 'number') || BLOCKED_KEYS.has(String(key))) return null;
        segments.push({ key: String(key) });
      } else if (keyPlan.k === 'opaque') {
        return null;
      } else {
        hasResidual = true;
        segments.push({ residual: keyPlan.operand });
      }
    }
    return { segments, hasResidual };
  }

  /** Appends the remaining segments to an operand as `index` operations. */
  function indexChain(operand, segments, from) {
    let current = operand;
    for (let i = from; i < segments.length; i++) {
      const segment = segments[i];
      const keyOperand = segment.key !== undefined ? { value: segment.key } : segment.residual;
      current = { expression: { operator: 'index', operands: [current, keyOperand] } };
    }
    return residualPV(current);
  }

  function planResourceMember(node, resolved) {
    const { segments, hasResidual } = resolved;
    if (!segments.length || segments[0].key === undefined) return OPAQUE;
    const head = segments[0].key;
    if (head === 'kind' || head === 'scope' || head === 'policyVersion') {
      // The first segment is a const key, so any residual lives in the rest.
      return hasResidual ? OPAQUE : constPV(evalConst(node));
    }
    if (head === 'id') {
      return segments.length === 1 ? residualPV({ variable: 'request.resource.id' }) : OPAQUE;
    }
    if (head !== 'attr' || segments.length === 1) return OPAQUE;

    // Leading run of const keys after `attr` decides known vs residual.
    let splitIndex = 1;
    while (splitIndex < segments.length && segments[splitIndex].key !== undefined) splitIndex++;
    if (splitIndex === 1) return OPAQUE; // R.attr[<residual>]
    if (Object.prototype.hasOwnProperty.call(knownAttr, segments[1].key)) {
      // Known attr: fully-const paths fold through the interpreter (throws
      // propagate — runtime parity); residual keys into a known value are a
      // rarity not worth planning.
      return splitIndex === segments.length ? constPV(evalConst(node)) : OPAQUE;
    }
    let path = `request.resource.attr.${segments[1].key}`;
    for (let i = 2; i < splitIndex; i++) path += `.${segments[i].key}`;
    return indexChain({ variable: path }, segments, splitIndex);
  }

  function planVariableMember(node, resolved) {
    const { segments, hasResidual } = resolved;
    if (!segments.length || segments[0].key === undefined) return OPAQUE;
    if (planningVariable) return OPAQUE; // runtime variables never see V
    const plan = variablePlan(segments[0].key);
    if (plan.k === 'opaque') return OPAQUE;
    if (plan.k === 'const') {
      // The first segment is a const key, so any residual lives in the rest.
      return hasResidual ? OPAQUE : constPV(evalConst(node));
    }
    return indexChain(plan.operand, segments, 1);
  }

  function planKnownRootMember(node, resolved) {
    return resolved.hasResidual ? OPAQUE : constPV(evalConst(node));
  }

  // O(1) member-base dispatch; unknown roots (bare custom roots, whole-R
  // usage) fall through to opaque in planMember.
  const memberPlanners = createDispatch({
    R: planResourceMember,
    V: planVariableMember,
    P: planKnownRootMember,
    C: planKnownRootMember,
    Math: planKnownRootMember,
    Date: planKnownRootMember,
  });

  function planMember(node) {
    const { base, segments } = peelChain(node);
    if (base.type !== 'Identifier') return OPAQUE;
    const planner = memberPlanners[base.name];
    if (!planner) return OPAQUE;
    const resolved = resolveSegments(segments);
    if (!resolved) return OPAQUE;
    return planner(node, resolved);
  }

  // Value-position short-circuits keep the interpreter's laziness: the right
  // branch is only planned once the left side is a known constant.
  const shortCircuitPlanners = createDispatch({
    '&&': (node, left) => (left.v ? planValue(node.right) : left),
    '||': (node, left) => (left.v ? left : planValue(node.right)),
    '??': (node, left) => (left.v === null || left.v === undefined ? planValue(node.right) : left),
  });

  function planBinary(node) {
    const shortCircuit = shortCircuitPlanners[node.operator];
    if (shortCircuit) {
      const left = planValue(node.left);
      // Non-const left: value-position semantics are not boolean — opaque.
      return left.k === 'const' ? shortCircuit(node, left) : OPAQUE;
    }
    const left = planValue(node.left);
    const right = planValue(node.right);
    if (left.k === 'const' && right.k === 'const') return constPV(evalConst(node));
    const operator = JS_TO_CERBOS_BINARY[node.operator];
    if (!operator || left.k === 'opaque' || right.k === 'opaque') return OPAQUE;
    return residualPV({ expression: { operator, operands: [toOp(left), toOp(right)] } });
  }

  function planCall(node) {
    const { callee } = node;
    // One pass over the arguments: plan + const/opaque flags together.
    const argPlans = new Array(node.arguments.length);
    let argsConst = true;
    let argsOpaque = false;
    for (let i = 0; i < node.arguments.length; i++) {
      const plan = planValue(node.arguments[i]);
      argPlans[i] = plan;
      if (plan.k !== 'const') argsConst = false;
      if (plan.k === 'opaque') argsOpaque = true;
    }

    if (callee.type === 'Identifier') {
      return argsConst ? constPV(evalConst(node)) : OPAQUE;
    }
    if (callee.type !== 'MemberExpression') return OPAQUE;

    const receiver = planValue(callee.object);
    if (receiver.k === 'const' && argsConst && (callee.computed ? planValue(callee.property).k === 'const' : true)) {
      return constPV(evalConst(node));
    }
    const isIncludes = !callee.computed && callee.property.name === 'includes' && node.arguments.length === 1;
    if (!isIncludes || receiver.k === 'opaque' || argsOpaque) return OPAQUE;
    // `in` is list membership. A const string receiver would mean substring
    // semantics — not expressible; a residual receiver is assumed to be a
    // list (documented plannability constraint).
    if (receiver.k === 'const' && !Array.isArray(receiver.v)) return OPAQUE;
    return residualPV({ expression: { operator: 'in', operands: [toOp(argPlans[0]), toOp(receiver)] } });
  }

  function planArray(node) {
    // One pass: element operands + const/opaque flags together.
    const operands = new Array(node.elements.length);
    let allConst = true;
    for (let i = 0; i < node.elements.length; i++) {
      const plan = planValue(node.elements[i]);
      if (plan.k === 'opaque') return OPAQUE;
      if (plan.k !== 'const') allConst = false;
      operands[i] = toOp(plan);
    }
    if (allConst) return constPV(evalConst(node));
    return residualPV({ expression: { operator: 'list', operands } });
  }

  // ObjectExpression / NewExpression: fold when fully known, otherwise opaque.
  function planObjectOrNew(node) {
    const parts = node.type === 'ObjectExpression' ? node.properties : node.arguments;
    for (const part of parts) {
      const valueNode = node.type === 'ObjectExpression' ? (part.shorthand ? part.key : part.value) : part;
      if (planValue(valueNode).k !== 'const') return OPAQUE;
      if (node.type === 'ObjectExpression' && part.computed && planValue(part.key).k !== 'const') return OPAQUE;
    }
    return constPV(evalConst(node));
  }

  function planUnary(node) {
    if (node.operator === '!') {
      const inner = planBool(node.argument);
      const negated = notNode(inner);
      if (negated.t === 'const') return constPV(negated.v);
      if (negated.t === 'opaque') return OPAQUE;
      return residualPV(toOperand(negated));
    }
    return planValue(node.argument).k === 'const' ? constPV(evalConst(node)) : OPAQUE;
  }

  function planConditionalValue(node) {
    const test = planValue(node.test);
    if (test.k !== 'const') return OPAQUE;
    return planValue(test.v ? node.consequent : node.alternate);
  }

  const identifierPlanners = createDispatch({
    P: () => constPV(principal),
    C: () => constPV(C),
    Math: () => constPV(Math),
    Date: () => constPV(Date),
  });

  // O(1) node-type dispatch — the planning analog of the codec's
  // NODE_EVALUATORS. Unknown node types degrade to opaque (always sound).
  const valuePlanners = createDispatch({
    Literal: (node) => constPV(node.value),
    Identifier: (node) => {
      const planner = identifierPlanners[node.name];
      return planner ? planner() : OPAQUE; // bare R / V / custom roots
    },
    MemberExpression: planMember,
    BinaryExpression: planBinary,
    UnaryExpression: planUnary,
    CallExpression: planCall,
    ArrayExpression: planArray,
    ConditionalExpression: planConditionalValue,
    ObjectExpression: planObjectOrNew,
    NewExpression: planObjectOrNew,
  });

  /**
   * Value-level partial evaluation: PlanValue for any expression node.
   *
   * @param {Record<string, unknown>} node
   * @returns {{ k: 'const', v: unknown } | { k: 'residual', operand: object } | { k: 'opaque' }}
   */
  function planValue(node) {
    const planner = valuePlanners[node.type];
    return planner ? planner(node) : OPAQUE;
  }

  function valueToBool(planned) {
    if (planned.k === 'const') return constNode(Boolean(planned.v));
    if (planned.k === 'opaque') return opaqueNode(currentSrc, 'unsupported-expression');
    const { operand } = planned;
    if (operand.expression && BOOLEAN_RESULT_OPS.has(operand.expression.operator)) return exprNode(operand);
    // Bare value in boolean position: eq(x, true) — documented constraint.
    if (operand.variable || operand.expression?.operator === 'index') {
      return exprNode({ expression: { operator: 'eq', operands: [operand, { value: true }] } });
    }
    return opaqueNode(currentSrc, 'unsupported-expression');
  }

  // Boolean-position dispatch: logical operators become plan nodes directly
  // (preserving laziness), everything else goes through the value layer.
  const boolPlanners = createDispatch({
    BinaryExpression: (node) => {
      if (node.operator === '&&') {
        const left = planBool(node.left);
        if (left.t === 'const' && !left.v) return left;
        return andNode([left, planBool(node.right)]);
      }
      if (node.operator === '||') {
        const left = planBool(node.left);
        if (left.t === 'const' && left.v) return left;
        return orNode([left, planBool(node.right)]);
      }
      return valueToBool(planValue(node));
    },
    UnaryExpression: (node) =>
      node.operator === '!' ? notNode(planBool(node.argument)) : valueToBool(planValue(node)),
    ConditionalExpression: (node) => {
      const test = planValue(node.test);
      if (test.k !== 'const') return opaqueNode(currentSrc, 'unsupported-expression');
      return planBool(test.v ? node.consequent : node.alternate);
    },
  });

  /**
   * Boolean-level partial evaluation: PlanNode for a condition expression.
   *
   * @param {Record<string, unknown>} node
   * @returns {import('./nodes.js').PlanNode}
   */
  function planBool(node) {
    const planner = boolPlanners[node.type];
    return planner ? planner(node) : valueToBool(planValue(node));
  }

  function planLeaf(fn) {
    const meta = fn[EXPR_META];
    if (!meta) return opaqueNode(describeFn(fn), 'js-function');
    const outerSrc = currentSrc;
    currentSrc = meta.expr;
    try {
      return planBool(meta.ast);
    } finally {
      currentSrc = outerSrc;
    }
  }

  function planMatchList(conds) {
    const nodes = new Array(conds.length);
    for (let i = 0; i < conds.length; i++) nodes[i] = planMatch(conds[i]);
    return nodes;
  }

  // Strategy table mirroring Conditions' #strategies; the empty/non-array
  // fail-closed guard runs before dispatch (shared by all three).
  const matchStrategies = createDispatch({
    any: (conds) => orNode(planMatchList(conds)),
    all: (conds) => andNode(planMatchList(conds)),
    none: (conds) => {
      const nodes = new Array(conds.length);
      for (let i = 0; i < conds.length; i++) nodes[i] = notNode(planMatch(conds[i]));
      return andNode(nodes);
    },
  });

  /**
   * Plans a Conditions match tree. Exact parity with Conditions.isFulfilled:
   * empty/invalid strategy payloads fail closed to FALSE, unknown keys are
   * ignored, multiple strategies on one object must all pass (AND).
   *
   * @param {unknown} match
   * @returns {import('./nodes.js').PlanNode}
   */
  function planMatch(match) {
    if (typeof match === 'function') return planLeaf(match);
    if (typeof match !== 'object' || match === null) return constNode(false);
    const parts = [];
    for (const key of Object.keys(match)) {
      const strategy = matchStrategies[key];
      if (!strategy) continue; // forward-compat: ignore unknown keys
      const conds = match[key];
      if (!Array.isArray(conds) || !conds.length) return constNode(false);
      parts.push(strategy(conds));
    }
    if (!parts.length) return constNode(false);
    return andNode(parts);
  }

  function planCondition(conditions) {
    if (!conditions) return constNode(true); // unconditional rule
    return planMatch(conditions.shape.match);
  }

  return { planCondition };
}

module.exports = { createExprPlanner };
