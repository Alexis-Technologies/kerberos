const jsepModule = require('jsep');
const objectPlugin = require('@jsep-plugin/object');
const ternaryPlugin = require('@jsep-plugin/ternary');

const jsep = jsepModule.default || jsepModule;

/**
 * Error thrown when an expression uses a construct that the safe evaluator
 * refuses to parse or evaluate.
 */
class KerberosExprError extends Error {
  constructor(message) {
    super(message);
    this.name = 'KerberosExprError';
  }
}

// Keys that can be used to reach the prototype chain / function constructors.
// Blocked regardless of how they are written (dot, computed, split, unicode),
// because the check runs on the resolved string key inside the interpreter.
const BLOCKED_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

const ALLOWED_BINARY_OPS = new Set([
  '&&', '||', '??',
  '===', '!==', '==', '!=',
  '<', '>', '<=', '>=',
  '+', '-', '*', '/', '%', '**',
  '&', '|', '^', '<<', '>>', '>>>',
]);

const ALLOWED_UNARY_OPS = new Set(['!', '-', '+', '~', 'typeof']);

// Methods that may be called on string / array / number values. None of these
// can leak a function reference or constructor.
const VALUE_METHODS = new Set([
  'includes', 'indexOf', 'lastIndexOf', 'startsWith', 'endsWith',
  'toLowerCase', 'toUpperCase', 'trim', 'trimStart', 'trimEnd',
  'slice', 'substring', 'charAt', 'charCodeAt', 'at', 'concat',
  'split', 'join', 'padStart', 'padEnd', 'repeat', 'toFixed', 'toString',
]);

// Math is exposed as a safe, side-effect-free global root.
const MATH_METHODS = new Set([
  'abs', 'ceil', 'floor', 'round', 'trunc', 'sign',
  'min', 'max', 'pow', 'sqrt', 'cbrt', 'log', 'log2', 'log10', 'exp', 'hypot',
]);

const ALLOWED_GLOBALS = { Math };

const DEFAULT_ROOTS = ['P', 'R', 'V', 'C'];

let jsepConfigured = false;

function configureJsep() {
  if (jsepConfigured) return;
  jsep.plugins.register(objectPlugin.default || objectPlugin, ternaryPlugin.default || ternaryPlugin);
  // `typeof` is not a default jsep unary operator.
  jsep.addUnaryOp('typeof');
  jsepConfigured = true;
}

/**
 * Structural fail-fast gate: ensures the AST only contains node types and
 * operators on the allowlist. Identifier names and member keys are enforced at
 * evaluation time (they depend on the runtime context), giving defense in depth.
 *
 * @param {Record<string, unknown>} node
 */
function validateNode(node) {
  if (!node || typeof node !== 'object') throw new KerberosExprError('Invalid expression node');

  switch (node.type) {
    case 'Literal':
      return;
    case 'Identifier':
      return;
    case 'MemberExpression':
      validateNode(node.object);
      if (node.computed) validateNode(node.property);
      return;
    case 'BinaryExpression':
      if (!ALLOWED_BINARY_OPS.has(node.operator)) throw new KerberosExprError(`Operator "${node.operator}" is not allowed`);
      validateNode(node.left);
      validateNode(node.right);
      return;
    case 'UnaryExpression':
      if (!ALLOWED_UNARY_OPS.has(node.operator)) throw new KerberosExprError(`Unary operator "${node.operator}" is not allowed`);
      validateNode(node.argument);
      return;
    case 'ConditionalExpression':
      validateNode(node.test);
      validateNode(node.consequent);
      validateNode(node.alternate);
      return;
    case 'ArrayExpression':
      for (const element of node.elements) validateNode(element);
      return;
    case 'ObjectExpression':
      for (const property of node.properties) {
        if (property.computed) validateNode(property.key);
        validateNode(property.shorthand ? property.key : property.value);
      }
      return;
    case 'CallExpression':
      if (node.callee.type !== 'MemberExpression') throw new KerberosExprError('Only whitelisted method calls are allowed');
      validateNode(node.callee);
      for (const argument of node.arguments) validateNode(argument);
      return;
    case 'Compound':
      throw new KerberosExprError('Compound expressions (e.g. "a, b", "a in b") are not allowed');
    default:
      throw new KerberosExprError(`Unsupported expression node: ${node.type}`);
  }
}

const astCache = new Map();

/**
 * Parses an expression once and caches the resulting AST keyed by the source
 * string, so repeated identical expressions never re-parse.
 *
 * @param {string} expr
 * @returns {Record<string, unknown>}
 */
function parseExpr(expr) {
  if (typeof expr !== 'string') throw new KerberosExprError('Expression must be a string');

  const cached = astCache.get(expr);
  if (cached) return cached;

  configureJsep();
  let ast;
  try {
    ast = jsep(expr);
  } catch (error) {
    throw new KerberosExprError(`Failed to parse expression: ${error.message}`);
  }
  validateNode(ast);
  astCache.set(expr, ast);
  return ast;
}

function safeKey(key) {
  const keyStr = typeof key === 'symbol' ? key.toString() : String(key);
  if (BLOCKED_KEYS.has(keyStr)) throw new KerberosExprError(`Access to "${keyStr}" is not allowed`);
  return keyStr;
}

function evalMember(node, ctx, config) {
  const object = evalNode(node.object, ctx, config);
  const rawKey = node.computed ? evalNode(node.property, ctx, config) : node.property.name;
  const keyStr = safeKey(rawKey);

  if (object === null || object === undefined) {
    throw new TypeError(`Cannot read properties of ${object} (reading '${keyStr}')`);
  }

  return object[rawKey];
}

function evalBinary(node, ctx, config) {
  const { operator } = node;

  if (operator === '&&') {
    const left = evalNode(node.left, ctx, config);
    return left ? evalNode(node.right, ctx, config) : left;
  }
  if (operator === '||') {
    const left = evalNode(node.left, ctx, config);
    return left || evalNode(node.right, ctx, config);
  }
  if (operator === '??') {
    const left = evalNode(node.left, ctx, config);
    return left === null || left === undefined ? evalNode(node.right, ctx, config) : left;
  }

  const left = evalNode(node.left, ctx, config);
  const right = evalNode(node.right, ctx, config);

  switch (operator) {
    case '===': return left === right;
    case '!==': return left !== right;
    case '==': return left == right; // eslint-disable-line eqeqeq
    case '!=': return left != right; // eslint-disable-line eqeqeq
    case '<': return left < right;
    case '>': return left > right;
    case '<=': return left <= right;
    case '>=': return left >= right;
    case '+': return left + right;
    case '-': return left - right;
    case '*': return left * right;
    case '/': return left / right;
    case '%': return left % right;
    case '**': return left ** right;
    case '&': return left & right;
    case '|': return left | right;
    case '^': return left ^ right;
    case '<<': return left << right;
    case '>>': return left >> right;
    case '>>>': return left >>> right;
    default: throw new KerberosExprError(`Operator "${operator}" is not allowed`);
  }
}

function evalUnary(node, ctx, config) {
  switch (node.operator) {
    case '!': return !evalNode(node.argument, ctx, config);
    case '-': return -evalNode(node.argument, ctx, config);
    case '+': return +evalNode(node.argument, ctx, config);
    case '~': return ~evalNode(node.argument, ctx, config);
    case 'typeof': return typeof evalNode(node.argument, ctx, config);
    default: throw new KerberosExprError(`Unary operator "${node.operator}" is not allowed`);
  }
}

function evalObject(node, ctx, config) {
  const result = {};
  for (const property of node.properties) {
    const rawKey = property.computed
      ? evalNode(property.key, ctx, config)
      : property.key.type === 'Identifier' ? property.key.name : evalNode(property.key, ctx, config);
    const keyStr = safeKey(rawKey);
    result[keyStr] = evalNode(property.shorthand ? property.key : property.value, ctx, config);
  }
  return result;
}

function evalCall(node, ctx, config) {
  const { callee } = node;
  if (callee.type !== 'MemberExpression') throw new KerberosExprError('Only whitelisted method calls are allowed');

  const method = callee.computed ? evalNode(callee.property, ctx, config) : callee.property.name;
  const methodStr = safeKey(method);
  const args = node.arguments.map((argument) => evalNode(argument, ctx, config));

  if (callee.object.type === 'Identifier' && callee.object.name === 'Math') {
    if (!MATH_METHODS.has(methodStr)) throw new KerberosExprError(`Math.${methodStr} is not allowed`);
    return Math[methodStr](...args);
  }

  const receiver = evalNode(callee.object, ctx, config);
  const isAllowedReceiver = typeof receiver === 'string' || typeof receiver === 'number' || Array.isArray(receiver);
  if (!isAllowedReceiver) throw new KerberosExprError('Method calls are only allowed on string, number or array values');
  if (!VALUE_METHODS.has(methodStr)) throw new KerberosExprError(`Method "${methodStr}" is not allowed`);

  const fn = receiver[methodStr];
  if (typeof fn !== 'function') throw new KerberosExprError(`"${methodStr}" is not a callable method`);
  return fn.apply(receiver, args);
}

function evalNode(node, ctx, config) {
  switch (node.type) {
    case 'Literal':
      return node.value;
    case 'Identifier':
      if (Object.prototype.hasOwnProperty.call(ALLOWED_GLOBALS, node.name)) return ALLOWED_GLOBALS[node.name];
      if (config.roots.has(node.name)) return ctx == null ? undefined : ctx[node.name];
      throw new KerberosExprError(`Unknown identifier "${node.name}" (allowed roots: ${[...config.roots].join(', ')}, Math)`);
    case 'MemberExpression':
      return evalMember(node, ctx, config);
    case 'BinaryExpression':
      return evalBinary(node, ctx, config);
    case 'UnaryExpression':
      return evalUnary(node, ctx, config);
    case 'ConditionalExpression':
      return evalNode(node.test, ctx, config) ? evalNode(node.consequent, ctx, config) : evalNode(node.alternate, ctx, config);
    case 'ArrayExpression':
      return node.elements.map((element) => evalNode(element, ctx, config));
    case 'ObjectExpression':
      return evalObject(node, ctx, config);
    case 'CallExpression':
      return evalCall(node, ctx, config);
    case 'Compound':
      throw new KerberosExprError('Compound expressions are not allowed');
    default:
      throw new KerberosExprError(`Unsupported expression node: ${node.type}`);
  }
}

function isExprDescriptor(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) && typeof value.$expr === 'string';
}

function deepTransform(value, handlers) {
  if (isExprDescriptor(value)) return handlers.expr(value);
  if (typeof value === 'function') return handlers.func(value);
  if (Array.isArray(value)) return value.map((item) => deepTransform(item, handlers));
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value)) out[key] = deepTransform(value[key], handlers);
    return out;
  }
  return value;
}

/**
 * Creates the default, security-first policy codec.
 *
 * It does NOT serialize JavaScript function bodies and never uses `eval` /
 * `new Function`. Dynamic policies express `conditions`, `variables` and
 * `outputs` as expression descriptors `{ "$expr": "R.attr.ownerId == P.id" }`.
 * Expressions are parsed once into a cached AST via `jsep` and interpreted by a
 * strict allowlist evaluator over the `{ P, R, V, C }` request context.
 *
 * @param {{ roots?: string[] }} [options]
 * @returns {{
 *   isExprDescriptor: (value: unknown) => boolean,
 *   compileExpr: (expr: string) => (ctx: Record<string, unknown>) => unknown,
 *   serialize: (policyShape: unknown) => unknown,
 *   deserialize: (jsonSafe: unknown) => unknown,
 * }}
 */
function createSafeExprCodec(options = {}) {
  const config = { roots: new Set(options.roots || DEFAULT_ROOTS) };

  function compileExpr(expr) {
    const ast = parseExpr(expr);
    return (ctx) => evalNode(ast, ctx, config);
  }

  const deserializeHandlers = {
    expr: (descriptor) => compileExpr(descriptor.$expr),
    func: (fn) => fn,
  };

  const serializeHandlers = {
    expr: (descriptor) => {
      // Validate by parsing; throws on disallowed constructs.
      parseExpr(descriptor.$expr);
      return { $expr: descriptor.$expr };
    },
    func: () => {
      throw new KerberosExprError(
        'Cannot serialize a raw JavaScript function. Dynamic/remote policies must express conditions, ' +
        'variables and outputs as { $expr: "..." } string descriptors (no eval / fn.toString).'
      );
    },
  };

  return {
    isExprDescriptor,
    compileExpr,
    serialize(policyShape) {
      return deepTransform(policyShape, serializeHandlers);
    },
    deserialize(jsonSafe) {
      return deepTransform(jsonSafe, deserializeHandlers);
    },
  };
}

const defaultCodec = createSafeExprCodec();

/**
 * Serializes a policy/derived-roles shape into a JSON-safe document using the
 * default safe codec. Throws if it encounters a raw function.
 *
 * @param {unknown} shape
 * @returns {unknown}
 */
function serializePolicy(shape) {
  return defaultCodec.serialize(shape);
}

/**
 * Deserializes a JSON-safe policy/derived-roles document into a runtime shape
 * (with compiled, sandboxed expression functions) using the default safe codec.
 *
 * @param {unknown} json
 * @param {{ deserialize: (json: unknown) => unknown }} [codec]
 * @returns {unknown}
 */
function deserializePolicy(json, codec = defaultCodec) {
  return codec.deserialize(json);
}

module.exports = {
  KerberosExprError,
  createSafeExprCodec,
  serializePolicy,
  deserializePolicy,
};
