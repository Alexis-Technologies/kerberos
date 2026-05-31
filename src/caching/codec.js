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

/**
 * Builds a prototype-less dispatch table so lookups can never resolve to
 * inherited members (e.g. `constructor`, `__proto__`) and stay O(1).
 *
 * @param {Record<string, unknown>} entries
 * @returns {Record<string, unknown>}
 */
function createDispatch(entries) {
  return Object.assign(Object.create(null), entries);
}

// Short-circuit operators must evaluate their right branch lazily, so they are
// handled explicitly instead of through the eager binary dispatch table.
const SHORT_CIRCUIT_OPS = new Set(['&&', '||', '??']);

// O(1) binary operator dispatch. Each handler receives the already-evaluated
// operands; short-circuit operators are intentionally excluded (see above).
const BINARY_OPS = createDispatch({
  '===': (left, right) => left === right,
  '!==': (left, right) => left !== right,
  '==': (left, right) => left == right, // eslint-disable-line eqeqeq
  '!=': (left, right) => left != right, // eslint-disable-line eqeqeq
  '<': (left, right) => left < right,
  '>': (left, right) => left > right,
  '<=': (left, right) => left <= right,
  '>=': (left, right) => left >= right,
  '+': (left, right) => left + right,
  '-': (left, right) => left - right,
  '*': (left, right) => left * right,
  '/': (left, right) => left / right,
  '%': (left, right) => left % right,
  '**': (left, right) => left ** right,
  '&': (left, right) => left & right,
  '|': (left, right) => left | right,
  '^': (left, right) => left ^ right,
  '<<': (left, right) => left << right,
  '>>': (left, right) => left >> right,
  '>>>': (left, right) => left >>> right,
});

// O(1) unary operator dispatch over the already-evaluated argument.
const UNARY_OPS = createDispatch({
  '!': (value) => !value,
  '-': (value) => -value,
  '+': (value) => +value,
  '~': (value) => ~value,
  typeof: (value) => typeof value,
});

const ALLOWED_BINARY_OPS = new Set([...SHORT_CIRCUIT_OPS, ...Object.keys(BINARY_OPS)]);

const ALLOWED_UNARY_OPS = new Set(Object.keys(UNARY_OPS));

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

// Whitelisted `new` targets. Only simple Identifier callees are accepted.
const ALLOWED_CONSTRUCTORS = { Date };

const DATE_STATIC_METHODS = new Set(['now', 'parse', 'UTC']);

const DATE_METHODS = new Set([
  'getTime', 'valueOf', 'toISOString', 'toJSON', 'toString',
  'getFullYear', 'getMonth', 'getDate', 'getDay',
  'getHours', 'getMinutes', 'getSeconds', 'getMilliseconds',
  'getUTCFullYear', 'getUTCMonth', 'getUTCDate', 'getUTCDay',
  'getUTCHours', 'getUTCMinutes', 'getUTCSeconds', 'getUTCMilliseconds',
]);

// Top-level function calls with an Identifier callee (no member access).
const GLOBAL_FUNCTIONS = {
  parseInt,
  parseFloat,
  Number,
  String,
  Boolean,
  isNaN,
  isFinite,
};

const ALLOWED_GLOBALS = { Math, Date };

const DEFAULT_ROOTS = ['P', 'R', 'V', 'C'];

// AST cache keyed by jsep instance so different instances (different plugins /
// operators) get their own namespace. WeakMap ensures the cache is GC-able.
const astCacheByJsep = new WeakMap();

/**
 * Parses an expression once and caches the resulting AST keyed by both the
 * jsep instance and the expression string.
 *
 * @param {string} expr
 * @param {Function} jsepInstance  - a pre-configured jsep callable
 * @returns {Record<string, unknown>}
 */
function parseExpr(expr, jsepInstance) {
  if (typeof expr !== 'string') throw new KerberosExprError('Expression must be a string');

  let cache = astCacheByJsep.get(jsepInstance);
  if (!cache) {
    cache = new Map();
    astCacheByJsep.set(jsepInstance, cache);
  }

  if (cache.has(expr)) return cache.get(expr);

  let ast;
  try {
    ast = jsepInstance(expr);
  } catch (error) {
    throw new KerberosExprError(`Failed to parse expression: ${error.message}`);
  }
  validateNode(ast);
  cache.set(expr, ast);
  return ast;
}

/**
 * Structural fail-fast gate: ensures the AST only contains node types and
 * operators on the allowlist. Identifier names and member keys are enforced at
 * evaluation time (they depend on the runtime context), giving defense in depth.
 *
 * @param {Record<string, unknown>} node
 */
// O(1) node-type dispatch for structural validation. Mirrors NODE_EVALUATORS so
// every evaluable node type has a matching gate (defense in depth).
const NODE_VALIDATORS = createDispatch({
  Literal() {},
  Identifier() {},
  MemberExpression(node) {
    validateNode(node.object);
    if (node.computed) validateNode(node.property);
  },
  BinaryExpression(node) {
    if (!ALLOWED_BINARY_OPS.has(node.operator)) throw new KerberosExprError(`Operator "${node.operator}" is not allowed`);
    validateNode(node.left);
    validateNode(node.right);
  },
  UnaryExpression(node) {
    if (!ALLOWED_UNARY_OPS.has(node.operator)) throw new KerberosExprError(`Unary operator "${node.operator}" is not allowed`);
    validateNode(node.argument);
  },
  ConditionalExpression(node) {
    validateNode(node.test);
    validateNode(node.consequent);
    validateNode(node.alternate);
  },
  ArrayExpression(node) {
    for (const element of node.elements) validateNode(element);
  },
  ObjectExpression(node) {
    for (const property of node.properties) {
      if (property.computed) validateNode(property.key);
      validateNode(property.shorthand ? property.key : property.value);
    }
  },
  CallExpression(node) {
    if (node.callee.type === 'Identifier') {
      if (!Object.prototype.hasOwnProperty.call(GLOBAL_FUNCTIONS, node.callee.name)) {
        throw new KerberosExprError(`Function "${node.callee.name}" is not allowed`);
      }
    } else if (node.callee.type === 'MemberExpression') {
      validateNode(node.callee);
    } else {
      throw new KerberosExprError('Only whitelisted function or method calls are allowed');
    }
    for (const argument of node.arguments) validateNode(argument);
  },
  NewExpression(node) {
    if (node.callee.type !== 'Identifier' || !Object.prototype.hasOwnProperty.call(ALLOWED_CONSTRUCTORS, node.callee.name)) {
      throw new KerberosExprError('Only whitelisted constructors are allowed (Date)');
    }
    for (const argument of node.arguments) validateNode(argument);
  },
  Compound() {
    throw new KerberosExprError('Compound expressions (e.g. "a, b", "a in b") are not allowed');
  },
});

function validateNode(node) {
  if (!node || typeof node !== 'object') throw new KerberosExprError('Invalid expression node');

  const validator = NODE_VALIDATORS[node.type];
  if (!validator) throw new KerberosExprError(`Unsupported expression node: ${node.type}`);
  validator(node);
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

  const handler = BINARY_OPS[operator];
  if (!handler) throw new KerberosExprError(`Operator "${operator}" is not allowed`);

  const left = evalNode(node.left, ctx, config);
  const right = evalNode(node.right, ctx, config);
  return handler(left, right);
}

function evalUnary(node, ctx, config) {
  const handler = UNARY_OPS[node.operator];
  if (!handler) throw new KerberosExprError(`Unary operator "${node.operator}" is not allowed`);
  return handler(evalNode(node.argument, ctx, config));
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

function evalArguments(nodeArguments, ctx, config) {
  const args = new Array(nodeArguments.length);
  for (let i = 0; i < nodeArguments.length; i++) args[i] = evalNode(nodeArguments[i], ctx, config);
  return args;
}

function evalCall(node, ctx, config) {
  const { callee } = node;
  const args = evalArguments(node.arguments, ctx, config);

  if (callee.type === 'Identifier') {
    if (!Object.prototype.hasOwnProperty.call(GLOBAL_FUNCTIONS, callee.name)) {
      throw new KerberosExprError(`Function "${callee.name}" is not allowed`);
    }
    return GLOBAL_FUNCTIONS[callee.name](...args);
  }

  if (callee.type !== 'MemberExpression') throw new KerberosExprError('Only whitelisted function or method calls are allowed');

  const method = callee.computed ? evalNode(callee.property, ctx, config) : callee.property.name;
  const methodStr = safeKey(method);

  if (callee.object.type === 'Identifier' && callee.object.name === 'Math') {
    if (!MATH_METHODS.has(methodStr)) throw new KerberosExprError(`Math.${methodStr} is not allowed`);
    return Math[methodStr](...args);
  }

  if (callee.object.type === 'Identifier' && callee.object.name === 'Date') {
    if (!DATE_STATIC_METHODS.has(methodStr)) throw new KerberosExprError(`Date.${methodStr} is not allowed`);
    return Date[methodStr](...args);
  }

  const receiver = evalNode(callee.object, ctx, config);

  if (receiver instanceof Date) {
    if (!DATE_METHODS.has(methodStr)) throw new KerberosExprError(`Date instance method "${methodStr}" is not allowed`);
    const fn = receiver[methodStr];
    if (typeof fn !== 'function') throw new KerberosExprError(`"${methodStr}" is not a callable method`);
    return fn.apply(receiver, args);
  }

  const isAllowedReceiver = typeof receiver === 'string' || typeof receiver === 'number' || Array.isArray(receiver);
  if (!isAllowedReceiver) throw new KerberosExprError('Method calls are only allowed on string, number, array or Date values');
  if (!VALUE_METHODS.has(methodStr)) throw new KerberosExprError(`Method "${methodStr}" is not allowed`);

  const fn = receiver[methodStr];
  if (typeof fn !== 'function') throw new KerberosExprError(`"${methodStr}" is not a callable method`);
  return fn.apply(receiver, args);
}

function evalNew(node, ctx, config) {
  if (node.callee.type !== 'Identifier') throw new KerberosExprError('Only whitelisted constructors are allowed (Date)');

  const Constructor = ALLOWED_CONSTRUCTORS[node.callee.name];
  if (!Constructor) throw new KerberosExprError(`Constructor "${node.callee.name}" is not allowed`);

  const args = evalArguments(node.arguments, ctx, config);
  return new Constructor(...args);
}

function evalIdentifier(node, ctx, config) {
  if (Object.prototype.hasOwnProperty.call(ALLOWED_GLOBALS, node.name)) return ALLOWED_GLOBALS[node.name];
  if (config.roots.has(node.name)) return ctx == null ? undefined : ctx[node.name];
  throw new KerberosExprError(
    `Unknown identifier "${node.name}" (allowed roots: ${[...config.roots].join(', ')}, Math, Date, ${Object.keys(GLOBAL_FUNCTIONS).join(', ')})`
  );
}

function evalArray(node, ctx, config) {
  const { elements } = node;
  const result = new Array(elements.length);
  for (let i = 0; i < elements.length; i++) result[i] = evalNode(elements[i], ctx, config);
  return result;
}

function evalConditional(node, ctx, config) {
  return evalNode(node.test, ctx, config) ? evalNode(node.consequent, ctx, config) : evalNode(node.alternate, ctx, config);
}

function throwCompound() {
  throw new KerberosExprError('Compound expressions are not allowed');
}

// O(1) node-type dispatch used by the interpreter hot path. A prototype-less
// table guarantees an unknown/poisoned `node.type` resolves to `undefined`.
const NODE_EVALUATORS = createDispatch({
  Literal: (node) => node.value,
  Identifier: evalIdentifier,
  MemberExpression: evalMember,
  BinaryExpression: evalBinary,
  UnaryExpression: evalUnary,
  ConditionalExpression: evalConditional,
  ArrayExpression: evalArray,
  ObjectExpression: evalObject,
  CallExpression: evalCall,
  NewExpression: evalNew,
  Compound: throwCompound,
});

function evalNode(node, ctx, config) {
  const evaluator = NODE_EVALUATORS[node.type];
  if (!evaluator) throw new KerberosExprError(`Unsupported expression node: ${node.type}`);
  return evaluator(node, ctx, config);
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
    for (const key of Object.keys(value)) {
      const transformed = deepTransform(value[key], handlers);
      // An own `__proto__` key in untrusted cached JSON must be copied as a plain
      // data property instead of mutating the output object's prototype.
      // `defineProperty` bypasses the `__proto__` setter.
      if (key === '__proto__') {
        Object.defineProperty(out, key, { value: transformed, enumerable: true, writable: true, configurable: true });
      } else {
        out[key] = transformed;
      }
    }
    return out;
  }
  return value;
}

/**
 * Creates the built-in security-first policy codec.
 *
 * Requires a pre-configured `jsep` instance (with plugins already registered)
 * analogously to how `ajv` is passed to `new Kerberos(...)`.
 *
 * Does NOT use `eval` / `new Function` / `fn.toString`. Dynamic policies express
 * `conditions`, `variables` and `outputs` as `{ "$expr": "..." }` descriptors.
 * Expressions are parsed once into a cached AST via the provided jsep instance
 * and evaluated by a strict allowlist interpreter over `{ P, R, V, C }`.
 *
 * @param {{ jsep: Function, roots?: string[] }} options
 * @returns {{
 *   isExprDescriptor: (value: unknown) => boolean,
 *   compileExpr: (expr: string) => (ctx: Record<string, unknown>) => unknown,
 *   serialize: (policyShape: unknown) => unknown,
 *   deserialize: (jsonSafe: unknown) => unknown,
 * }}
 */
function createSafeExprCodec({ jsep, roots } = {}) {
  if (!jsep || typeof jsep !== 'function') {
    throw new KerberosExprError(
      'createSafeExprCodec({ jsep }) requires a pre-configured jsep instance. ' +
      'Install jsep and its plugins, then pass the instance:\n' +
      '  const jsep = require(\'jsep\').default;\n' +
      '  jsep.plugins.register(require(\'@jsep-plugin/object\'), ...);\n' +
      '  const codec = createSafeExprCodec({ jsep });'
    );
  }

  const config = { roots: new Set(roots || DEFAULT_ROOTS) };

  function compileExpr(expr) {
    const ast = parseExpr(expr, jsep);
    return (ctx) => evalNode(ast, ctx, config);
  }

  const deserializeHandlers = {
    expr: (descriptor) => compileExpr(descriptor.$expr),
    func: (fn) => fn,
  };

  const serializeHandlers = {
    expr: (descriptor) => {
      // Full validation: parse and check AST via the provided jsep instance.
      parseExpr(descriptor.$expr, jsep);
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

/**
 * Serializes a policy/derived-roles shape into a JSON-safe document.
 *
 * Throws `KerberosExprError` if any raw JavaScript function is encountered.
 * Pass `{ jsep }` to also validate each `{ $expr }` string by full AST parse.
 *
 * @param {unknown} shape
 * @param {{ jsep?: Function }} [options]
 * @returns {unknown}
 */
function serializePolicy(shape, { jsep } = {}) {
  const handlers = {
    expr: (descriptor) => {
      if (typeof descriptor.$expr !== 'string') throw new KerberosExprError('$expr must be a string');
      if (jsep) parseExpr(descriptor.$expr, jsep);
      return { $expr: descriptor.$expr };
    },
    func: () => {
      throw new KerberosExprError(
        'Cannot serialize a raw JavaScript function. Dynamic/remote policies must express conditions, ' +
        'variables and outputs as { $expr: "..." } string descriptors (no eval / fn.toString).'
      );
    },
  };
  return deepTransform(shape, handlers);
}

/**
 * Deserializes a JSON-safe policy/derived-roles document into a runtime shape
 * using the provided codec.
 *
 * @param {unknown} json
 * @param {{ deserialize: (json: unknown) => unknown }} codec
 * @returns {unknown}
 */
function deserializePolicy(json, codec) {
  if (!codec?.deserialize) {
    throw new KerberosExprError(
      'deserializePolicy requires a codec with a deserialize method. ' +
      'Create one via createSafeExprCodec({ jsep }).'
    );
  }
  return codec.deserialize(json);
}

module.exports = {
  KerberosExprError,
  createSafeExprCodec,
  serializePolicy,
  deserializePolicy,
};
