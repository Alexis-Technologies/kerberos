/**
 * CEL → `$expr` translator: turns a Cerbos condition expression into a
 * JavaScript expression evaluatable by the safe `$expr` interpreter
 * (`createSafeExprCodec` with the documented jsep setup: the object/ternary/new
 * plugins plus `jsep.addUnaryOp('typeof')`).
 *
 * The governing invariant is REFUSE TO GUESS: every construct is either
 * translated with faithful semantics or rejected with a named error — nothing
 * is dropped or approximated silently. The deliberate documented deviations
 * (`/` on unknown operands follows JS numeric semantics; `lowerAscii` /
 * `upperAscii` map to full-Unicode case folding; `in` translates to
 * `.includes` and therefore errors at evaluation on map receivers) are listed
 * in the importer docs.
 *
 * Representation choices:
 * - timestamps are epoch-millisecond NUMBERS (`timestamp(x)` → `Date.parse(x)`,
 *   `now()` → `Date.now()`), so comparisons, equality and arithmetic all work
 *   with plain numeric operators;
 * - durations are millisecond numbers, constant-folded from `duration("72h")`
 *   Go-style literals;
 * - `has(e)` → `typeof e !== "undefined"` (matches CEL: an explicit null field
 *   is present; a missing one is not).
 */

const { KerberosImportError } = require('./errors.js');
const { parseCel } = require('./cel.js');

function unsupported(what, source) {
  throw new KerberosImportError(`${what} — in \`${source}\``);
}

// JavaScript operator precedence tiers used for minimal parenthesization.
const PREC = {
  ternary: 1,
  nullish: 2,
  or: 3,
  and: 4,
  equality: 8,
  relational: 9,
  additive: 11,
  multiplicative: 12,
  unary: 14,
  postfix: 17,
  primary: 20,
};

const BINARY_JS = {
  '||': { op: '||', prec: PREC.or },
  '&&': { op: '&&', prec: PREC.and },
  '==': { op: '===', prec: PREC.equality },
  '!=': { op: '!==', prec: PREC.equality },
  '<': { op: '<', prec: PREC.relational },
  '<=': { op: '<=', prec: PREC.relational },
  '>': { op: '>', prec: PREC.relational },
  '>=': { op: '>=', prec: PREC.relational },
  '+': { op: '+', prec: PREC.additive },
  '-': { op: '-', prec: PREC.additive },
  '*': { op: '*', prec: PREC.multiplicative },
  '/': { op: '/', prec: PREC.multiplicative },
  '%': { op: '%', prec: PREC.multiplicative },
};

// Member keys the $expr interpreter blocks unconditionally — reject at import
// time so the policy fails loudly here rather than at evaluation.
const BLOCKED_FIELDS = new Set(['__proto__', 'prototype', 'constructor']);

// Cerbos CEL extension functions with no faithful `$expr` counterpart.
const CERBOS_EXTENSIONS = new Set([
  'hasIntersection',
  'intersect',
  'except',
  'isSubset',
  'hierarchy',
  'spiffeID',
  'spiffeMatchAny',
  'spiffeMatchExact',
  'spiffeMatchOneOf',
  'spiffeMatchTrustDomain',
  'inIPAddrRange',
  'timeSince',
  'format',
  'matches',
]);

// CEL comprehension macros require lambda support the interpreter does not have.
const MACROS = new Set(['exists', 'all', 'exists_one', 'filter', 'map']);

// CEL timestamp accessors (UTC by default) → JS Date UTC accessors.
const TIMESTAMP_ACCESSORS = {
  getFullYear: 'getUTCFullYear',
  getMonth: 'getUTCMonth', // both zero-based
  getDate: 'getUTCDate', // both one-based
  getDayOfWeek: 'getUTCDay', // both zero-based, Sunday = 0
  getHours: 'getUTCHours',
  getMinutes: 'getUTCMinutes',
  getSeconds: 'getUTCSeconds',
  getMilliseconds: 'getUTCMilliseconds',
};

// CEL duration accessors return the TOTAL truncated to the unit (cel-go
// delegates to Go's time.Duration.Hours()/Minutes()/... equivalents).
const DURATION_ACCESSORS = { getHours: 3600000, getMinutes: 60000, getSeconds: 1000, getMilliseconds: 1 };

const GO_DURATION_RE = /^[+-]?(\d+(\.\d+)?(ns|us|µs|μs|ms|s|m|h))+$/;
const GO_DURATION_UNIT_MS = { ns: 1e-6, us: 1e-3, µs: 1e-3, μs: 1e-3, ms: 1, s: 1000, m: 60000, h: 3600000 };

/** Parses a Go-style duration literal (`"72h3m0.5s"`, `"300s"`) into milliseconds. */
function parseGoDuration(text, source) {
  if (typeof text !== 'string' || !GO_DURATION_RE.test(text)) {
    unsupported(`\`duration("${text}")\` is not a valid duration literal`, source);
  }
  const sign = text[0] === '-' ? -1 : 1;
  let ms = 0;
  for (const [, amount, , unit] of text.matchAll(/(\d+(\.\d+)?)(ns|us|µs|μs|ms|s|m|h)/g)) {
    ms += Number(amount) * GO_DURATION_UNIT_MS[unit];
  }
  return sign * ms;
}

/** Emits a JS string literal the jsep lexer reads back to exactly `value`. */
function emitString(value) {
  return JSON.stringify(value);
}

class Translator {
  constructor(source) {
    this.source = source;
  }

  fail(what) {
    unsupported(what, this.source);
  }

  /**
   * Static kind inference for the timestamp/duration number encoding:
   * `'timestamp'` and `'duration'` nodes are epoch-ms / ms numbers.
   */
  kindOf(node) {
    if (node.type === 'call' && node.target === null) {
      if (node.name === 'timestamp' || node.name === 'now') return 'timestamp';
      if (node.name === 'duration') return 'duration';
    }
    if (node.type === 'binary' && (node.op === '+' || node.op === '-')) {
      const left = this.kindOf(node.left);
      const right = this.kindOf(node.right);
      if (left === 'timestamp' && right === 'timestamp') return node.op === '-' ? 'duration' : null;
      if (left === 'timestamp' && right === 'duration') return 'timestamp';
      if (left === 'duration' && right === 'timestamp') return node.op === '+' ? 'timestamp' : null;
      if (left === 'duration' && right === 'duration') return 'duration';
      return null;
    }
    if (node.type === 'ternary') {
      const consequent = this.kindOf(node.consequent);
      return consequent !== null && consequent === this.kindOf(node.alternate) ? consequent : null;
    }
    return null;
  }

  wrap(text, prec, minPrec) {
    return prec < minPrec ? `(${text})` : text;
  }

  emit(node, minPrec) {
    switch (node.type) {
      case 'lit':
        return this.emitLiteral(node, minPrec);
      case 'ident':
        return this.emitIdent(node.name);
      case 'select':
        return this.emitSelect(node, minPrec);
      case 'index':
        return this.wrap(`${this.emit(node.object, PREC.postfix)}[${this.emit(node.index, 0)}]`, PREC.postfix, minPrec);
      case 'list':
        return `[${node.elements.map((element) => this.emit(element, 0)).join(', ')}]`;
      case 'map':
        return this.emitMap(node);
      case 'unary':
        return this.wrap(`${node.op}${this.emit(node.operand, PREC.unary)}`, PREC.unary, minPrec);
      case 'binary':
        return this.emitBinary(node, minPrec);
      case 'ternary':
        return this.wrap(
          `${this.emit(node.test, PREC.nullish)} ? ${this.emit(node.consequent, PREC.nullish)} : ${this.emit(node.alternate, PREC.ternary)}`,
          PREC.ternary,
          minPrec,
        );
      case 'call':
        return node.target === null ? this.emitGlobalCall(node, minPrec) : this.emitMethodCall(node, minPrec);
      default:
        return this.fail(`internal: unknown CEL node \`${node.type}\``);
    }
  }

  emitLiteral(node, minPrec) {
    if (node.kind === 'string') return emitString(node.value);
    if (node.kind === 'bool') return node.value ? 'true' : 'false';
    if (node.kind === 'null') return 'null';
    if (node.kind === 'int' || node.kind === 'uint') {
      if (!Number.isSafeInteger(node.value)) {
        this.fail(`integer literal ${node.value} exceeds JavaScript's safe integer range`);
      }
      return node.value < 0 ? this.wrap(String(node.value), PREC.unary, minPrec) : String(node.value);
    }
    return String(node.value); // double
  }

  emitIdent(name) {
    if (name === 'R' || name === 'P' || name === 'V' || name === 'C') return name;
    if (name === 'variables') return 'V';
    if (name === 'constants') return 'C';
    if (name === 'request') this.fail('bare `request` is not translatable (use request.principal / request.resource)');
    if (name === 'globals' || name === 'G') {
      this.fail('`globals` are not supported by Kerberos — use policy constants (`C`)');
    }
    if (name === 'runtime') this.fail('`runtime` (effectiveDerivedRoles) is not supported');
    return this.fail(`unknown identifier \`${name}\` (supported roots: request, R, P, V, C, variables, constants)`);
  }

  emitSelect(node, minPrec) {
    if (BLOCKED_FIELDS.has(node.field)) {
      this.fail(`field \`${node.field}\` is blocked by the $expr interpreter`);
    }
    if (node.object.type === 'ident' && node.object.name === 'request') {
      if (node.field === 'principal') return 'P';
      if (node.field === 'resource') return 'R';
      if (node.field === 'auxData') {
        this.fail('`request.auxData` is not supported — copy JWT claims into principal.attr');
      }
      this.fail(`unknown \`request.${node.field}\``);
    }
    return this.wrap(`${this.emit(node.object, PREC.postfix)}.${node.field}`, PREC.postfix, minPrec);
  }

  emitMap(node) {
    const entries = node.entries.map(({ key, value }) => {
      if (key.type !== 'lit' || key.kind !== 'string') {
        this.fail('map literals with non-string keys are not supported');
      }
      return `${emitString(key.value)}: ${this.emit(value, 0)}`;
    });
    return `{ ${entries.join(', ')} }`;
  }

  emitBinary(node, minPrec) {
    if (node.op === 'in') {
      // CEL list/string membership. On a map receiver `.includes` errors at
      // evaluation (fail-loud) instead of silently checking values.
      return this.wrap(
        `${this.emit(node.right, PREC.postfix)}.includes(${this.emit(node.left, 0)})`,
        PREC.postfix,
        minPrec,
      );
    }
    if (node.op === '+' || node.op === '-') {
      for (const side of [node.left, node.right]) {
        if (side.type === 'list' || side.type === 'map') {
          this.fail('list/map concatenation with `+` is not supported');
        }
      }
    }
    if (node.op === '/' && this.isIntLiteral(node.left) && this.isIntLiteral(node.right)) {
      // CEL integer division truncates; only provable for literal operands.
      return this.wrap(
        `Math.trunc(${this.emit(node.left, PREC.multiplicative)} / ${this.emit(node.right, PREC.unary)})`,
        PREC.postfix,
        minPrec,
      );
    }
    const js = BINARY_JS[node.op];
    if (!js) this.fail(`operator \`${node.op}\` is not supported`);
    // Left-associative: the right operand needs one tier tighter.
    const left = this.emit(node.left, js.prec);
    const right = this.emit(node.right, js.prec + 1);
    return this.wrap(`${left} ${js.op} ${right}`, js.prec, minPrec);
  }

  isIntLiteral(node) {
    return node.type === 'lit' && (node.kind === 'int' || node.kind === 'uint');
  }

  emitGlobalCall(node, minPrec) {
    const { name, args } = node;
    const arity = (n) => {
      if (args.length !== n) this.fail(`\`${name}()\` expects ${n} argument${n === 1 ? '' : 's'}`);
    };

    switch (name) {
      case 'has': {
        arity(1);
        const [arg] = args;
        if (arg.type !== 'select' && arg.type !== 'index') {
          this.fail('`has()` requires a field selection argument');
        }
        return this.wrap(`typeof ${this.emit(arg, PREC.unary)} !== "undefined"`, PREC.equality, minPrec);
      }
      case 'size':
        arity(1);
        return this.wrap(`${this.emit(args[0], PREC.postfix)}.length`, PREC.postfix, minPrec);
      case 'timestamp':
        arity(1);
        if (this.kindOf(args[0]) === 'timestamp') return this.emit(args[0], minPrec);
        return this.wrap(`Date.parse(${this.emit(args[0], 0)})`, PREC.postfix, minPrec);
      case 'now':
        arity(0);
        return this.wrap('Date.now()', PREC.postfix, minPrec);
      case 'duration': {
        arity(1);
        const [arg] = args;
        if (arg.type !== 'lit' || arg.kind !== 'string') {
          this.fail('`duration()` with a non-literal argument is not supported');
        }
        const ms = parseGoDuration(arg.value, this.source);
        return ms < 0 ? this.wrap(String(ms), PREC.unary, minPrec) : String(ms);
      }
      case 'int':
      case 'uint': {
        arity(1);
        if (this.kindOf(args[0]) === 'timestamp') {
          // CEL int(timestamp) = epoch seconds.
          return this.wrap(`Math.trunc(${this.emit(args[0], PREC.multiplicative)} / 1000)`, PREC.postfix, minPrec);
        }
        return this.wrap(`Math.trunc(Number(${this.emit(args[0], 0)}))`, PREC.postfix, minPrec);
      }
      case 'double':
        arity(1);
        return this.wrap(`Number(${this.emit(args[0], 0)})`, PREC.postfix, minPrec);
      case 'string': {
        arity(1);
        if (this.kindOf(args[0]) === 'timestamp') {
          return this.wrap(`new Date(${this.emit(args[0], 0)}).toISOString()`, PREC.postfix, minPrec);
        }
        return this.wrap(`String(${this.emit(args[0], 0)})`, PREC.postfix, minPrec);
      }
      case 'dyn':
        arity(1);
        return this.emit(args[0], minPrec);
      case 'bool':
      case 'bytes':
      case 'type':
        return this.fail(`\`${name}()\` is not supported`);
      default:
        if (CERBOS_EXTENSIONS.has(name)) {
          this.fail(`Cerbos CEL extension \`${name}()\` has no $expr counterpart`);
        }
        return this.fail(`function \`${name}()\` is not supported`);
    }
  }

  emitMethodCall(node, minPrec) {
    const { target, name, args } = node;
    const arity = (n) => {
      if (args.length !== n) this.fail(`\`.${name}()\` expects ${n} argument${n === 1 ? '' : 's'}`);
    };
    const method = (jsName) =>
      this.wrap(
        `${this.emit(target, PREC.postfix)}.${jsName}(${args.map((arg) => this.emit(arg, 0)).join(', ')})`,
        PREC.postfix,
        minPrec,
      );

    if (MACROS.has(name)) {
      this.fail(`CEL macro \`.${name}()\` cannot be translated (the $expr interpreter has no lambdas)`);
    }

    const targetKind = this.kindOf(target);
    if (targetKind === 'timestamp' && name in TIMESTAMP_ACCESSORS) {
      if (args.length !== 0) this.fail(`\`.${name}()\` with a time-zone argument is not supported`);
      return this.wrap(`new Date(${this.emit(target, 0)}).${TIMESTAMP_ACCESSORS[name]}()`, PREC.postfix, minPrec);
    }
    if (targetKind === 'timestamp' && name === 'getDayOfMonth') {
      // CEL's getDayOfMonth is zero-based; JS getUTCDate is one-based.
      if (args.length !== 0) this.fail('`.getDayOfMonth()` with a time-zone argument is not supported');
      return this.wrap(`new Date(${this.emit(target, 0)}).getUTCDate() - 1`, PREC.additive, minPrec);
    }
    if (targetKind === 'duration' && name in DURATION_ACCESSORS) {
      arity(0);
      const divisor = DURATION_ACCESSORS[name];
      const inner = this.emit(target, divisor === 1 ? PREC.postfix : PREC.multiplicative);
      return divisor === 1
        ? this.wrap(`Math.trunc(${this.emit(target, 0)})`, PREC.postfix, minPrec)
        : this.wrap(`Math.trunc(${inner} / ${divisor})`, PREC.postfix, minPrec);
    }
    if (name === 'getDayOfYear') this.fail('`.getDayOfYear()` has no JavaScript counterpart');

    switch (name) {
      case 'startsWith':
      case 'endsWith':
        arity(1);
        return method(name);
      case 'contains':
        arity(1);
        return method('includes');
      case 'size':
        arity(0);
        return this.wrap(`${this.emit(target, PREC.postfix)}.length`, PREC.postfix, minPrec);
      case 'matches':
        return this.fail('`.matches()` (RE2 regular expressions) is not supported by the $expr interpreter');
      case 'lowerAscii':
        arity(0);
        return method('toLowerCase');
      case 'upperAscii':
        arity(0);
        return method('toUpperCase');
      case 'trim':
        arity(0);
        return method('trim');
      case 'replace':
        // CEL's replace substitutes every occurrence; JS .replace substitutes
        // the first, so translate through split/join.
        if (args.length !== 2) this.fail('`.replace()` with a limit argument is not supported');
        return this.wrap(
          `${this.emit(target, PREC.postfix)}.split(${this.emit(args[0], 0)}).join(${this.emit(args[1], 0)})`,
          PREC.postfix,
          minPrec,
        );
      case 'split':
        if (args.length !== 1) {
          this.fail('`.split()` with a limit argument is not supported (JS truncates, CEL keeps the remainder)');
        }
        return method('split');
      case 'join':
        if (args.length > 1) this.fail('`.join()` expects at most 1 argument');
        // CEL's default separator is '' where JavaScript's is ','.
        return args.length === 0
          ? this.wrap(`${this.emit(target, PREC.postfix)}.join("")`, PREC.postfix, minPrec)
          : method('join');
      case 'charAt':
        arity(1);
        return method('charAt');
      case 'indexOf':
      case 'lastIndexOf':
        if (args.length < 1 || args.length > 2) this.fail(`\`.${name}()\` expects 1 or 2 arguments`);
        return method(name);
      case 'substring':
        if (args.length < 1 || args.length > 2) this.fail('`.substring()` expects 1 or 2 arguments');
        return method('substring');
      default:
        if (CERBOS_EXTENSIONS.has(name)) {
          this.fail(`Cerbos CEL extension \`.${name}()\` has no $expr counterpart`);
        }
        return this.fail(`method \`.${name}()\` is not supported`);
    }
  }
}

/**
 * Translates one CEL expression into a `$expr`-compatible JavaScript
 * expression string.
 *
 * @param {string} source
 * @returns {string}
 */
function celToExpr(source) {
  const ast = parseCel(source);
  return new Translator(source).emit(ast, 0);
}

module.exports = { celToExpr, parseGoDuration };
