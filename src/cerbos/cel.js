/**
 * Lexer + recursive-descent parser for CEL (Common Expression Language)
 * expressions as used in Cerbos policy conditions.
 *
 * Follows the CEL grammar (https://github.com/google/cel-spec): ternary →
 * `||` → `&&` → relations (incl. `in`) → additive → multiplicative → unary →
 * member/index/call postfix → primary. The parser is complete for the
 * expression grammar; constructs Kerberos cannot evaluate (bytes literals,
 * message construction `Type{...}`, leading-dot absolute names) are rejected
 * HERE with a position-carrying error, while functions/macros outside the
 * translatable subset are rejected by the translator (translate.js).
 *
 * Platform-neutral, zero dependencies.
 */

const { KerberosImportError } = require('./errors.js');

// Reserved words of the CEL grammar; using one as an identifier is an error.
const RESERVED = new Set([
  'as',
  'break',
  'const',
  'continue',
  'else',
  'for',
  'function',
  'if',
  'import',
  'let',
  'loop',
  'package',
  'namespace',
  'return',
  'var',
  'void',
  'while',
]);

const PUNCT2 = new Set(['&&', '||', '<=', '>=', '==', '!=']);
const PUNCT1 = new Set(['<', '>', '!', '?', ':', '.', ',', '[', ']', '(', ')', '{', '}', '+', '-', '*', '/', '%']);

const ESCAPES = {
  a: '\x07',
  b: '\b',
  f: '\f',
  n: '\n',
  r: '\r',
  t: '\t',
  v: '\v',
  '\\': '\\',
  "'": "'",
  '"': '"',
  '`': '`',
  '?': '?',
};

function isDigit(ch) {
  return ch >= '0' && ch <= '9';
}

function isHexDigit(ch) {
  return isDigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

function isIdentStart(ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_';
}

function isIdentPart(ch) {
  return isIdentStart(ch) || isDigit(ch);
}

/** @returns {Array<{ type: string, value: unknown, pos: number, kind?: string }>} */
function tokenize(source) {
  const tokens = [];
  let i = 0;

  const fail = (message, at = i) => {
    throw new KerberosImportError(`CEL parse error at offset ${at}: ${message} — in \`${source}\``);
  };

  while (i < source.length) {
    const ch = source[i];

    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      i++;
      continue;
    }
    if (ch === '/' && source[i + 1] === '/') {
      while (i < source.length && source[i] !== '\n') i++;
      continue;
    }

    // String literals, with optional r/R (raw) and b/B (bytes) prefixes.
    if (
      ch === '"' ||
      ch === "'" ||
      ((ch === 'r' || ch === 'R' || ch === 'b' || ch === 'B') && isStringStart(source, i))
    ) {
      let raw = false;
      const start = i;
      let j = i;
      while (source[j] === 'r' || source[j] === 'R' || source[j] === 'b' || source[j] === 'B') {
        if (source[j] === 'b' || source[j] === 'B') fail('bytes literals are not supported', j);
        raw = true;
        j++;
      }
      const { value, end } = readString(source, j, raw, fail);
      tokens.push({ type: 'str', value, pos: start });
      i = end;
      continue;
    }

    if (isDigit(ch) || (ch === '.' && isDigit(source[i + 1]))) {
      const token = readNumber(source, i, fail);
      tokens.push(token);
      i = token.end;
      continue;
    }

    if (isIdentStart(ch)) {
      const start = i;
      while (i < source.length && isIdentPart(source[i])) i++;
      const word = source.slice(start, i);
      if (word === 'true' || word === 'false') tokens.push({ type: 'bool', value: word === 'true', pos: start });
      else if (word === 'null') tokens.push({ type: 'null', value: null, pos: start });
      else if (word === 'in') tokens.push({ type: 'punct', value: 'in', pos: start });
      else if (RESERVED.has(word)) fail(`\`${word}\` is a reserved word`, start);
      else tokens.push({ type: 'ident', value: word, pos: start });
      continue;
    }

    const two = source.slice(i, i + 2);
    if (PUNCT2.has(two)) {
      tokens.push({ type: 'punct', value: two, pos: i });
      i += 2;
      continue;
    }
    if (PUNCT1.has(ch)) {
      tokens.push({ type: 'punct', value: ch, pos: i });
      i++;
      continue;
    }
    fail(`unexpected character \`${ch}\``);
  }
  return tokens;
}

/** Is the r/R/b/B prefix run at `i` immediately followed by a quote? */
function isStringStart(source, i) {
  let j = i;
  while (source[j] === 'r' || source[j] === 'R' || source[j] === 'b' || source[j] === 'B') j++;
  return j > i && (source[j] === '"' || source[j] === "'");
}

function readString(source, start, raw, fail) {
  const quote = source[start];
  const triple = source.slice(start, start + 3) === quote.repeat(3);
  const delim = triple ? quote.repeat(3) : quote;
  let i = start + delim.length;
  let value = '';
  while (i < source.length) {
    if (source.slice(i, i + delim.length) === delim) return { value, end: i + delim.length };
    const ch = source[i];
    if (!triple && (ch === '\n' || ch === '\r')) fail('unterminated string literal', start);
    if (ch === '\\' && !raw) {
      const esc = source[i + 1];
      if (esc === 'x' || esc === 'u' || esc === 'U') {
        const len = esc === 'x' ? 2 : esc === 'u' ? 4 : 8;
        const hex = source.slice(i + 2, i + 2 + len);
        if (hex.length !== len || ![...hex].every(isHexDigit)) fail(`invalid \\${esc} escape`, i);
        const code = parseInt(hex, 16);
        if (code > 0x10ffff) fail(`invalid \\${esc} escape (out of range)`, i);
        value += String.fromCodePoint(code);
        i += 2 + len;
        continue;
      }
      if (esc >= '0' && esc <= '7') {
        const oct = source.slice(i + 1, i + 4);
        if (oct.length !== 3 || ![...oct].every((c) => c >= '0' && c <= '7')) fail('invalid octal escape', i);
        value += String.fromCodePoint(parseInt(oct, 8));
        i += 4;
        continue;
      }
      if (esc === undefined || !(esc in ESCAPES)) fail(`unsupported escape \\${esc ?? ''}`, i);
      value += ESCAPES[esc];
      i += 2;
      continue;
    }
    value += ch;
    i++;
  }
  return fail('unterminated string literal', start);
}

function readNumber(source, start, fail) {
  let i = start;
  if (source[i] === '0' && (source[i + 1] === 'x' || source[i + 1] === 'X')) {
    i += 2;
    const hexStart = i;
    while (i < source.length && isHexDigit(source[i])) i++;
    if (i === hexStart) fail('invalid hex literal', start);
    const value = parseInt(source.slice(hexStart, i), 16);
    let kind = 'int';
    if (source[i] === 'u' || source[i] === 'U') {
      kind = 'uint';
      i++;
    }
    return { type: 'num', kind, value, pos: start, end: i };
  }

  while (i < source.length && isDigit(source[i])) i++;
  let isDouble = false;
  // CEL doubles require a digit after the decimal point (`3.` is `3 .`).
  if (source[i] === '.' && isDigit(source[i + 1])) {
    isDouble = true;
    i++;
    while (i < source.length && isDigit(source[i])) i++;
  }
  if (source[i] === 'e' || source[i] === 'E') {
    let j = i + 1;
    if (source[j] === '+' || source[j] === '-') j++;
    if (isDigit(source[j])) {
      isDouble = true;
      i = j;
      while (i < source.length && isDigit(source[i])) i++;
    }
  }
  if (!isDouble && (source[i] === 'u' || source[i] === 'U')) {
    const value = Number(source.slice(start, i));
    return { type: 'num', kind: 'uint', value, pos: start, end: i + 1 };
  }
  const text = source.slice(start, i);
  return { type: 'num', kind: isDouble ? 'double' : 'int', value: Number(text), pos: start, end: i };
}

/** Recursive-descent parser producing the CEL AST consumed by translate.js. */
class CelParser {
  constructor(source) {
    this.source = source;
    this.tokens = tokenize(source);
    this.index = 0;
  }

  fail(message, token = this.peek()) {
    const at = token ? ` at offset ${token.pos}` : ' at end of input';
    throw new KerberosImportError(`CEL parse error${at}: ${message} — in \`${this.source}\``);
  }

  peek() {
    return this.tokens[this.index] ?? null;
  }

  next() {
    const token = this.tokens[this.index];
    if (!token) this.fail('unexpected end of expression');
    this.index++;
    return token;
  }

  atPunct(value) {
    const token = this.peek();
    return token !== null && token.type === 'punct' && token.value === value;
  }

  expect(value) {
    const token = this.next();
    if (token.type !== 'punct' || token.value !== value) this.fail(`expected \`${value}\``, token);
    return token;
  }

  parse() {
    const expr = this.parseExpr();
    const leftover = this.peek();
    if (leftover) this.fail('unexpected trailing content', leftover);
    return expr;
  }

  parseExpr() {
    const test = this.parseOr();
    if (!this.atPunct('?')) return test;
    this.next();
    const consequent = this.parseOr();
    this.expect(':');
    const alternate = this.parseExpr();
    return { type: 'ternary', test, consequent, alternate };
  }

  parseOr() {
    let left = this.parseAnd();
    while (this.atPunct('||')) {
      this.next();
      left = { type: 'binary', op: '||', left, right: this.parseAnd() };
    }
    return left;
  }

  parseAnd() {
    let left = this.parseRelation();
    while (this.atPunct('&&')) {
      this.next();
      left = { type: 'binary', op: '&&', left, right: this.parseRelation() };
    }
    return left;
  }

  parseRelation() {
    let left = this.parseAdd();
    for (;;) {
      const token = this.peek();
      if (
        token &&
        token.type === 'punct' &&
        (token.value === '<' ||
          token.value === '<=' ||
          token.value === '>' ||
          token.value === '>=' ||
          token.value === '==' ||
          token.value === '!=' ||
          token.value === 'in')
      ) {
        this.next();
        left = { type: 'binary', op: token.value, left, right: this.parseAdd() };
        continue;
      }
      return left;
    }
  }

  parseAdd() {
    let left = this.parseMul();
    for (;;) {
      if (this.atPunct('+') || this.atPunct('-')) {
        const op = this.next().value;
        left = { type: 'binary', op, left, right: this.parseMul() };
        continue;
      }
      return left;
    }
  }

  parseMul() {
    let left = this.parseUnary();
    for (;;) {
      if (this.atPunct('*') || this.atPunct('/') || this.atPunct('%')) {
        const op = this.next().value;
        left = { type: 'binary', op, left, right: this.parseUnary() };
        continue;
      }
      return left;
    }
  }

  parseUnary() {
    if (this.atPunct('!') || this.atPunct('-')) {
      const op = this.next().value;
      return { type: 'unary', op, operand: this.parseUnary() };
    }
    return this.parseMember();
  }

  parseMember() {
    let node = this.parsePrimary();
    for (;;) {
      if (this.atPunct('.')) {
        this.next();
        const nameToken = this.next();
        if (nameToken.type !== 'ident') this.fail('expected a field or method name after `.`', nameToken);
        if (this.atPunct('(')) {
          node = { type: 'call', target: node, name: nameToken.value, args: this.parseArgs() };
        } else {
          node = { type: 'select', object: node, field: nameToken.value };
        }
        continue;
      }
      if (this.atPunct('[')) {
        this.next();
        const index = this.parseExpr();
        this.expect(']');
        node = { type: 'index', object: node, index };
        continue;
      }
      if (this.atPunct('{')) {
        this.fail('message construction (`Type{...}`) is not supported');
      }
      return node;
    }
  }

  parseArgs() {
    this.expect('(');
    const args = [];
    if (this.atPunct(')')) {
      this.next();
      return args;
    }
    for (;;) {
      args.push(this.parseExpr());
      if (this.atPunct(',')) {
        this.next();
        continue;
      }
      this.expect(')');
      return args;
    }
  }

  parsePrimary() {
    const token = this.peek();
    if (!token) this.fail('unexpected end of expression');

    if (token.type === 'punct') {
      if (token.value === '(') {
        this.next();
        const inner = this.parseExpr();
        this.expect(')');
        return inner;
      }
      if (token.value === '[') {
        this.next();
        const elements = [];
        if (this.atPunct(']')) {
          this.next();
          return { type: 'list', elements };
        }
        for (;;) {
          elements.push(this.parseExpr());
          if (this.atPunct(',')) {
            this.next();
            if (this.atPunct(']')) break; // trailing comma
            continue;
          }
          break;
        }
        this.expect(']');
        return { type: 'list', elements };
      }
      if (token.value === '{') {
        this.next();
        const entries = [];
        if (this.atPunct('}')) {
          this.next();
          return { type: 'map', entries };
        }
        for (;;) {
          const key = this.parseExpr();
          this.expect(':');
          const value = this.parseExpr();
          entries.push({ key, value });
          if (this.atPunct(',')) {
            this.next();
            if (this.atPunct('}')) break; // trailing comma
            continue;
          }
          break;
        }
        this.expect('}');
        return { type: 'map', entries };
      }
      if (token.value === '.') {
        this.fail('leading-dot absolute names (`.name`) are not supported');
      }
      this.fail(`unexpected \`${token.value}\``);
    }

    if (token.type === 'ident') {
      this.next();
      if (this.atPunct('(')) return { type: 'call', target: null, name: token.value, args: this.parseArgs() };
      if (this.atPunct('{')) this.fail('message construction (`Type{...}`) is not supported');
      return { type: 'ident', name: token.value };
    }

    this.next();
    if (token.type === 'num') return { type: 'lit', kind: token.kind, value: token.value };
    if (token.type === 'str') return { type: 'lit', kind: 'string', value: token.value };
    if (token.type === 'bool') return { type: 'lit', kind: 'bool', value: token.value };
    if (token.type === 'null') return { type: 'lit', kind: 'null', value: null };
    return this.fail(`unexpected token`, token);
  }
}

/**
 * Parses a CEL expression into an AST.
 *
 * @param {string} source
 * @returns {Record<string, unknown>}
 */
function parseCel(source) {
  if (typeof source !== 'string' || source.trim() === '') {
    throw new KerberosImportError('CEL expression must be a non-empty string');
  }
  return new CelParser(source).parse();
}

module.exports = { parseCel };
