/**
 * Zero-dependency parser for the YAML subset Cerbos policy documents are
 * written in: block mappings and sequences, flow collections, plain / quoted /
 * block scalars, comments, and `---` multi-document streams.
 *
 * This is deliberately NOT a general YAML parser. Constructs whose semantics
 * would have to be guessed at are rejected with a clear error instead of being
 * approximated: anchors/aliases (`&`, `*`), tags (`!`, `!!`), directives
 * (`%YAML`), explicit keys (`? `), multi-line plain scalars, tab indentation,
 * and `.inf` / `.nan` floats. Everything the parser does accept is verified
 * against the reference `yaml` package over the whole conformance corpus (see
 * test/CerbosYaml.test.js).
 *
 * Platform-neutral: no Node builtins, safe for the browser bundle.
 */

const { KerberosImportError } = require('./errors.js');

function fail(message, line) {
  throw new KerberosImportError(message, { line });
}

/** Leading-space count; tabs in indentation are rejected (as in YAML proper). */
function indentOf(text, lineNo) {
  let i = 0;
  while (i < text.length && text[i] === ' ') i++;
  if (text[i] === '\t') fail('tab characters are not allowed in indentation', lineNo);
  return i;
}

/**
 * Strips a trailing comment from a structural line: a `#` at content start or
 * preceded by whitespace, outside single/double quotes, starts a comment.
 * Never applied to block-scalar content lines (those keep `#` literally).
 */
function stripComment(text) {
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote === "'") {
      if (ch === "'") quote = text[i + 1] === "'" ? (i++, "'") : null;
    } else if (quote === '"') {
      if (ch === '\\') i++;
      else if (ch === '"') quote = null;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === '#' && (i === 0 || text[i - 1] === ' ' || text[i - 1] === '\t')) {
      return text.slice(0, i).trimEnd();
    }
  }
  return text.trimEnd();
}

const INT_RE = /^[-+]?[0-9]+$/;
const HEX_RE = /^0x[0-9a-fA-F]+$/;
const OCT_RE = /^0o[0-7]+$/;
const FLOAT_RE = /^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$/;
const SPECIAL_FLOAT_RE = /^[-+]?\.(inf|Inf|INF|nan|NaN|NAN)$/;

/** YAML 1.2 core-schema resolution for plain scalars, minus non-finite floats. */
function resolvePlainScalar(text, lineNo) {
  if (text === '' || text === '~' || text === 'null' || text === 'Null' || text === 'NULL') return null;
  if (text === 'true' || text === 'True' || text === 'TRUE') return true;
  if (text === 'false' || text === 'False' || text === 'FALSE') return false;
  if (INT_RE.test(text)) return parseInt(text, 10);
  if (HEX_RE.test(text)) return parseInt(text.slice(2), 16);
  if (OCT_RE.test(text)) return parseInt(text.slice(2), 8);
  if (SPECIAL_FLOAT_RE.test(text)) fail(`non-finite float \`${text}\` is not supported`, lineNo);
  if (FLOAT_RE.test(text)) return parseFloat(text);
  return text;
}

const DOUBLE_ESCAPES = {
  0: '\0',
  a: '\x07',
  b: '\b',
  t: '\t',
  n: '\n',
  v: '\v',
  f: '\f',
  r: '\r',
  e: '\x1b',
  ' ': ' ',
  '"': '"',
  '/': '/',
  '\\': '\\',
  N: '\u0085',
  _: '\u00a0',
  L: '\u2028',
  P: '\u2029',
};

/**
 * Parses a quoted scalar starting at `text[start]` (which is `'` or `"`).
 * Returns `{ value, end }` where `end` is the index just past the closing
 * quote. Quoted scalars must close on the same line (multi-line quoted
 * scalars are outside the subset).
 */
function parseQuoted(text, start, lineNo) {
  const quote = text[start];
  let value = '';
  let i = start + 1;
  while (i < text.length) {
    const ch = text[i];
    if (quote === "'") {
      if (ch === "'") {
        if (text[i + 1] === "'") {
          value += "'";
          i += 2;
          continue;
        }
        return { value, end: i + 1 };
      }
      value += ch;
      i++;
    } else {
      if (ch === '"') return { value, end: i + 1 };
      if (ch === '\\') {
        const esc = text[i + 1];
        if (esc === 'x' || esc === 'u' || esc === 'U') {
          const len = esc === 'x' ? 2 : esc === 'u' ? 4 : 8;
          const hex = text.slice(i + 2, i + 2 + len);
          if (hex.length !== len || !/^[0-9a-fA-F]+$/.test(hex)) fail(`invalid \\${esc} escape`, lineNo);
          value += String.fromCodePoint(parseInt(hex, 16));
          i += 2 + len;
          continue;
        }
        if (esc === undefined || !(esc in DOUBLE_ESCAPES)) fail(`unsupported escape \\${esc ?? ''}`, lineNo);
        value += DOUBLE_ESCAPES[esc];
        i += 2;
        continue;
      }
      value += ch;
      i++;
    }
  }
  return fail('unterminated quoted string', lineNo);
}

function rejectNodeProperties(text, lineNo, where) {
  const ch = text[0];
  if (ch === '&') fail(`anchors (\`&\`) are not supported${where}`, lineNo);
  if (ch === '*') fail(`aliases (\`*\`) are not supported${where}`, lineNo);
  if (ch === '!') fail(`tags (\`!\`) are not supported${where}`, lineNo);
  if (ch === '?' && (text.length === 1 || text[1] === ' ')) {
    fail(`explicit keys (\`? \`) are not supported${where}`, lineNo);
  }
  if (ch === '@' || ch === '`') fail(`reserved indicator \`${ch}\`${where}`, lineNo);
}

/** Net `[`/`{` bracket depth of `text`, ignoring brackets inside quotes. */
function flowDepth(text, lineNo) {
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "'" || ch === '"') {
      const { end } = parseQuoted(text, i, lineNo);
      i = end - 1;
    } else if (ch === '[' || ch === '{') depth++;
    else if (ch === ']' || ch === '}') depth--;
  }
  return depth;
}

/** Recursive-descent parser for flow collections (`[...]` / `{...}`). */
class FlowParser {
  constructor(text, lineNo) {
    this.text = text;
    this.lineNo = lineNo;
    this.pos = 0;
  }

  skipSpaces() {
    while (this.pos < this.text.length && (this.text[this.pos] === ' ' || this.text[this.pos] === '\t')) this.pos++;
  }

  parseValue() {
    this.skipSpaces();
    const ch = this.text[this.pos];
    if (ch === undefined) fail('unexpected end of flow collection', this.lineNo);
    if (ch === '[') return this.parseSequence();
    if (ch === '{') return this.parseMapping();
    if (ch === "'" || ch === '"') {
      const { value, end } = parseQuoted(this.text, this.pos, this.lineNo);
      this.pos = end;
      return value;
    }
    rejectNodeProperties(this.text.slice(this.pos), this.lineNo, ' in flow collections');
    return this.parsePlain();
  }

  /** Plain scalar in flow context: ends at `,`, `]`, `}` or a `: ` key marker. */
  parsePlain() {
    const start = this.pos;
    while (this.pos < this.text.length) {
      const ch = this.text[this.pos];
      if (ch === ',' || ch === ']' || ch === '}') break;
      if (ch === ':') {
        const next = this.text[this.pos + 1];
        if (next === undefined || next === ' ' || next === '\t' || next === ',' || next === ']' || next === '}') break;
      }
      this.pos++;
    }
    const raw = this.text.slice(start, this.pos).trim();
    if (raw === '' && this.text[this.pos] !== ':') fail('empty plain scalar in flow collection', this.lineNo);
    return resolvePlainScalar(raw, this.lineNo);
  }

  parseSequence() {
    this.pos++; // [
    const items = [];
    this.skipSpaces();
    if (this.text[this.pos] === ']') {
      this.pos++;
      return items;
    }
    for (;;) {
      items.push(this.parseEntryValue());
      this.skipSpaces();
      const ch = this.text[this.pos];
      if (ch === ',') {
        this.pos++;
        this.skipSpaces();
        if (this.text[this.pos] === ']') {
          this.pos++;
          return items;
        }
        continue;
      }
      if (ch === ']') {
        this.pos++;
        return items;
      }
      fail('expected `,` or `]` in flow sequence', this.lineNo);
    }
  }

  /** A sequence entry may itself be a single `key: value` pair (a one-pair map). */
  parseEntryValue() {
    const value = this.parseValue();
    this.skipSpaces();
    if (this.text[this.pos] === ':' && typeof value === 'string') {
      this.pos++;
      const inner = this.parseValue();
      return { [value]: inner };
    }
    return value;
  }

  parseMapping() {
    this.pos++; // {
    const result = {};
    this.skipSpaces();
    if (this.text[this.pos] === '}') {
      this.pos++;
      return result;
    }
    for (;;) {
      this.skipSpaces();
      const keyValue = this.parseValue();
      const key = typeof keyValue === 'string' ? keyValue : String(keyValue);
      this.skipSpaces();
      let value = null;
      if (this.text[this.pos] === ':') {
        this.pos++;
        this.skipSpaces();
        const ch = this.text[this.pos];
        value = ch === ',' || ch === '}' ? null : this.parseValue();
      }
      if (Object.prototype.hasOwnProperty.call(result, key)) fail(`duplicate mapping key \`${key}\``, this.lineNo);
      result[key] = value;
      this.skipSpaces();
      const ch = this.text[this.pos];
      if (ch === ',') {
        this.pos++;
        this.skipSpaces();
        if (this.text[this.pos] === '}') {
          this.pos++;
          return result;
        }
        continue;
      }
      if (ch === '}') {
        this.pos++;
        return result;
      }
      fail('expected `,` or `}` in flow mapping', this.lineNo);
    }
  }
}

/** Block-structure parser over one document's worth of lines. */
class BlockParser {
  /** @param {Array<{ text: string, lineNo: number }>} lines */
  constructor(lines) {
    this.lines = lines;
    this.index = 0;
  }

  peek() {
    return this.lines[this.index] ?? null;
  }

  /** Skips lines that are blank once comments are stripped. */
  skipBlank() {
    while (this.index < this.lines.length) {
      const { text } = this.lines[this.index];
      if (stripComment(text).trim() !== '') return;
      this.index++;
    }
  }

  /** Parses the next node at `minIndent` or deeper; `null` when there is none. */
  parseNode(minIndent) {
    this.skipBlank();
    const line = this.peek();
    if (!line) return null;
    const indent = indentOf(line.text, line.lineNo);
    if (indent < minIndent) return null;

    const content = stripComment(line.text).slice(indent);
    if (content === '-' || content.startsWith('- ')) return this.parseSequence(indent);
    rejectNodeProperties(content, line.lineNo, '');
    const key = this.findKey(content, line.lineNo);
    if (key) return this.parseMapping(indent);
    return this.parseScalarLine(indent, line);
  }

  /**
   * Locates the `key:` marker of a block-mapping line: an unquoted `:` at
   * flow depth zero followed by space or end of content. Returns
   * `{ key, rest }` or `null` when the line is not a mapping entry.
   */
  findKey(content, lineNo) {
    let keyEnd = -1;
    if (content[0] === "'" || content[0] === '"') {
      const { value, end } = parseQuoted(content, 0, lineNo);
      const after = content.slice(end).trimStart();
      if (!after.startsWith(':')) return null;
      const rest = after.slice(1);
      if (rest !== '' && rest[0] !== ' ') return null;
      return { key: value, rest: rest.trimStart() };
    }
    let depth = 0;
    for (let i = 0; i < content.length; i++) {
      const ch = content[i];
      if (ch === "'" || ch === '"') {
        const { end } = parseQuoted(content, i, lineNo);
        i = end - 1;
        continue;
      }
      if (ch === '[' || ch === '{') depth++;
      else if (ch === ']' || ch === '}') depth--;
      else if (ch === ':' && depth === 0) {
        const next = content[i + 1];
        if (next === undefined || next === ' ') {
          keyEnd = i;
          break;
        }
      }
    }
    if (keyEnd === -1) return null;
    const keyText = content.slice(0, keyEnd).trim();
    if (keyText === '') fail('empty mapping key', lineNo);
    return { key: keyText, rest: content.slice(keyEnd + 1).trimStart() };
  }

  parseMapping(indent) {
    const result = {};
    for (;;) {
      this.skipBlank();
      const line = this.peek();
      if (!line) break;
      const lineIndent = indentOf(line.text, line.lineNo);
      if (lineIndent < indent) break;
      if (lineIndent > indent) {
        fail(
          'bad indentation of a mapping entry (multi-line plain scalars are not supported — use a block scalar)',
          line.lineNo,
        );
      }
      const content = stripComment(line.text).slice(indent);
      if (content === '-' || content.startsWith('- ')) {
        fail('unexpected sequence item inside a mapping', line.lineNo);
      }
      rejectNodeProperties(content, line.lineNo, '');
      const found = this.findKey(content, line.lineNo);
      if (!found) fail('expected a `key:` mapping entry', line.lineNo);
      if (Object.prototype.hasOwnProperty.call(result, found.key)) {
        fail(`duplicate mapping key \`${found.key}\``, line.lineNo);
      }
      result[found.key] = this.parseValueAfterKey(found.rest, indent, line);
    }
    return result;
  }

  parseValueAfterKey(rest, keyIndent, keyLine) {
    if (rest === '') {
      this.index++;
      this.skipBlank();
      const next = this.peek();
      if (!next) return null;
      const nextIndent = indentOf(next.text, next.lineNo);
      if (nextIndent > keyIndent) return this.parseNode(keyIndent + 1);
      if (nextIndent === keyIndent) {
        const content = stripComment(next.text).slice(nextIndent);
        // A block sequence may sit at the same indent as its key.
        if (content === '-' || content.startsWith('- ')) return this.parseSequence(nextIndent);
      }
      return null;
    }
    if (rest[0] === '|' || rest[0] === '>') return this.parseBlockScalar(rest, keyIndent, keyLine.lineNo);
    rejectNodeProperties(rest, keyLine.lineNo, '');
    if (rest[0] === '[' || rest[0] === '{') return this.parseFlowValue(rest, keyLine);
    return this.parseInlineScalar(rest, keyLine.lineNo);
  }

  /** Single-line plain or quoted scalar used as a mapping/sequence value. */
  parseInlineScalar(rest, lineNo) {
    this.index++;
    if (rest[0] === "'" || rest[0] === '"') {
      const { value, end } = parseQuoted(rest, 0, lineNo);
      if (rest.slice(end).trim() !== '') fail('unexpected content after a quoted scalar', lineNo);
      return value;
    }
    return resolvePlainScalar(rest, lineNo);
  }

  /** Root-level (or nested-block) scalar occupying its own line. */
  parseScalarLine(indent, line) {
    const content = stripComment(line.text).slice(indent);
    if (content[0] === '|' || content[0] === '>') {
      fail('a block scalar is only supported as a mapping value in this subset', line.lineNo);
    }
    const value =
      content[0] === '[' || content[0] === '{'
        ? this.parseFlowValue(content, line)
        : this.parseInlineScalar(content, line.lineNo);
    // A following line at the same or deeper indent would make this a
    // multi-line plain scalar, which the subset rejects rather than folds.
    this.skipBlank();
    const next = this.peek();
    if (next && indentOf(next.text, next.lineNo) >= indent) {
      fail('multi-line plain scalars are not supported — use a block scalar (`|` or `>`)', next.lineNo);
    }
    return value;
  }

  /** A flow collection value; pulls continuation lines while brackets are open. */
  parseFlowValue(first, startLine) {
    let text = first;
    this.index++;
    while (flowDepth(text, startLine.lineNo) > 0) {
      const next = this.peek();
      if (!next) fail('unterminated flow collection', startLine.lineNo);
      text += ` ${stripComment(next.text).trim()}`;
      this.index++;
    }
    const parser = new FlowParser(text, startLine.lineNo);
    const value = parser.parseValue();
    parser.skipSpaces();
    if (parser.pos !== text.length) fail('unexpected content after a flow collection', startLine.lineNo);
    return value;
  }

  parseSequence(indent) {
    const items = [];
    for (;;) {
      this.skipBlank();
      const line = this.peek();
      if (!line) break;
      const lineIndent = indentOf(line.text, line.lineNo);
      if (lineIndent !== indent) break;
      const content = stripComment(line.text).slice(indent);
      if (content !== '-' && !content.startsWith('- ')) break;

      if (content === '-') {
        this.index++;
        items.push(this.parseNode(indent + 1));
        continue;
      }
      // Re-anchor the rest of the line at its own column so `- key: value`
      // (and any continuation keys aligned underneath) parse as one nested
      // node. Uses the RAW line so comment stripping happens exactly once,
      // in the nested parse.
      const raw = line.text;
      let restStart = indent + 1;
      while (raw[restStart] === ' ') restStart++;
      this.lines[this.index] = { text: `${' '.repeat(restStart)}${raw.slice(restStart)}`, lineNo: line.lineNo };
      items.push(this.parseNode(restStart));
    }
    return items;
  }

  parseBlockScalar(header, keyIndent, headerLineNo) {
    const style = header[0];
    let chomp = '';
    let explicit = 0;
    let i = 1;
    for (; i < header.length; i++) {
      const ch = header[i];
      if ((ch === '-' || ch === '+') && chomp === '') chomp = ch;
      else if (/[1-9]/.test(ch) && explicit === 0) explicit = Number(ch);
      else break;
    }
    if (header.slice(i).trim() !== '') fail('unexpected content after a block scalar header', headerLineNo);

    this.index++;
    const consumed = [];
    while (this.index < this.lines.length) {
      const line = this.lines[this.index];
      const blank = line.text.trim() === '';
      if (!blank && indentOf(line.text, line.lineNo) <= keyIndent) break;
      consumed.push(line);
      this.index++;
    }

    let contentIndent = explicit > 0 ? keyIndent + explicit : -1;
    if (contentIndent === -1) {
      for (const line of consumed) {
        if (line.text.trim() !== '') {
          contentIndent = indentOf(line.text, line.lineNo);
          break;
        }
      }
    }
    if (contentIndent === -1) {
      // Only blank lines: empty scalar ('' for strip/clip; newlines for keep).
      return chomp === '+' ? '\n'.repeat(consumed.length) : '';
    }

    const contentLines = consumed.map((line) => {
      if (line.text.trim() === '') return line.text.length > contentIndent ? line.text.slice(contentIndent) : '';
      if (indentOf(line.text, line.lineNo) < contentIndent) {
        fail('block scalar line is less indented than the detected content indent', line.lineNo);
      }
      return line.text.slice(contentIndent);
    });

    const body = style === '|' ? contentLines.join('\n') : foldLines(contentLines);
    // Chomping: `+` keeps every trailing newline (each trailing blank line
    // contributed one to `body`, plus the final line break), `-` strips them
    // all, the default clips to exactly one.
    if (chomp === '+') return `${body}\n`;
    const trimmed = body.replace(/\n+$/, '');
    if (chomp === '-') return trimmed;
    return trimmed === '' ? '' : `${trimmed}\n`;
  }
}

/**
 * Folded (`>`) scalar semantics, verified differentially against the
 * reference `yaml` package: a lone break between two base-indent text lines
 * becomes a space; a group of k blank lines contributes k newlines; breaks
 * adjacent to a more-indented line are literal (so a blank group touching an
 * indented line keeps one extra newline per indented side).
 */
function foldLines(lines) {
  const isIndented = (line) => line !== '' && (line[0] === ' ' || line[0] === '\t');
  let out = '';
  let i = 0;

  let lead = 0;
  while (i < lines.length && lines[i] === '') {
    lead++;
    i++;
  }
  if (i === lines.length) return '\n'.repeat(lead);
  out += '\n'.repeat(lead + (lead > 0 && isIndented(lines[i]) ? 1 : 0));

  while (i < lines.length) {
    const line = lines[i];
    out += line;
    i++;
    let blanks = 0;
    while (i < lines.length && lines[i] === '') {
      blanks++;
      i++;
    }
    if (i === lines.length) {
      // Trailing blank group: the final line break is chomping's business.
      out += '\n'.repeat(blanks);
      break;
    }
    const next = lines[i];
    if (blanks === 0) out += !isIndented(line) && !isIndented(next) ? ' ' : '\n';
    else out += '\n'.repeat(blanks + (isIndented(line) ? 1 : 0) + (isIndented(next) ? 1 : 0));
  }
  return out;
}

/**
 * Parses a YAML stream into an array of documents (one per `---` section).
 * Documents that contain only comments/blank lines are omitted.
 *
 * @param {string} text
 * @returns {unknown[]}
 */
function parseYamlDocuments(text) {
  if (typeof text !== 'string') throw new KerberosImportError('YAML input must be a string');
  const rawLines = text.split(/\r\n|\r|\n/);
  // A trailing newline terminates the last line — it is not an extra blank
  // line (which would change `|+` / `>+` keep-chomping).
  if (rawLines[rawLines.length - 1] === '') rawLines.pop();

  /** @type {Array<Array<{ text: string, lineNo: number }>>} */
  const documents = [[]];
  for (let i = 0; i < rawLines.length; i++) {
    const lineNo = i + 1;
    const raw = rawLines[i];
    const trimmed = raw.trimEnd();
    if (trimmed[0] === '%') fail('YAML directives (`%`) are not supported', lineNo);
    if (trimmed === '---' || trimmed.startsWith('--- ') || trimmed.startsWith('---\t')) {
      const rest = stripComment(trimmed.slice(3)).trim();
      if (rest !== '') fail('content on the `---` document marker line is not supported', lineNo);
      documents.push([]);
      continue;
    }
    if (trimmed === '...') {
      documents.push([]);
      continue;
    }
    documents[documents.length - 1].push({ text: raw, lineNo });
  }

  const result = [];
  for (const docLines of documents) {
    const parser = new BlockParser(docLines);
    parser.skipBlank();
    if (!parser.peek()) continue; // empty document
    const value = parser.parseNode(0);
    parser.skipBlank();
    const leftover = parser.peek();
    if (leftover) fail('unexpected content after the document root node', leftover.lineNo);
    result.push(value);
  }
  return result;
}

module.exports = { parseYamlDocuments };
