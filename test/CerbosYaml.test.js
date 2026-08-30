const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const YAML = require('yaml');

const { parseYamlDocuments } = require('../src/cerbos/yaml.js');
const { KerberosImportError } = require('../src/cerbos/errors.js');

// The subset parser is verified two ways: a differential sweep against the
// reference `yaml` package over the whole Cerbos conformance corpus (real
// policy documents), and table-driven unit cases for every supported and
// every rejected construct.

describe('parseYamlDocuments — differential against the reference parser', () => {
  for (const dir of ['conformance/policies', 'conformance/suites']) {
    const absolute = path.join(__dirname, '..', dir);
    for (const file of fs.readdirSync(absolute).sort()) {
      if (!/\.ya?ml$/.test(file)) continue;
      it(`${dir}/${file}`, () => {
        const text = fs.readFileSync(path.join(absolute, file), 'utf8');
        const reference = YAML.parseAllDocuments(text)
          .map((doc) => doc.toJS())
          .filter((doc) => doc !== null);
        assert.deepEqual(parseYamlDocuments(text), reference);
      });
    }
  }
});

describe('parseYamlDocuments — supported constructs', () => {
  const roundTrips = [
    ['scalar types', 'a: 1\nb: true\nc: null\nd: ~\ne: hello world\ng: 0x1F\nh: -3.5e2\nj: .5\nk: 3.25'],
    ['nested sequences and maps', 'seq:\n  - 1\n  - two\n  - - nested\n    - deep\n  - k: v\n    l: w'],
    ['sequence at key indent', 'seq:\n- same indent\n- item2'],
    ['flow collections', 'flow: [a, 1, [b, {c: d}], "e,f"]\nmap: {x: 1, y: [2, 3], z: }'],
    ['multi-line flow', 'multi: [a,\n  b,\n  c]'],
    ['literal block scalar', 'lit: |\n  line1\n  line2\n\n  line4\nafter: 1'],
    ['literal strip chomping', 'lit: |-\n  a\n  b\n\n\nafter: 1'],
    ['literal keep chomping', 'lit: |+\n  a\n\n\nafter: 1'],
    ['keep chomping at end of file', 'lit: |+\n  a\n\n'],
    ['folded block scalar', 'fold: >\n  one\n  two\n\n  three\nafter: 1'],
    ['folded expression (the Cerbos idiom)', 'expr: >-\n  request.resource.attr.owner ==\n  request.principal.id'],
    ['folded with indented lines', 'fold: >\n  a\n    ind1\n    ind2\n  b\nafter: 1'],
    ['folded blank next to indented', 'fold: >-\n  t1\n    i1\n\n  t2'],
    ['explicit block indent', 'lit: |2\n   a\n    b\nafter: 1'],
    ['empty flow collections', 'empty-map: {}\nempty-seq: []'],
    ['comments', 'k: v # comment\n# full line\nother: 1 # more'],
    ['hash inside quotes is content', 'hash: "a # not comment"\nplain: a#b'],
    ['multi-document stream', '---\ndoc1: 1\n---\ndoc2: 2\n...\n---\ndoc3: 3'],
    ['deep nesting', 'nested:\n  deep:\n    deeper:\n      - x: 1\n        y:\n          - 2'],
    ['colons in values', "colonval: 'a: b'\nurl: http://example.com/x"],
    ['single-quote escaping', "single: 'it''s'"],
    ['double-quote escapes', 'esc: "tab\\tnl\\nuni\\u0041end"'],
    ['quoted keys', '"quoted key": 1\nplain: 2'],
    ['blank line before nested block', 'blank-then:\n\n  inner: 1'],
    ['indicator characters inside quotes', 'amp: "&notanchor"\nstar: \'*notalias\''],
    ['empty sequence item', 'seq:\n  -\n  - b'],
    ['sequence of flow values', 'seq-of-flow:\n  - [1, 2]\n  - {a: b}'],
    ['dash inside plain scalar', 'dash-scalar: some - thing\ndashy: a-b'],
  ];

  for (const [label, text] of roundTrips) {
    it(label, () => {
      const reference = YAML.parseAllDocuments(text)
        .map((doc) => {
          if (doc.errors.length) throw doc.errors[0];
          return doc.toJS();
        })
        .filter((doc) => doc !== null);
      assert.deepEqual(parseYamlDocuments(text), reference);
    });
  }

  it('omits comment-only documents', () => {
    assert.deepEqual(parseYamlDocuments('---\n# just a comment\n---\na: 1'), [{ a: 1 }]);
  });

  it('parses an empty stream to no documents', () => {
    assert.deepEqual(parseYamlDocuments(''), []);
    assert.deepEqual(parseYamlDocuments('# only comments\n'), []);
  });
});

describe('parseYamlDocuments — rejected constructs', () => {
  const rejected = [
    ['anchors', 'a: &anchor 1'],
    ['aliases', 'a: *anchor'],
    ['tags', 'a: !!str 1'],
    ['directives', '%YAML 1.2\n---\na: 1'],
    ['explicit keys', '? complex\n: value'],
    ['multi-line plain scalars', 'a: one\n  two'],
    ['multi-line plain scalar at root', 'one\ntwo'],
    ['tab indentation', 'a:\n\tb: 1'],
    ['non-finite floats', 'a: .inf'],
    ['duplicate keys', 'a: 1\na: 2'],
    ['duplicate flow keys', 'a: {x: 1, x: 2}'],
    ['unterminated quoted string', 'a: "unterminated'],
    ['unterminated flow collection', 'a: [1, 2'],
    ['content on the --- marker line', '--- inline'],
    ['content after a quoted scalar', 'a: "x" y'],
    ['content after a flow collection', 'a: [1] b'],
    ['bad mapping indentation', 'a: 1\n  b: 2'],
  ];

  for (const [label, text] of rejected) {
    it(`rejects ${label}`, () => {
      assert.throws(() => parseYamlDocuments(text), KerberosImportError);
    });
  }

  it('rejects non-string input', () => {
    assert.throws(() => parseYamlDocuments(42), KerberosImportError);
  });

  it('carries the offending line number', () => {
    try {
      parseYamlDocuments('fine: 1\nbad: &anchor 2');
      assert.fail('expected a throw');
    } catch (error) {
      assert.equal(error.name, 'KerberosImportError');
      assert.equal(error.line, 2);
      assert.match(error.message, /line 2/);
    }
  });
});
