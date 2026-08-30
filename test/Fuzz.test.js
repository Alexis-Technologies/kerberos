const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const jsep = require('jsep');
jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));
jsep.addUnaryOp('typeof');

const { createSafeExprCodec, KerberosExprError } = require('../index.js');
const { parseYamlDocuments } = require('../src/cerbos/yaml.js');
const { celToExpr } = require('../src/cerbos/translate.js');
const { KerberosImportError } = require('../src/cerbos/errors.js');
const { RelationResolver } = require('../relations.js');

// Deterministic fuzzing: a seeded PRNG mutates known-good inputs and feeds
// the results to the security-sensitive surfaces. The properties asserted are
// the CONTRACTS, not exact outputs:
//
// - the `$expr` codec only ever throws its typed error at parse time, never
//   leaks functions from evaluation, and never pollutes Object.prototype;
// - every expression celToExpr EMITS must compile under the documented jsep
//   setup (the translator's output contract);
// - the YAML parser and CEL parser throw KerberosImportError — nothing else —
//   on arbitrary garbage;
// - RelationResolver construction/checks throw typed errors only.
//
// Iterations are bounded so `pnpm test` stays fast; crank them with
// FUZZ_ITERATIONS=100000 for a deep run.

const ITERATIONS = Number(process.env.FUZZ_ITERATIONS ?? 400);

/** mulberry32 — tiny deterministic PRNG. */
function createRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick(random, items) {
  return items[Math.floor(random() * items.length)];
}

const NASTY_TOKENS = [
  '__proto__',
  'constructor',
  'prototype',
  'toString',
  'valueOf',
  '`',
  '${',
  '\u0000',
  '"',
  "'",
  '(',
  ')',
  '[',
  ']',
  '{',
  '}',
  '.',
  ',',
  '=>',
  ';',
  '=',
  '++',
  '/*',
  '*/',
  '//',
  ' in ',
  'new ',
  'typeof ',
  'eval',
  'Function',
  'require',
  'process',
  'globalThis',
  '?.',
  '!',
  '?',
  ':',
  '\n',
  '\t',
  '\u2028',
];

function mutate(random, source, rounds) {
  let text = source;
  for (let i = 0; i < rounds; i++) {
    const op = Math.floor(random() * 3);
    const at = Math.floor(random() * (text.length + 1));
    if (op === 0 && text.length > 1) {
      text = text.slice(0, at) + text.slice(at + 1 + Math.floor(random() * 3)); // delete
    } else if (op === 1) {
      text = text.slice(0, at) + pick(random, NASTY_TOKENS) + text.slice(at); // insert
    } else {
      const from = Math.floor(random() * text.length);
      text = text.slice(0, at) + text[from] + text.slice(at); // duplicate a char
    }
  }
  return text;
}

describe('fuzz — $expr codec', () => {
  const codec = createSafeExprCodec({ jsep });
  const ctx = {
    P: { id: 'u1', roles: ['USER'], attr: { level: 3, teams: ['a', 'b'], name: 'x' } },
    R: { kind: 'doc', id: 'd1', attr: { owner: 'u1', n: 5, tags: ['x'], s: 'AbC', t: '2024-01-01T00:00:00Z' } },
    V: { isOwner: true },
    C: { limit: 10 },
  };
  const seeds = [
    'R.attr.owner === P.id',
    '["a", "b"].includes(R.attr.s) || R.attr.n > 3 ? 1 : 2',
    'typeof R.attr.x !== "undefined" && !(P.attr.level >= 3)',
    'Date.parse(R.attr.t) < Date.now() - 3600000',
    'Math.max(R.attr.n, C.limit) + P.attr.teams.join(",").length',
    '{ "k": R.attr.n }["k"] % 3 === 2',
    'new Date(R.attr.t).getUTCFullYear() === 2024',
    'P.attr.name.toUpperCase().startsWith("X") ? R.attr.tags[0] : null',
  ];

  it(`${ITERATIONS} mutated expressions: typed parse errors, no leaked functions, no pollution`, () => {
    const random = createRandom(0xc0ffee);
    let compiled = 0;
    for (let i = 0; i < ITERATIONS; i++) {
      const source = mutate(random, pick(random, seeds), 1 + Math.floor(random() * 6));
      let fn = null;
      try {
        fn = codec.compileExpr(source);
      } catch (error) {
        assert.equal(error instanceof KerberosExprError, true, `${source} → ${error.name}: ${error.message}`);
      }
      if (fn) {
        compiled++;
        try {
          const result = fn(ctx);
          assert.notEqual(typeof result, 'function', `evaluation leaked a function for: ${source}`);
        } catch (error) {
          // Runtime evaluation may fail on the request data (member access on
          // undefined and friends) — but only through expected error types.
          assert.equal(
            error instanceof KerberosExprError || error instanceof TypeError || error instanceof RangeError,
            true,
            `${source} → ${error.name}: ${error.message}`,
          );
        }
      }
    }
    // Prototype pollution check: nothing above may have touched the globals.
    assert.equal(Object.keys(Object.prototype).length, 0);
    assert.equal({}.polluted, undefined);
    assert.equal(Object.prototype.constructor, Object);
    assert.ok(compiled > 0, 'the mutator never produced a compilable expression — seeds/mutations are broken');
  });

  it('malformed NewExpression nodes from @jsep-plugin/new throw the typed error (fuzz regression)', () => {
    // `new R.attr.x` makes the plugin emit { type: 'NewExpression', name }
    // with NO callee — the codec must reject it as KerberosExprError, not
    // crash with a raw TypeError.
    for (const source of ['new R.attr.owner === P.id', 'new R === 1', 'typeof new P.id']) {
      assert.throws(() => codec.compileExpr(source), KerberosExprError, source);
    }
  });

  it('blocked-key spellings never reach the prototype chain', () => {
    const spellings = [
      'R.attr["__proto__"]',
      'R.attr["__pro" + "to__"]',
      'R.attr[["__proto__"][0]]',
      'P["constructor"]',
      'P.constructor',
      'R.attr.x.prototype',
      '({})["__proto__"]',
    ];
    for (const source of spellings) {
      assert.throws(
        () => codec.compileExpr(source)(ctx),
        KerberosExprError,
        `${source} should be blocked at parse or evaluation`,
      );
    }
  });
});

describe('fuzz — CEL translator', () => {
  const codec = createSafeExprCodec({ jsep });
  const seeds = [
    'request.resource.attr.owner == request.principal.id',
    'R.attr.status in ["OPEN", "NEW"] && has(R.attr.owner)',
    'size(R.attr.tags) > 0 ? "big" : "small"',
    'timestamp(R.attr.t) < now() - duration("36h")',
    'P.attr.teams.join(",").startsWith("a") || V.isOwner',
    '"a-b".replace("-", "_") == "a_b" && 7 / 2 == 3',
  ];

  it(`${ITERATIONS} mutated CEL sources: typed errors only, and emitted output always compiles`, () => {
    const random = createRandom(0xdecade);
    let translated = 0;
    for (let i = 0; i < ITERATIONS; i++) {
      const source = mutate(random, pick(random, seeds), 1 + Math.floor(random() * 6));
      let output = null;
      try {
        output = celToExpr(source);
      } catch (error) {
        assert.equal(error instanceof KerberosImportError, true, `${source} → ${error.name}: ${error.message}`);
      }
      if (output !== null) {
        translated++;
        // The translator's output contract: whatever it emits must be a valid
        // $expr for the documented jsep setup.
        try {
          codec.compileExpr(output);
        } catch (error) {
          assert.fail(
            `translator emitted an uncompilable expression\n  cel: ${source}\n  out: ${output}\n  ${error.message}`,
          );
        }
      }
    }
    assert.ok(translated > 0, 'the mutator never produced a translatable expression');
  });
});

describe('fuzz — YAML subset parser', () => {
  const corpus = [];
  for (const dir of ['conformance/policies', 'conformance/suites']) {
    const absolute = path.join(__dirname, '..', dir);
    for (const file of fs.readdirSync(absolute).slice(0, 6)) {
      if (/\.ya?ml$/.test(file)) corpus.push(fs.readFileSync(path.join(absolute, file), 'utf8'));
    }
  }

  it(`${ITERATIONS} mutated documents: parses or throws KerberosImportError, nothing else`, () => {
    const random = createRandom(0xfeed);
    for (let i = 0; i < ITERATIONS; i++) {
      const source = mutate(random, pick(random, corpus), 1 + Math.floor(random() * 8));
      try {
        parseYamlDocuments(source);
      } catch (error) {
        assert.equal(error instanceof KerberosImportError, true, `${error.name}: ${error.message}`);
      }
    }
  });
});

describe('fuzz — RelationResolver', () => {
  const schema = {
    definitions: {
      user: {},
      group: { relations: { member: ['user', 'group#member'] } },
      doc: {
        relations: { owner: ['user'], parent: ['group'] },
        permissions: {
          view: { anyOf: ['owner', { via: 'parent', permission: 'member' }] },
        },
      },
    },
  };

  it(`${Math.min(ITERATIONS, 200)} random tuple sets: checks resolve or throw typed errors`, async () => {
    const random = createRandom(0xbeef);
    const relations = ['member', 'owner', 'parent', 'view', 'bogus'];
    for (let i = 0; i < Math.min(ITERATIONS, 200); i++) {
      const tuples = [];
      for (let j = 0; j < Math.floor(random() * 6); j++) {
        tuples.push({
          resource: { type: pick(random, ['group', 'doc']), id: `r${Math.floor(random() * 3)}` },
          relation: pick(random, ['member', 'owner', 'parent']),
          subject:
            random() < 0.5
              ? { type: 'user', id: `u${Math.floor(random() * 3)}` }
              : {
                  type: 'group',
                  id: `r${Math.floor(random() * 3)}`,
                  relation: 'member',
                },
        });
      }
      let resolver = null;
      try {
        resolver = new RelationResolver({ schema, tuples });
      } catch (error) {
        // Random tuples may violate the schema — but only as typed errors.
        assert.match(String(error.name), /^Kerberos/, `${error.name}: ${error.message}`);
      }
      if (!resolver) continue;
      try {
        const result = await resolver.check({
          principal: { id: `u${Math.floor(random() * 3)}` },
          resource: { type: 'doc', id: `r${Math.floor(random() * 3)}` },
          relation: pick(random, relations),
        });
        assert.equal(typeof result.matched, 'boolean');
      } catch (error) {
        assert.match(String(error.name), /^Kerberos/, `${error.name}: ${error.message}`);
      }
    }
  });
});
