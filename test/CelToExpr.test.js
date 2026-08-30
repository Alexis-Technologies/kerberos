const { describe, it } = require('node:test');
const { strict: assert } = require('node:assert');

const jsep = require('jsep');
jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));
jsep.addUnaryOp('typeof');

const { createSafeExprCodec } = require('../index.js');
const { celToExpr } = require('../src/cerbos/translate.js');
const { parseGoDuration } = require('../src/cerbos/translate.js');
const { KerberosImportError } = require('../src/cerbos/errors.js');

const codec = createSafeExprCodec({ jsep });

// Every translation is verified SEMANTICALLY: the emitted string is compiled
// by the real codec (with the documented jsep setup) and evaluated against a
// context, so a mistranslation cannot pass on string-shape luck alone.

const ctx = {
  P: { id: 'u1', roles: ['USER'], attr: { level: 3, override: false, teams: ['a', 'b'] } },
  R: {
    kind: 'doc',
    id: 'd1',
    attr: {
      owner: 'u1',
      status: 'OPEN',
      tags: ['x'],
      name: 'doc-7',
      title: 'top secret',
      n: 5,
      createdAt: '2020-01-01T00:00:00Z',
      a: '2024-05-05T00:00:00Z',
      b: '2024-05-05T00:00:00Z',
      s: 'AbC',
      nl: 'a\nb',
      assignees: ['u1', 'u2'],
      role: 'admin',
      locked: true,
    },
  },
  V: { isOwner: true },
  C: { limit: 10 },
};

describe('celToExpr — semantic translation', () => {
  const cases = [
    // Longhand and shorthand roots
    ['request.resource.attr.owner == request.principal.id', true],
    ['R.attr.owner == P.id', true],
    ['V.isOwner && variables.isOwner', true],
    ['constants.limit == C.limit', true],
    ['request.principal.id == "u1"', true],
    // Membership
    ['R.attr.status in ["OPEN", "NEW"]', true],
    ['R.attr.status in ["CLOSED"]', false],
    ['P.id in R.attr.assignees', true],
    // has()
    ['has(R.attr.owner)', true],
    ['has(R.attr.missing)', false],
    ['!has(R.attr.missing) || R.attr.missing > 5', true],
    // size()
    ['size(R.attr.tags) > 0', true],
    ['size("abc") == 3', true],
    ['R.attr.tags.size() == 1', true],
    // String methods
    ['R.attr.name.startsWith("doc-")', true],
    ['R.attr.title.endsWith("secret")', true],
    ['R.attr.title.contains("secret")', true],
    ['R.attr.s.lowerAscii() == "abc"', true],
    ['R.attr.s.upperAscii() == "ABC"', true],
    ['"  pad  ".trim() == "pad"', true],
    ['"a-b-c".replace("-", "_") == "a_b_c"', true],
    ['"a b c".split(" ")[1] == "b"', true],
    ['["x", "y"].join(",") == "x,y"', true],
    ['P.attr.teams.join() == "ab"', true],
    ['"abc".charAt(1) == "b"', true],
    ['"abcabc".indexOf("b") == 1', true],
    ['"abcabc".lastIndexOf("b") == 4', true],
    ['"abcdef".substring(1, 3) == "bc"', true],
    // Ternary, boolean and comparison operators
    ['R.attr.n > 3 ? "big" : "small"', 'big'],
    ['R.attr.role == "admin" && (P.attr.level >= 3 || P.attr.override == true)', true],
    ['!(R.attr.n > 3 && false)', true],
    ['R.attr.status != "CLOSED"', true],
    ['R.attr.n in [1, 2, 3] ? 1 : 2', 2],
    // Arithmetic and precedence
    ['(1 + 2) * 3 == 9', true],
    ['1 - (2 - 3) == 2', true],
    ['-2 + 3 == 1', true],
    ['7 / 2 == 3', true], // CEL integer division of int literals truncates
    ['7.0 / 2.0 == 3.5', true],
    ['10 % 3 == 1', true],
    // Timestamps (epoch-ms number encoding) and durations
    ['timestamp(R.attr.createdAt) < now()', true],
    ['now() - timestamp(R.attr.createdAt) < duration("36h")', false],
    ['now() - timestamp(R.attr.createdAt) > duration("36h")', true],
    ['timestamp(R.attr.a) == timestamp(R.attr.b)', true],
    ['duration("1h30m") == 5400000', true],
    ['duration("300s") == 300000', true],
    ['timestamp(R.attr.a).getFullYear() == 2024', true],
    ['timestamp(R.attr.a).getMonth() == 4', true], // both zero-based
    ['timestamp(R.attr.a).getDate() == 5', true], // both one-based
    ['timestamp(R.attr.a).getDayOfMonth() == 4', true], // CEL zero-based
    ['timestamp("2024-05-05T00:00:00Z").getDayOfWeek() == 0', true], // a Sunday
    ['timestamp("2024-05-05T06:07:08Z").getHours() == 6', true],
    ['(now() - timestamp(R.attr.createdAt)).getHours() > 24', true],
    ['duration("90m").getHours() == 1', true],
    ['duration("90m").getMinutes() == 90', true],
    ['int(timestamp("1970-01-01T00:01:00Z")) == 60', true], // epoch seconds
    ['string(timestamp(R.attr.a)) == "2024-05-05T00:00:00.000Z"', true],
    // Conversions
    ['int("42") == 42', true],
    ['int(3.9) == 3', true],
    ['uint("42") == 42', true],
    ['double("3.5") == 3.5', true],
    ['string(42) == "42"', true],
    ['dyn(5) == 5', true],
    // Literals
    ['0x1F == 31', true],
    ['42u == 42', true],
    ['.5 < 1.0', true],
    ['1e3 == 1000.0', true],
    ["\"it's\" == 'it\\'s'", true],
    ['R.attr.nl == "a\\nb"', true],
    ['r"a\\nb" != "a\\nb"', true], // raw string keeps the backslash
    ['"""triple "quoted" string""".contains("quoted")', true],
    ['{"a": 1}["a"] == 1', true],
    ['[1, 2, 3][1] == 2', true],
    ['null == null', true],
    ['true && !false', true],
    // Index access
    ['R.attr.assignees[0] == "u1"', true],
    // Comments
    ['R.attr.n > 3 // trailing comment', true],
  ];

  for (const [cel, expected] of cases) {
    it(cel, () => {
      const js = celToExpr(cel);
      assert.equal(codec.compileExpr(js)(ctx), expected, `translated to: ${js}`);
    });
  }

  it('emits stable, readable output for the common idioms', () => {
    assert.equal(celToExpr('request.resource.attr.owner == request.principal.id'), 'R.attr.owner === P.id');
    assert.equal(celToExpr('R.attr.status in ["OPEN", "NEW"]'), '["OPEN", "NEW"].includes(R.attr.status)');
    assert.equal(celToExpr('has(R.attr.owner)'), 'typeof R.attr.owner !== "undefined"');
    assert.equal(celToExpr('size(R.attr.tags) > 0'), 'R.attr.tags.length > 0');
    assert.equal(celToExpr('timestamp(R.attr.t) < now()'), 'Date.parse(R.attr.t) < Date.now()');
    assert.equal(celToExpr('variables.isOwner'), 'V.isOwner');
  });
});

describe('celToExpr — rejected constructs', () => {
  const rejected = [
    ['comprehension macro exists', 'R.attr.tags.exists(t, t == "a")'],
    ['comprehension macro all', 'R.attr.tags.all(t, t != "")'],
    ['comprehension macro filter', 'R.attr.tags.filter(t, t != "")'],
    ['comprehension macro map', 'R.attr.tags.map(t, t)'],
    ['comprehension macro exists_one', 'R.attr.tags.exists_one(t, t == "a")'],
    ['regular expressions', 'R.attr.name.matches("^doc")'],
    ['Cerbos extension hasIntersection', 'hasIntersection(P.attr.teams, R.attr.tags)'],
    ['Cerbos extension hierarchy', 'hierarchy(R.attr.scope).siblingOf(hierarchy("a.b"))'],
    ['Cerbos extension spiffeID', 'spiffeID("spiffe://x").isMemberOf(spiffeMatchExact(spiffeID("spiffe://x")))'],
    ['globals', 'globals.environment == "prod"'],
    ['globals shorthand', 'G.environment == "prod"'],
    ['runtime', 'runtime.effectiveDerivedRoles'],
    ['auxData', 'request.auxData.jwt.iss == "issuer"'],
    ['bare request', 'request == request'],
    ['unknown identifier', 'x.y == 1'],
    ['unknown function', 'frobnicate(1)'],
    ['unknown method', 'R.attr.tags.frobnicate()'],
    ['bytes literals', 'b"bytes" == b"bytes"'],
    ['message construction', 'google.protobuf.Timestamp{seconds: 1}'],
    ['reserved words', 'while == 1'],
    ['leading-dot names', '.absolute.name == 1'],
    ['non-literal duration', 'duration(R.attr.d) < 100'],
    ['invalid duration literal', 'duration("not-a-duration") < 100'],
    ['list concatenation', '[1] + [2] == [1, 2]'],
    ['blocked field access', 'R.attr.x.__proto__ == 1'],
    ['blocked constructor access', 'R.attr.x.constructor == 1'],
    ['time-zone accessor arguments', 'timestamp(R.attr.a).getFullYear("Europe/Kyiv") == 2024'],
    ['getDayOfYear', 'timestamp(R.attr.a).getDayOfYear() == 1'],
    ['bool conversion', 'bool("true")'],
    ['type()', 'type(R.attr.n) == type(1)'],
    ['non-string map keys', '{1: "a"}[1] == "a"'],
    ['replace with a limit', '"aaa".replace("a", "b", 1) == "baa"'],
    ['split with a limit', '"a b c".split(" ", 2)'],
    ['has() of a non-selection', 'has(P.id == "u1")'],
    ['unsafe integer literals', '9007199254740993 == 9007199254740993'],
    ['empty expression', '   '],
    ['unterminated string', '"abc'],
    ['trailing content', 'R.attr.n > 3 R.attr.n'],
  ];

  for (const [label, cel] of rejected) {
    it(`rejects ${label}`, () => {
      assert.throws(() => celToExpr(cel), KerberosImportError, `for: ${cel}`);
    });
  }
});

describe('parseGoDuration', () => {
  const cases = [
    ['300s', 300000],
    ['1h30m', 5400000],
    ['72h3m0.5s', 259380500],
    ['-15m', -900000],
    ['1.5h', 5400000],
    ['250ms', 250],
    ['1000us', 1],
    ['1000000ns', 1],
  ];
  for (const [text, ms] of cases) {
    it(`${text} = ${ms}ms`, () => {
      assert.equal(parseGoDuration(text, text), ms);
    });
  }
});
