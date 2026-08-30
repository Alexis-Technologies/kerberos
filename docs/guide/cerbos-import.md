# Importing Cerbos policies

The `@alexify/kerberos/cerbos` subpath turns an existing **Cerbos policy repository** — YAML/JSON policy documents with CEL conditions — into Kerberos policies you can evaluate in-process, with **zero dependencies**: it ships its own parser for the YAML subset Cerbos policies are written in and its own CEL parser + translator, so nothing new lands in your bundle beyond the subpath itself.

```js
import { importCerbosPolicies } from '@alexify/kerberos/cerbos';
import { Kerberos, createSafeExprCodec, deserializePolicy } from '@alexify/kerberos';
import jsep from 'jsep';
import jsepObject from '@jsep-plugin/object';
import jsepTernary from '@jsep-plugin/ternary';
import jsepNew from '@jsep-plugin/new';
import fs from 'node:fs';

// The importer emits SERIALIZED documents ({ $expr } conditions), so the
// standard dynamic-policy codec setup applies (see /guide/caching):
jsep.plugins.register(jsepObject, jsepTernary, jsepNew);
jsep.addUnaryOp('typeof');
const codec = createSafeExprCodec({ jsep });

const texts = fs.readdirSync('./policies').map((f) => fs.readFileSync(`./policies/${f}`, 'utf8'));
const { policies, derivedRoles } = importCerbosPolicies(texts);

const kerberos = new Kerberos(
  policies.map((doc) => deserializePolicy(doc, codec)),
  derivedRoles.map((doc) => deserializePolicy(doc, codec)),
);
```

Because the importer's output is plain JSON with `{ $expr }` descriptors, it is also exactly what the [dynamic-policy cache layer](/guide/caching) stores — you can import a Cerbos repo once and publish the results to Redis/keyv instead of constructing an engine directly.

## The governing invariant: refuse to guess

The importer never drops or approximates anything. Every Cerbos construct is either translated with faithful semantics or rejected with a `KerberosImportError` naming the construct and its location (`document.resourcePolicy.rules[2]: …`). A silently-skipped rule or a mistranslated condition would change authorization decisions without a trace — the importer treats that as the one unacceptable outcome.

The single, explicitly-opt-in exception: `importCerbosPolicies(input, { drop: ['schemas'] })` discards `schemas` blocks (attribute-schema references, enforced through the [`schemas` engine option](/guide/schema-validation#attribute-schemas-cerbos-schemas)) when you have no schema definitions to wire.

## API

| Export | Purpose |
| ------ | ------- |
| `importCerbosPolicies(input, options?)` | YAML/JSON text, parsed objects, or arrays of either → `{ policies, derivedRoles }` (serialized documents). |
| `celToExpr(source)` | Translates one CEL expression into a `$expr`-compatible JavaScript expression string. |
| `parseYamlDocuments(text)` | The YAML-subset parser, standalone (`---` multi-document streams supported). |
| `KerberosImportError` | Typed error; carries `line` for YAML parse errors. |

`input` accepts one string (which may hold several `---` documents), one parsed object, or an array of either. Policies with `disabled: true` are skipped, matching Cerbos's own loader. Effects are validated (`EFFECT_ALLOW` / `EFFECT_DENY`), and `scopePermissions: SCOPE_PERMISSIONS_OVERRIDE_PARENT` — the Cerbos default and exactly what Kerberos implements — is accepted; `REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS` throws.

## What is translated

| Cerbos | Kerberos |
| ------ | -------- |
| `resourcePolicy` (version, resource, scope, `importDerivedRoles`, rules with roles/derivedRoles/condition/output) | `{ resourcePolicy }` document |
| `principalPolicy` (principal, version, scope, per-resource action rules) | `{ principalPolicy }` document |
| `rolePolicy` (role, `parentRoles`, allowActions rules; no version in Cerbos → `default`) | `{ rolePolicy }` document |
| `derivedRoles` (definitions with `parentRoles` + condition) | derived-roles document |
| `condition.match` — `expr`, nested `all` / `any` / `none` `{ of: [...] }` | `{ match: { $expr } }`, `{ all: [...] }` / `{ any: [...] }` / `{ none: [...] }` |
| `variables.local` (CEL strings), `constants.local` (literal JSON) | `variables` / `constants` with `{ $expr }` / literals |
| `output.expr`, `output.when.ruleActivated` / `conditionNotMet` | `{ $expr }` output descriptors |

`schemas:` blocks translate verbatim — wire their definitions into the [`schemas` engine option](/guide/schema-validation#attribute-schemas-cerbos-schemas) to enforce them, or discard them with `drop: ['schemas']`. Always rejected (Kerberos does not implement them): `exportVariables` / `exportConstants` and `variables.import`, `scopePermissions: REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS`, script conditions, unknown keys at any level.

## The CEL → `$expr` translation

`celToExpr` parses real CEL (full expression grammar: precedence, ternary, literals incl. raw/triple-quoted strings, hex/uint numbers, comments) and emits JavaScript for the safe interpreter. The interesting mappings:

| CEL | JavaScript (`$expr`) | Note |
| --- | ------------------- | ---- |
| `request.principal` / `request.resource` | `P` / `R` | shorthand `P`, `R`, `V`, `C`, `variables`, `constants` also accepted |
| `==` / `!=` | `===` / `!==` | CEL equality does not coerce |
| `x in list` | `list.includes(x)` | on a *map* receiver this **errors at evaluation** (fail-loud) instead of checking keys |
| `has(R.attr.x)` | `typeof R.attr.x !== "undefined"` | an explicit `null` is *present*, matching CEL |
| `size(x)` / `x.size()` | `x.length` | strings and lists (a map's entry count is not translatable) |
| `timestamp(x)` / `now()` | `Date.parse(x)` / `Date.now()` | timestamps are epoch-**millisecond numbers**, so `<`, `==`, `-` all work numerically |
| `duration("72h3m")` | `259380000` | Go-style duration literals are constant-folded to ms; non-literal `duration()` throws |
| `t.getFullYear()` … | `new Date(t).getUTCFullYear()` … | CEL defaults to UTC; `getDayOfMonth()` adds the `- 1` (CEL is zero-based); time-zone arguments throw |
| `d.getHours()` on a duration | `Math.trunc(d / 3600000)` | totals, as in cel-go |
| `int(timestamp(x))` | `Math.trunc(Date.parse(x) / 1000)` | epoch seconds |
| `x.contains(s)` | `x.includes(s)` | `startsWith` / `endsWith` map directly |
| `x.replace(a, b)` | `x.split(a).join(b)` | CEL replaces every occurrence; JS `.replace` would stop at the first |
| `x.lowerAscii()` / `upperAscii()` | `toLowerCase()` / `toUpperCase()` | full-Unicode instead of ASCII-only — a documented deviation |
| `7 / 2` (int literals) | `Math.trunc(7 / 2)` | CEL integer division truncates; with non-literal operands `/` stays JS-numeric (Cerbos attributes come from JSON, i.e. CEL doubles, where the semantics agree) |
| `dyn(e)` | `e` | identity |

**Rejected, by design** (each with a named error): comprehension macros (`exists`, `all`, `exists_one`, `filter`, `map` — the interpreter has no lambdas), `matches()` (RE2), Cerbos extension functions (`hasIntersection`, `hierarchy`, `spiffeID`, …), `globals` / `G`, `runtime`, `request.auxData`, bytes literals, message construction, list/map `+` concatenation, non-string map keys, unsafe integer literals, and any identifier or function the translator does not recognize.

## How this is verified

The whole [Cerbos conformance corpus](https://github.com/Alexis-Technologies/kerberos/blob/main/conformance/README.md) — real Cerbos policy YAML whose expected decisions are pinned against a live Cerbos PDP in CI — is additionally run **through the public importer** (`conformance/importer.test.js`): YAML parsed by this parser, CEL translated by this translator, and every decision and query-plan expectation must still hold. The YAML subset parser is separately verified differentially against the reference `yaml` package over the same corpus.
