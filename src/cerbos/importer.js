/**
 * Cerbos policy importer: translates Cerbos policy documents (YAML/JSON text
 * or already-parsed objects) into Kerberos serialized policy documents whose
 * conditions/variables/outputs are `{ $expr }` descriptors (CEL translated by
 * translate.js). The output is cache-ready JSON; bring it to life with
 * `deserializePolicy(doc, createSafeExprCodec({ jsep }))` before handing it to
 * the `Kerberos` constructor.
 *
 * Like the rest of `src/cerbos/`, the importer REFUSES TO GUESS: Cerbos
 * features Kerberos does not implement throw a named `KerberosImportError`
 * instead of being dropped (the sole, explicitly-opt-in exception is
 * `drop: ['schemas']`, which discards validation-only schema references).
 * A policy with `disabled: true` is skipped, matching Cerbos's own loader.
 */

const { KerberosImportError } = require('./errors.js');
const { parseYamlDocuments } = require('./yaml.js');
const { celToExpr } = require('./translate.js');

const POLICY_KINDS = ['resourcePolicy', 'principalPolicy', 'rolePolicy', 'derivedRoles'];

// Cerbos document keys that carry no evaluation meaning for Kerberos.
const IGNORED_TOP_LEVEL = new Set(['apiVersion', 'description', 'metadata', 'disabled']);

// Cerbos features Kerberos deliberately does not implement. Named explicitly
// so the error message is actionable and doubles as documentation of the gap.
const KNOWN_UNSUPPORTED = {
  schemas: 'attribute schema enforcement (`schemas`)',
  exportVariables: 'exported variable sets (`exportVariables`)',
  exportConstants: 'exported constant sets (`exportConstants`)',
};

const DROPPABLE = new Set(['schemas']);

const EFFECTS = new Set(['EFFECT_ALLOW', 'EFFECT_DENY']);

function fail(message) {
  throw new KerberosImportError(message);
}

function unsupported(what, where) {
  fail(`${where}: ${what} is not supported by the importer`);
}

/** Translates one CEL string, prefixing translation errors with the location. */
function toExpr(source, where) {
  if (typeof source !== 'string') unsupported(`non-string expression (${typeof source})`, where);
  try {
    return { $expr: celToExpr(source) };
  } catch (error) {
    if (error instanceof KerberosImportError) fail(`${where}: ${error.message}`);
    throw error;
  }
}

function assertKeys(body, allowed, where, drop) {
  for (const key of Object.keys(body)) {
    if (allowed.has(key)) continue;
    if (KNOWN_UNSUPPORTED[key]) {
      if (drop.has(key) && DROPPABLE.has(key)) continue;
      unsupported(KNOWN_UNSUPPORTED[key], where);
    }
    unsupported(`unrecognized key \`${key}\``, where);
  }
}

function checkEffect(effect, where) {
  if (!EFFECTS.has(effect)) unsupported(`effect \`${effect}\``, where);
  return effect;
}

function checkScopePermissions(value, where) {
  // OVERRIDE_PARENT is the Cerbos default and exactly what Kerberos implements.
  if (value === undefined || value === 'SCOPE_PERMISSIONS_OVERRIDE_PARENT') return;
  unsupported(`scopePermissions \`${value}\``, where);
}

/** Cerbos `{ expr }` / `{ all: { of: [...] } }` → Kerberos `{ $expr }` / `{ all: [...] }`. */
function translateMatch(match, where) {
  if (match === null || typeof match !== 'object') unsupported(`malformed condition (${typeof match})`, where);
  const keys = Object.keys(match);
  if (keys.length !== 1) unsupported(`condition with ${keys.length} keys (${keys.join(', ')})`, where);
  const [key] = keys;

  if (key === 'expr') return toExpr(match.expr, where);
  if (key === 'all' || key === 'any' || key === 'none') {
    const branch = match[key];
    const list = branch && typeof branch === 'object' && Array.isArray(branch.of) ? branch.of : null;
    if (!list) unsupported(`\`${key}\` without an \`of:\` list`, where);
    return { [key]: list.map((entry, i) => translateMatch(entry, `${where}.${key}[${i}]`)) };
  }
  return unsupported(`condition operator \`${key}\``, where);
}

function translateCondition(condition, where) {
  if (condition === undefined) return undefined;
  if (!condition || typeof condition !== 'object') unsupported('malformed condition', where);
  if ('script' in condition) unsupported('script conditions', where);
  if (!('match' in condition)) unsupported('condition without `match`', where);
  assertKeys(condition, new Set(['match']), where, new Set());
  return { match: translateMatch(condition.match, `${where}.match`) };
}

/** Cerbos `output: { expr }` / `{ when: {...} }` → Kerberos `{ $expr }` / `{ when: {...} }`. */
function translateOutput(output, where) {
  if (output === undefined) return undefined;
  if (!output || typeof output !== 'object') unsupported('malformed output', where);
  assertKeys(output, new Set(['expr', 'when']), where, new Set());
  if (typeof output.expr === 'string') return toExpr(output.expr, `${where}.expr`);
  if (output.when && typeof output.when === 'object') {
    const when = {};
    for (const [key, value] of Object.entries(output.when)) {
      if (key !== 'ruleActivated' && key !== 'conditionNotMet') unsupported(`output.when.${key}`, where);
      when[key] = toExpr(value, `${where}.when.${key}`);
    }
    return { when };
  }
  return unsupported('output without `expr` or `when`', where);
}

/** Cerbos `{ import: [...], local: { name: 'cel' } }` variable/constant bindings. */
function translateBindings(bindings, where, label) {
  if (bindings === undefined) return undefined;
  if (!bindings || typeof bindings !== 'object') unsupported(`malformed ${label}s block`, where);
  assertKeys(bindings, new Set(['import', 'local']), where, new Set());
  if (Array.isArray(bindings.import) && bindings.import.length > 0) {
    unsupported(`imported ${label} sets`, where);
  }
  const local = bindings.local ?? {};
  const out = {};
  for (const [name, value] of Object.entries(local)) {
    // Constants are literal JSON in both engines; variables are expressions.
    out[name] = label === 'constant' ? value : toExpr(value, `${where}.local.${name}`);
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function shared(body, where) {
  const variables = translateBindings(body.variables, `${where}.variables`, 'variable');
  const constants = translateBindings(body.constants, `${where}.constants`, 'constant');
  return { ...(variables && { variables }), ...(constants && { constants }) };
}

const TRANSLATORS = {
  resourcePolicy(body, where, drop) {
    assertKeys(
      body,
      new Set([
        'version',
        'resource',
        'scope',
        'scopePermissions',
        'rules',
        'importDerivedRoles',
        'variables',
        'constants',
      ]),
      where,
      drop,
    );
    checkScopePermissions(body.scopePermissions, where);
    if (!Array.isArray(body.rules)) unsupported('resourcePolicy without a rules list', where);
    return {
      resourcePolicy: {
        version: body.version ?? 'default',
        resource: body.resource,
        ...(body.scope !== undefined && { scope: body.scope }),
        ...(body.importDerivedRoles && { importDerivedRoles: body.importDerivedRoles }),
        ...shared(body, where),
        rules: body.rules.map((rule, i) => {
          const at = `${where}.rules[${i}]`;
          assertKeys(
            rule,
            new Set(['name', 'actions', 'effect', 'roles', 'derivedRoles', 'condition', 'output']),
            at,
            drop,
          );
          const condition = translateCondition(rule.condition, at);
          const output = translateOutput(rule.output, `${at}.output`);
          return {
            ...(rule.name && { name: rule.name }),
            actions: rule.actions,
            effect: checkEffect(rule.effect, at),
            ...(rule.roles && { roles: rule.roles }),
            ...(rule.derivedRoles && { derivedRoles: rule.derivedRoles }),
            ...(condition && { condition }),
            ...(output && { output }),
          };
        }),
      },
    };
  },

  principalPolicy(body, where, drop) {
    assertKeys(
      body,
      new Set(['principal', 'version', 'scope', 'scopePermissions', 'rules', 'variables', 'constants']),
      where,
      drop,
    );
    checkScopePermissions(body.scopePermissions, where);
    if (!Array.isArray(body.rules)) unsupported('principalPolicy without a rules list', where);
    return {
      principalPolicy: {
        principal: body.principal,
        version: body.version ?? 'default',
        ...(body.scope !== undefined && { scope: body.scope }),
        ...shared(body, where),
        rules: body.rules.map((rule, i) => {
          const at = `${where}.rules[${i}]`;
          assertKeys(rule, new Set(['resource', 'actions']), at, drop);
          if (!Array.isArray(rule.actions)) unsupported('principal rule without an actions list', at);
          return {
            resource: rule.resource,
            actions: rule.actions.map((action, j) => {
              const atAction = `${at}.actions[${j}]`;
              assertKeys(action, new Set(['name', 'action', 'effect', 'condition', 'output']), atAction, drop);
              const condition = translateCondition(action.condition, atAction);
              const output = translateOutput(action.output, `${atAction}.output`);
              return {
                ...(action.name && { name: action.name }),
                action: action.action,
                effect: checkEffect(action.effect, atAction),
                ...(condition && { condition }),
                ...(output && { output }),
              };
            }),
          };
        }),
      },
    };
  },

  rolePolicy(body, where, drop) {
    assertKeys(body, new Set(['role', 'version', 'scope', 'scopePermissions', 'parentRoles', 'rules']), where, drop);
    checkScopePermissions(body.scopePermissions, where);
    if (!Array.isArray(body.rules)) unsupported('rolePolicy without a rules list', where);
    return {
      rolePolicy: {
        role: body.role,
        // Cerbos role policies carry no `version`; Kerberos requires one.
        version: body.version ?? 'default',
        ...(body.scope !== undefined && { scope: body.scope }),
        ...(body.parentRoles && { parentRoles: body.parentRoles }),
        rules: body.rules.map((rule, i) => {
          const at = `${where}.rules[${i}]`;
          assertKeys(rule, new Set(['name', 'resource', 'allowActions', 'condition']), at, drop);
          const condition = translateCondition(rule.condition, at);
          return {
            ...(rule.name && { name: rule.name }),
            resource: rule.resource,
            allowActions: rule.allowActions,
            ...(condition && { condition }),
          };
        }),
      },
    };
  },

  derivedRoles(body, where, drop) {
    assertKeys(body, new Set(['name', 'definitions', 'variables', 'constants']), where, drop);
    if (!Array.isArray(body.definitions)) unsupported('derivedRoles without a definitions list', where);
    return {
      name: body.name,
      ...shared(body, where),
      definitions: body.definitions.map((def, i) => {
        const at = `${where}.definitions[${i}]`;
        assertKeys(def, new Set(['name', 'parentRoles', 'condition']), at, drop);
        const condition = translateCondition(def.condition, at);
        return {
          name: def.name,
          parentRoles: def.parentRoles,
          ...(condition && { condition }),
        };
      }),
    };
  },
};

/** Translates one parsed Cerbos document; `null` when the policy is disabled. */
function translateDocument(doc, where, drop) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    unsupported(`malformed document (${Array.isArray(doc) ? 'array' : typeof doc})`, where);
  }
  if (doc.apiVersion !== undefined && doc.apiVersion !== 'api.cerbos.dev/v1') {
    unsupported(`apiVersion \`${doc.apiVersion}\``, where);
  }
  for (const key of Object.keys(doc)) {
    if (IGNORED_TOP_LEVEL.has(key) || POLICY_KINDS.includes(key)) continue;
    if (KNOWN_UNSUPPORTED[key]) unsupported(KNOWN_UNSUPPORTED[key], where);
    if (key === 'variables' || key === 'constants') {
      unsupported('top-level (legacy) variables/constants — use the policy-scoped form', where);
    }
    unsupported(`unrecognized top-level key \`${key}\``, where);
  }

  const kind = POLICY_KINDS.find((candidate) => doc[candidate] !== undefined);
  if (!kind) unsupported('document declares no policy body', where);
  if (doc.disabled === true) return null;
  return { kind, document: TRANSLATORS[kind](doc[kind], `${where}.${kind}`, drop) };
}

/** One input → parsed documents. Strings may be YAML (multi-document) or JSON. */
function parseInput(input, where) {
  if (typeof input === 'string') {
    if (input.trimStart().startsWith('{')) {
      try {
        return [JSON.parse(input)];
      } catch (error) {
        fail(`${where}: invalid JSON — ${error.message}`);
      }
    }
    return parseYamlDocuments(input);
  }
  if (input && typeof input === 'object' && !Array.isArray(input)) return [input];
  return fail(`${where}: expected a YAML/JSON string or a parsed document object`);
}

/**
 * Imports Cerbos policy documents into Kerberos serialized documents.
 *
 * @param {string | Record<string, unknown> | Array<string | Record<string, unknown>>} input
 *   YAML/JSON text (a string may contain multiple `---` documents), a parsed
 *   document object, or an array of either.
 * @param {{ drop?: string[] }} [options]
 *   `drop: ['schemas']` discards `schemas` blocks (validation-only) instead of
 *   throwing on them.
 * @returns {{ policies: Array<Record<string, unknown>>, derivedRoles: Array<Record<string, unknown>> }}
 *   Serialized documents (`{ $expr }` conditions). Deserialize each with
 *   `deserializePolicy(doc, codec)` before passing to the Kerberos constructor.
 */
function importCerbosPolicies(input, options = {}) {
  if (options === null || typeof options !== 'object') fail('options must be an object');
  const dropList = options.drop ?? [];
  if (!Array.isArray(dropList)) fail('options.drop must be an array');
  for (const entry of dropList) {
    if (!DROPPABLE.has(entry)) fail(`options.drop: \`${entry}\` is not a droppable feature (droppable: schemas)`);
  }
  const drop = new Set(dropList);

  const inputs = Array.isArray(input) ? input : [input];
  const policies = [];
  const derivedRoles = [];
  for (const [inputIndex, entry] of inputs.entries()) {
    const whereBase = inputs.length === 1 ? 'document' : `input[${inputIndex}]`;
    const documents = parseInput(entry, whereBase);
    for (const [docIndex, doc] of documents.entries()) {
      const where = documents.length === 1 ? whereBase : `${whereBase}[${docIndex}]`;
      const translated = translateDocument(doc, where, drop);
      if (!translated) continue; // disabled policy
      if (translated.kind === 'derivedRoles') derivedRoles.push(translated.document);
      else policies.push(translated.document);
    }
  }
  return { policies, derivedRoles };
}

module.exports = { importCerbosPolicies };
