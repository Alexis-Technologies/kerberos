'use strict';

/**
 * Loads the shared corpus — Cerbos policy documents — into Kerberos policies.
 *
 * This is deliberately NOT a Cerbos importer (that is a separate, larger piece
 * of work: it needs a real CEL parser). It is a structural mapper that relies on
 * the two document formats being nearly identical, and it refuses to guess:
 * anything outside the supported subset throws rather than being dropped or
 * approximated, because a silently-skipped rule would turn a conformance
 * failure into a false pass.
 *
 * Conditions are passed through as `{ $expr }` strings unchanged. The corpus is
 * restricted to the CEL ∩ jsep subset (see conformance/README.md), so the same
 * source text is evaluated by both engines. A string outside that subset fails
 * loudly on the Kerberos side as `KerberosExprError`.
 */

const fs = require('node:fs');
const path = require('node:path');
const YAML = require('yaml');

class ConformanceUnsupportedError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConformanceUnsupportedError';
  }
}

const POLICY_KINDS = ['resourcePolicy', 'principalPolicy', 'rolePolicy', 'derivedRoles'];

// Cerbos document keys that carry no meaning for Kerberos and can be dropped.
const IGNORED_TOP_LEVEL = new Set(['apiVersion', 'description', 'metadata', 'disabled']);

// Cerbos features Kerberos deliberately does not implement. Listing them
// explicitly (instead of falling through to a generic "unknown key") keeps the
// error message actionable and doubles as documentation of the gap.
const KNOWN_UNSUPPORTED = {
  schemas: 'attribute schema enforcement',
  scopePermissions: 'scopePermissions (REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS)',
  exportVariables: 'exported variable sets',
  exportConstants: 'exported constant sets',
};

function unsupported(what, where) {
  throw new ConformanceUnsupportedError(`${where}: ${what} is not supported by the conformance corpus`);
}

/** Cerbos writes `{ expr }` / `{ all: { of: [...] } }`; Kerberos wants `{ $expr }` / `{ all: [...] }`. */
function translateMatch(match, where) {
  if (match === null || typeof match !== 'object') unsupported(`malformed condition (${typeof match})`, where);

  const keys = Object.keys(match);
  if (keys.length !== 1) unsupported(`condition with ${keys.length} keys (${keys.join(', ')})`, where);
  const [key] = keys;

  if (key === 'expr') {
    if (typeof match.expr !== 'string') unsupported('non-string expr', where);
    return { $expr: match.expr };
  }
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
  if (!condition || typeof condition !== 'object' || !('match' in condition)) {
    unsupported('condition without `match`', where);
  }
  return { match: translateMatch(condition.match, `${where}.match`) };
}

/** Cerbos output expressions are bare CEL strings; Kerberos wants `{ $expr }`. */
function translateOutput(output, where) {
  if (output === undefined) return undefined;
  if (typeof output === 'string') return { $expr: output };
  if (output && typeof output === 'object' && output.when) {
    const when = {};
    for (const [key, value] of Object.entries(output.when)) {
      if (key !== 'ruleActivated' && key !== 'conditionNotMet') unsupported(`output.when.${key}`, where);
      if (typeof value !== 'string') unsupported(`non-string output.when.${key}`, where);
      when[key] = { $expr: value };
    }
    return { when };
  }
  return unsupported('unrecognized output shape', where);
}

/** `{ local: { name: 'expr' }, import: [...] }` → `{ name: { $expr } }`. */
function translateBindings(bindings, where, label) {
  if (bindings === undefined) return undefined;
  if (Array.isArray(bindings.import) && bindings.import.length > 0) {
    unsupported(`imported ${label} sets`, where);
  }
  const local = bindings.local ?? {};
  const out = {};
  for (const [name, value] of Object.entries(local)) {
    // Constants are literal JSON in both engines; variables are expressions.
    out[name] = label === 'constant' ? value : { $expr: value };
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function assertNoUnsupportedKeys(body, where, allowed) {
  for (const key of Object.keys(body)) {
    if (KNOWN_UNSUPPORTED[key]) unsupported(KNOWN_UNSUPPORTED[key], where);
    if (!allowed.has(key)) unsupported(`unrecognized key \`${key}\``, where);
  }
}

function shared(body, where) {
  return {
    ...(translateBindings(body.variables, where, 'variable') && {
      variables: translateBindings(body.variables, where, 'variable'),
    }),
    ...(translateBindings(body.constants, where, 'constant') && {
      constants: translateBindings(body.constants, where, 'constant'),
    }),
  };
}

const TRANSLATORS = {
  resourcePolicy(body, where) {
    assertNoUnsupportedKeys(
      body,
      where,
      new Set(['version', 'resource', 'scope', 'rules', 'importDerivedRoles', 'variables', 'constants']),
    );
    return {
      resourcePolicy: {
        version: body.version,
        resource: body.resource,
        ...(body.scope !== undefined && { scope: body.scope }),
        ...(body.importDerivedRoles && { importDerivedRoles: body.importDerivedRoles }),
        ...shared(body, where),
        rules: body.rules.map((rule, i) => {
          const at = `${where}.rules[${i}]`;
          return {
            ...(rule.name && { name: rule.name }),
            actions: rule.actions,
            effect: rule.effect,
            ...(rule.roles && { roles: rule.roles }),
            ...(rule.derivedRoles && { derivedRoles: rule.derivedRoles }),
            ...(translateCondition(rule.condition, at) && { condition: translateCondition(rule.condition, at) }),
            ...(translateOutput(rule.output, at) && { output: translateOutput(rule.output, at) }),
          };
        }),
      },
    };
  },

  principalPolicy(body, where) {
    assertNoUnsupportedKeys(body, where, new Set(['principal', 'version', 'scope', 'rules', 'variables', 'constants']));
    return {
      principalPolicy: {
        principal: body.principal,
        version: body.version,
        ...(body.scope !== undefined && { scope: body.scope }),
        ...shared(body, where),
        rules: body.rules.map((rule, i) => ({
          resource: rule.resource,
          actions: rule.actions.map((action, j) => {
            const at = `${where}.rules[${i}].actions[${j}]`;
            return {
              ...(action.name && { name: action.name }),
              action: action.action,
              effect: action.effect,
              ...(translateCondition(action.condition, at) && { condition: translateCondition(action.condition, at) }),
              ...(translateOutput(action.output, at) && { output: translateOutput(action.output, at) }),
            };
          }),
        })),
      },
    };
  },

  rolePolicy(body, where) {
    assertNoUnsupportedKeys(
      body,
      where,
      new Set(['role', 'version', 'scope', 'parentRoles', 'rules', 'variables', 'constants']),
    );
    return {
      rolePolicy: {
        role: body.role,
        // Cerbos role policies have no `version`; Kerberos requires one.
        version: body.version ?? 'default',
        ...(body.scope !== undefined && { scope: body.scope }),
        ...(body.parentRoles && { parentRoles: body.parentRoles }),
        ...shared(body, where),
        rules: body.rules.map((rule, i) => {
          const at = `${where}.rules[${i}]`;
          return {
            ...(rule.name && { name: rule.name }),
            resource: rule.resource,
            allowActions: rule.allowActions,
            ...(translateCondition(rule.condition, at) && { condition: translateCondition(rule.condition, at) }),
          };
        }),
      },
    };
  },

  derivedRoles(body, where) {
    assertNoUnsupportedKeys(body, where, new Set(['name', 'definitions', 'variables', 'constants']));
    return {
      name: body.name,
      ...shared(body, where),
      definitions: body.definitions.map((def, i) => {
        const at = `${where}.definitions[${i}]`;
        return {
          name: def.name,
          parentRoles: def.parentRoles,
          ...(translateCondition(def.condition, at) && { condition: translateCondition(def.condition, at) }),
        };
      }),
    };
  },
};

/** Translates one parsed Cerbos document into `{ kind, document }`. */
function translateDocument(doc, where) {
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
  return { kind, document: TRANSLATORS[kind](doc[kind], `${where}.${kind}`) };
}

/**
 * Reads every policy document in `dir` and returns Kerberos constructor
 * arguments plus the raw Cerbos documents (which the live-PDP run serves).
 */
function loadCorpus(dir) {
  const policies = [];
  const derivedRoles = [];
  const raw = [];

  for (const file of fs.readdirSync(dir).sort()) {
    if (!/\.ya?ml$/.test(file)) continue;
    const text = fs.readFileSync(path.join(dir, file), 'utf8');
    const documents = YAML.parseAllDocuments(text).filter((doc) => doc.toJS() !== null);
    // Cerbos rejects a policy file carrying more than one YAML document
    // ("more than one YAML document detected"). Refuse it here too, so the
    // offline run cannot pass on a corpus a real PDP would not even load.
    if (documents.length > 1) {
      throw new ConformanceUnsupportedError(
        `${file}: more than one YAML document in a policy file — Cerbos loads one policy per file`,
      );
    }
    for (const [index, doc] of documents.entries()) {
      const parsed = doc.toJS();
      if (!parsed) continue;
      const where = `${file}[${index}]`;
      const { kind, document } = translateDocument(parsed, where);
      raw.push({ file, document: parsed });
      if (kind === 'derivedRoles') derivedRoles.push(document);
      else policies.push(document);
    }
  }

  return { policies, derivedRoles, raw };
}

module.exports = { ConformanceUnsupportedError, loadCorpus, translateDocument };
