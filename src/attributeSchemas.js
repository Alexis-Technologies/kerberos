/**
 * Attribute schema enforcement — Cerbos `schemas` parity.
 *
 * A resource policy may declare `schemas.principalSchema` / `resourceSchema`
 * references (with optional `ignoreWhen.actions` globs); the engine's
 * `schemas` option maps those refs to actual validators and picks the
 * enforcement level:
 *
 * - `reject` (default when the option is set): a request whose attributes
 *   fail validation is denied for every action, with the failures reported as
 *   `validationErrors` on the result;
 * - `warn`:  failures are reported on the result (and reach the audit log)
 *   but evaluation proceeds normally;
 * - `none`:  schema references in policies are inert (Cerbos's own default).
 *
 * A definition may be a plain object (JSON Schema — compiled with the
 * engine's `ajv` option), a Zod-like schema (anything with `safeParse`), or a
 * function returning error messages. Every validator is normalized to
 * `(value) => Array<{ path, message }>` at construction, so evaluation-time
 * validation is a plain call. Validation errors follow Cerbos's shape:
 * `{ path, message, source: 'SOURCE_PRINCIPAL' | 'SOURCE_RESOURCE' }`.
 *
 * Platform-neutral, zero dependencies.
 */

const { KerberosValidationError } = require('./errors.js');

const ENFORCEMENT_LEVELS = new Set(['none', 'warn', 'reject']);

function normalizeErrors(raw, ref) {
  if (raw === undefined || raw === null || raw === true) return [];
  if (raw === false) return [{ path: '', message: `does not match schema "${ref}"` }];
  if (!Array.isArray(raw)) {
    throw new KerberosValidationError(
      `Attribute schema "${ref}": a validator function must return an array of errors (or nothing when valid)`,
    );
  }
  return raw.map((entry) => {
    if (typeof entry === 'string') return { path: '', message: entry };
    if (entry && typeof entry === 'object') {
      return { path: typeof entry.path === 'string' ? entry.path : '', message: String(entry.message ?? 'invalid') };
    }
    return { path: '', message: String(entry) };
  });
}

function compileDefinition(ref, definition, ajv) {
  // Zod-like: anything exposing safeParse (covers Zod 3/4 schemas).
  if (definition && typeof definition.safeParse === 'function') {
    return (value) => {
      const parsed = definition.safeParse(value);
      if (parsed.success) return [];
      const issues = parsed.error?.issues ?? [];
      return issues.map((issue) => ({
        path: `/${(issue.path ?? []).join('/')}`,
        message: issue.message ?? 'invalid',
      }));
    };
  }

  // Custom validator function.
  if (typeof definition === 'function') {
    return (value) => normalizeErrors(definition(value), ref);
  }

  // Plain object: JSON Schema, compiled through the engine's ajv option.
  if (definition && typeof definition === 'object') {
    if (!ajv) {
      throw new KerberosValidationError(
        `Attribute schema "${ref}" is a JSON Schema, which requires the \`ajv\` engine option to compile ` +
          '(or provide a Zod schema / validator function instead)',
      );
    }
    const validate = ajv.compile(definition);
    return (value) => {
      if (validate(value)) return [];
      return (validate.errors ?? []).map((error) => ({
        path: error.instancePath ?? '',
        message: error.message ?? 'invalid',
      }));
    };
  }

  throw new KerberosValidationError(
    `Attribute schema "${ref}": expected a JSON Schema object, a Zod-like schema or a validator function`,
  );
}

/**
 * Builds the engine's attribute-schema registry from the `schemas` option.
 * Returns `null` when enforcement is off (no option, or `enforcement: 'none'`).
 *
 * @param {{ enforcement?: string, definitions?: Record<string, unknown> } | null | undefined} options
 * @param {unknown} ajv - the engine's ajv option (used to compile JSON Schema definitions)
 * @returns {{ enforcement: 'warn' | 'reject', resolve(ref: string): (value: unknown) => Array<{ path: string, message: string }> } | null}
 */
function createAttributeSchemaRegistry(options, ajv) {
  if (options === undefined || options === null) return null;
  if (typeof options !== 'object') {
    throw new TypeError('Invalid schemas option — expected an object like { enforcement, definitions }');
  }
  const enforcement = options.enforcement ?? 'reject';
  if (!ENFORCEMENT_LEVELS.has(enforcement)) {
    throw new TypeError(`Invalid schemas.enforcement "${enforcement}" — expected 'none', 'warn' or 'reject'`);
  }
  if (enforcement === 'none') return null;

  const definitions = options.definitions ?? {};
  if (typeof definitions !== 'object' || definitions === null || Array.isArray(definitions)) {
    throw new TypeError('Invalid schemas.definitions — expected an object mapping refs to schema definitions');
  }

  const validators = new Map();
  for (const [ref, definition] of Object.entries(definitions)) {
    validators.set(ref, compileDefinition(ref, definition, ajv));
  }

  return {
    enforcement,
    resolve(ref) {
      const validator = validators.get(ref);
      if (!validator) {
        // A policy referencing an undefined schema is a configuration error,
        // and KerberosValidationError always propagates regardless of the
        // onError option — this must never silently read as valid OR invalid.
        throw new KerberosValidationError(
          `Attribute schema "${ref}" is referenced by a policy but missing from schemas.definitions`,
        );
      }
      return validator;
    },
  };
}

/**
 * Validates one request's principal/resource attributes against the schema
 * bindings of the most specific resource policy in the chain that declares
 * any. Pure and synchronous — validators were compiled at construction.
 *
 * @param {{ enforcement: string, resolve(ref: string): Function }} registry
 * @param {Array<{ policy: { attributeSchemas: object | null } }>} resourceChain - most specific scope first
 * @param {Record<string, unknown>} req
 * @returns {Array<{ path: string, message: string, source: string }>}
 */
function validateRequestAttributes(registry, resourceChain, req) {
  let bindings = null;
  for (const entry of resourceChain) {
    if (entry.policy.attributeSchemas) {
      bindings = entry.policy.attributeSchemas;
      break;
    }
  }
  if (!bindings) return [];

  const errors = [];
  const sources = [
    ['principalSchema', 'SOURCE_PRINCIPAL', req.P.attr],
    ['resourceSchema', 'SOURCE_RESOURCE', req.R.attr],
  ];
  for (const [key, source, attr] of sources) {
    const binding = bindings[key];
    if (!binding) continue;
    // Cerbos semantics: validation is skipped only when EVERY action in the
    // request matches the ignoreWhen globs.
    if (binding.ignoreMatcher && req.actions.every((action) => binding.ignoreMatcher.matches(action))) continue;
    for (const { path, message } of registry.resolve(binding.ref)(attr ?? {})) {
      errors.push({ path, message, source });
    }
  }
  return errors;
}

module.exports = { createAttributeSchemaRegistry, validateRequestAttributes };
