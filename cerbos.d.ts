/**
 * Type definitions for the `@alexify/kerberos/cerbos` subpath — the Cerbos
 * policy importer: YAML/JSON policy documents plus a CEL → `$expr` expression
 * translator.
 *
 * The importer refuses to guess: any Cerbos construct outside its supported
 * subset throws {@link KerberosImportError} instead of being dropped or
 * approximated. Its output is SERIALIZED documents (`{ $expr }` condition
 * descriptors) — deserialize each with `deserializePolicy(doc, codec)` from
 * the main entry before passing it to the `Kerberos` constructor.
 */

/**
 * Error thrown when a document, expression or YAML construct falls outside
 * the importer's supported subset.
 */
export declare class KerberosImportError extends Error {
  name: 'KerberosImportError';
  /** 1-based line number, present for YAML parsing errors. */
  line?: number;
}

/**
 * A serialized Kerberos policy document produced by the importer: one of
 * `{ resourcePolicy }`, `{ principalPolicy }` or `{ rolePolicy }`, with
 * conditions/variables/outputs as `{ $expr }` descriptors.
 */
export type ImportedPolicyDocument = Record<string, unknown>;

/** A serialized derived-roles document (`{ name, definitions }`). */
export type ImportedDerivedRolesDocument = Record<string, unknown>;

/**
 * Importer input: YAML/JSON text (a string may contain multiple `---`
 * documents), an already-parsed document object, or an array of either.
 */
export type CerbosImportInput = string | Record<string, unknown> | ReadonlyArray<string | Record<string, unknown>>;

export interface CerbosImportOptions {
  /**
   * Unsupported-but-droppable Cerbos features to discard instead of throwing
   * on. Only `'schemas'` (validation-only attribute schema references) is
   * droppable — everything else the importer cannot translate always throws.
   */
  drop?: ReadonlyArray<'schemas'>;
}

export interface CerbosImportResult {
  /** Serialized policy documents, ready for `deserializePolicy(doc, codec)`. */
  policies: ImportedPolicyDocument[];
  /** Serialized derived-roles documents, ready for `deserializePolicy(doc, codec)`. */
  derivedRoles: ImportedDerivedRolesDocument[];
}

/**
 * Parses a YAML stream (the subset Cerbos policies are written in) into an
 * array of documents — one per `---` section, comment-only sections omitted.
 * Anchors, aliases, tags, directives and multi-line plain scalars throw.
 */
export declare function parseYamlDocuments(text: string): unknown[];

/**
 * Translates one CEL expression into a `$expr`-compatible JavaScript
 * expression string (for the documented jsep setup: object/ternary/new
 * plugins plus `jsep.addUnaryOp('typeof')`). Throws {@link KerberosImportError}
 * on CEL constructs with no faithful `$expr` counterpart (macros, `matches()`,
 * Cerbos extension functions, `globals`, `request.auxData`, …).
 */
export declare function celToExpr(source: string): string;

/**
 * Imports Cerbos policy documents into Kerberos serialized documents.
 * Policies with `disabled: true` are skipped, matching Cerbos's own loader.
 */
export declare function importCerbosPolicies(
  input: CerbosImportInput,
  options?: CerbosImportOptions,
): CerbosImportResult;
