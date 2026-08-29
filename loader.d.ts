/**
 * Type definitions for the `@alexify/kerberos/loader` subpath — the Node-only
 * file/directory policy loader and hash-stamped policy bundles.
 *
 * The core package never touches the filesystem; this subpath is the
 * boot-time bridge for policy-as-code repositories. In browsers every
 * function throws (`src/loader/browser.js` is substituted by bundlers) —
 * fetch a bundle over the network instead.
 */

import type { PolicyCodec } from './index.js';

/** Error thrown for I/O, format and bundle-integrity failures. */
export declare class KerberosLoaderError extends Error {
  name: 'KerberosLoaderError';
  /** The file (or directory) the failure belongs to, when known. */
  file?: string;
}

export interface LoadPolicyOptions {
  /**
   * A policy codec (`createSafeExprCodec({ jsep })`): when provided, loaded
   * documents are deserialized (`{ $expr }` → live functions) and are ready
   * for the `Kerberos` constructor; without it the SERIALIZED documents are
   * returned (cache- and bundle-ready).
   */
  codec?: PolicyCodec | { deserialize(json: unknown): unknown };
  /**
   * How to treat documents: `'auto'` (default) routes `.yaml`/`.yml` files
   * and JSON documents carrying `apiVersion` through the `/cerbos` importer;
   * `true` forces the importer for everything; `false` disables it.
   */
  cerbos?: 'auto' | boolean;
  /** Forwarded to the Cerbos importer (`drop: ['schemas']`). */
  drop?: readonly string[];
}

export interface LoadPolicyDirectoryOptions extends LoadPolicyOptions {
  /** Recurse into subdirectories (default true). `_`- and `.`-prefixed entries are always skipped. */
  recursive?: boolean;
}

export interface LoadedPolicies {
  policies: unknown[];
  derivedRoles: unknown[];
}

export interface LoadedPolicyDirectory extends LoadedPolicies {
  /** Relative paths of every policy file loaded, sorted. */
  files: string[];
  /**
   * Attribute-schema definitions from `_schemas/**.json`, keyed by both the
   * bare relative path (`expense.json`) and the Cerbos ref form
   * (`cerbos:///expense.json`) — feed this to the engine's
   * `schemas.definitions` option.
   */
  schemas: Record<string, unknown>;
}

/** A hash-stamped policy bundle produced by `createPolicyBundle`. */
export interface KerberosPolicyBundle extends LoadedPolicies {
  kerberosPolicyBundle: 1;
  /** SHA-256 of the canonical (sorted-key) JSON of `{ policies, derivedRoles }`. */
  version: string;
  createdAt?: string;
  counts: { policies: number; derivedRoles: number };
}

export interface CreatePolicyBundleOptions {
  /** ISO timestamp for the stamp; `null` omits it (fully reproducible output). */
  createdAt?: string | null;
}

export interface LoadPolicyBundleOptions {
  codec?: PolicyCodec | { deserialize(json: unknown): unknown };
  /** Verify the hash stamp (default true). */
  verify?: boolean;
}

export interface LoadedPolicyBundle extends LoadedPolicies {
  version: string;
  createdAt?: string;
}

/** Loads one `.json` (Kerberos/Cerbos) or `.yaml` (Cerbos) policy file. */
export declare function loadPolicyFile(filePath: string, options?: LoadPolicyOptions): LoadedPolicies;

/**
 * Loads every policy document under `dir` plus `_schemas/` attribute-schema
 * definitions. Deterministic order (sorted paths).
 */
export declare function loadPolicyDirectory(
  dir: string,
  options?: LoadPolicyDirectoryOptions,
): LoadedPolicyDirectory;

/** Stamps serialized documents into a versioned bundle (content-addressed SHA-256 `version`). */
export declare function createPolicyBundle(
  input: Partial<LoadedPolicies>,
  options?: CreatePolicyBundleOptions,
): KerberosPolicyBundle;

/** Writes a bundle (stamping raw `{ policies, derivedRoles }` first) as pretty JSON. */
export declare function writePolicyBundle(
  filePath: string,
  input: Partial<LoadedPolicies> | KerberosPolicyBundle,
  options?: CreatePolicyBundleOptions,
): KerberosPolicyBundle;

/**
 * Loads a bundle from a path or parsed object, verifying its hash stamp —
 * hand-edited, truncated or foreign-stamped content throws.
 */
export declare function loadPolicyBundle(
  source: string | KerberosPolicyBundle | Record<string, unknown>,
  options?: LoadPolicyBundleOptions,
): LoadedPolicyBundle;
