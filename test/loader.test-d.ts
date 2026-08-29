import { expectAssignable, expectType } from 'tsd';

import {
  KerberosLoaderError,
  createPolicyBundle,
  loadPolicyBundle,
  loadPolicyDirectory,
  loadPolicyFile,
  writePolicyBundle,
  type KerberosPolicyBundle,
  type LoadPolicyDirectoryOptions,
  type LoadedPolicies,
  type LoadedPolicyBundle,
  type LoadedPolicyDirectory,
} from '../loader.js';

// Pulls the whole /loader subpath surface (loader.d.ts) into tsd compilation.

expectType<LoadedPolicies>(loadPolicyFile('./policy.yaml'));

const dir = loadPolicyDirectory('./policies', { recursive: false, cerbos: 'auto' });
expectType<LoadedPolicyDirectory>(dir);
expectType<string[]>(dir.files);
expectType<Record<string, unknown>>(dir.schemas);
expectAssignable<LoadPolicyDirectoryOptions>({ cerbos: true, drop: ['schemas'] });

const bundle = createPolicyBundle(dir, { createdAt: null });
expectType<KerberosPolicyBundle>(bundle);
expectType<string>(bundle.version);
expectType<1>(bundle.kerberosPolicyBundle);

expectType<KerberosPolicyBundle>(writePolicyBundle('./bundle.json', bundle));
expectType<LoadedPolicyBundle>(loadPolicyBundle('./bundle.json', { verify: true }));
expectType<LoadedPolicyBundle>(loadPolicyBundle(bundle));

const error = new KerberosLoaderError('boom');
expectType<'KerberosLoaderError'>(error.name);
expectType<string | undefined>(error.file);
