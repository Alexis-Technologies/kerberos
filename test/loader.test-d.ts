import { expectAssignable, expectType } from 'tsd';

import {
  KerberosLoaderError,
  createPolicyBundle,
  loadPolicyBundle,
  loadPolicyDirectory,
  loadPolicyFile,
  promises,
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

expectType<Promise<LoadedPolicies>>(promises.loadPolicyFile('./policy.yaml'));
expectType<Promise<LoadedPolicyDirectory>>(promises.loadPolicyDirectory('./policies', { concurrency: 8 }));
expectType<Promise<KerberosPolicyBundle>>(promises.writePolicyBundle('./bundle.json', bundle));
expectType<Promise<LoadedPolicyBundle>>(promises.loadPolicyBundle('./bundle.json', { verify: false }));

const error = new KerberosLoaderError('boom');
expectType<'KerberosLoaderError'>(error.name);
expectType<string | undefined>(error.file);
