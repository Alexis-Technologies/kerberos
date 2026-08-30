import { expectAssignable, expectError, expectType } from 'tsd';

import {
  KerberosImportError,
  celToExpr,
  importCerbosPolicies,
  parseYamlDocuments,
  type CerbosImportInput,
  type CerbosImportResult,
  type ImportedDerivedRolesDocument,
  type ImportedPolicyDocument,
} from '../cerbos.js';

// Pulls the whole /cerbos subpath surface (cerbos.d.ts) into tsd compilation.

expectType<unknown[]>(parseYamlDocuments('a: 1'));
expectType<string>(celToExpr('R.attr.owner == P.id'));

expectAssignable<CerbosImportInput>('yaml text');
expectAssignable<CerbosImportInput>({ resourcePolicy: {} });
expectAssignable<CerbosImportInput>(['yaml text', { resourcePolicy: {} }]);

const result = importCerbosPolicies('resourcePolicy:\n  resource: doc\n  rules: []');
expectType<CerbosImportResult>(result);
expectType<ImportedPolicyDocument[]>(result.policies);
expectType<ImportedDerivedRolesDocument[]>(result.derivedRoles);

importCerbosPolicies('text', { drop: ['schemas'] });
expectError(importCerbosPolicies('text', { drop: ['scopePermissions'] }));

const error = new KerberosImportError('boom');
expectType<'KerberosImportError'>(error.name);
expectType<number | undefined>(error.line);
