import { expectAssignable, expectType } from 'tsd';

import { Kerberos, type KerberosRelationsResolver } from '../index.js';
import {
  buildAdmissionKey,
  parseObjectRef,
  parseSubjectRef,
  parseTuple,
  RelationResolver,
  RelationSchema,
  type RelationLookupSubjectsResult,
  type RelationSchemaShape,
  type RelationTuple,
} from '../relations.js';

const schemaShape: RelationSchemaShape = {
  relationSchema: {
    caveats: { pro_tier: { match: { $expr: 'ctx.tier === "pro"' } } },
    definitions: {
      user: {},
      group: { relations: { member: ['user', 'group#member'] } },
      doc: {
        relations: { viewer: ['user', 'user:*', { type: 'user', caveat: 'pro_tier' }], parent: ['doc'] },
        permissions: {
          view: { anyOf: ['viewer', { via: 'parent', permission: 'view' }] },
          audit: { allOf: ['viewer'] },
          read_only: { exclude: { base: 'viewer', subtract: ['viewer'] } },
        },
      },
    },
  },
};

const tuple: RelationTuple = { resource: 'doc:d1', relation: 'viewer', subject: 'user:u1' };

const resolver = new RelationResolver({
  schema: schemaShape,
  tuples: ['doc:d1#viewer@user:u1', tuple],
  subjectType: 'user',
  reverseIndex: false,
  maxDepth: 25,
  maxResults: 100,
});

expectType<RelationSchema>(resolver.schema);
expectType<Promise<boolean>>(resolver.check({ resource: 'doc:d1', permission: 'view', subject: 'user:u1' }));
expectType<Promise<boolean>>(
  resolver.check(
    { resource: { kind: 'doc', id: 'd1' }, relation: 'view', principal: { id: 'u1', roles: ['USER'] } },
    { memo: new Map() },
  ),
);
expectType<Promise<Set<string>>>(resolver.list({ resource: 'doc:d1', subject: 'user:u1', relations: ['view'] }));
expectType<Promise<RelationLookupSubjectsResult>>(resolver.lookupSubjects({ resource: 'doc:d1', permission: 'view' }));
expectType<Promise<string[]>>(
  resolver.lookupResources({ subject: 'user:u1', permission: 'view', resourceType: 'doc' }),
);

// The resolver satisfies the engine delegation contract.
expectAssignable<KerberosRelationsResolver>(resolver);
void new Kerberos([], [], { relations: resolver });

// Compiled-schema surface.
const schema = resolver.schema;
expectType<boolean>(schema.hasDefinition('doc'));
expectType<boolean>(schema.isCheckable('doc', 'view'));
expectType<Set<string> | undefined>(schema.getRelationAdmission('doc', 'viewer'));

// Reference-grammar helpers.
expectType<string>(buildAdmissionKey('user', null, false, null));
expectType<{ type: string; id: string }>(parseObjectRef('doc:d1'));
expectType<{ type: string; id: string; relation: string | null }>(parseSubjectRef('group:eng#member'));
void parseTuple('doc:d1#viewer@user:u1');

// Resolver hooks and events.
import type { RelationCheckedEvent, RelationHookContext, RelationResolverHooks } from '../relations.js';

const resolverHooks: RelationResolverHooks = {
  beforeRequest(ctx) {
    expectType<RelationHookContext>(ctx);
    expectType<'check' | 'list' | 'lookupSubjects' | 'lookupResources'>(ctx.kind);
    expectType<string>(ctx.callId);
    expectType<boolean>(ctx.enriched);
    return { ...ctx.args, subject: 'user:sally' };
  },
  afterRequest(ctx, summary) {
    expectType<boolean>(summary.success);
    expectType<true | undefined>(summary.enriched);
  },
  onError(error, ctx) {
    expectType<unknown>(error);
  },
};
const hookedResolver = new RelationResolver({
  schema: schemaShape,
  hooks: resolverHooks,
  hooksTimeoutMs: 100,
  maxListeners: 20,
});
// @ts-expect-error — per-resource hooks do not exist on the resolver.
new RelationResolver({ schema: schemaShape, hooks: { beforeResource() {} } });

expectType<RelationResolver>(
  hookedResolver
    .on('relation:checked', (event) => {
      expectType<RelationCheckedEvent>(event);
      expectType<boolean>(event.allowed);
    })
    .once('cache:miss', (event) => expectType<'relation'>(event.kind))
    .removeAllListeners(),
);
// @ts-expect-error — engine-only event names are rejected on the resolver.
hookedResolver.on('decision', () => {});
