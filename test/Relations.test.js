const { describe, it } = require('node:test');
const assert = require('node:assert').strict;

const { RelationSchema, parseObjectRef, parseSubjectRef, parseTuple } = require('../src/Relations/index.js');
const { createSafeExprCodec } = require('../src/caching/codec.js');
const { KerberosRelationsError } = require('../src/errors.js');

// Shared jsep instance — configured once with all plugins for the test suite.
const jsepModule = require('jsep');
const jsep = jsepModule.default || jsepModule;
jsep.plugins.register(require('@jsep-plugin/object'), require('@jsep-plugin/ternary'), require('@jsep-plugin/new'));

// The canonical folder/document/group example used across the suite.
function buildSchemaShape() {
  return {
    relationSchema: {
      caveats: {
        valid_ip: { match: ({ P, ctx }) => (ctx.allowed_ips ?? []).includes(P?.attr?.ip) },
      },
      definitions: {
        user: {},
        group: { relations: { member: ['user', 'group#member'] } },
        folder: {
          relations: { parent: ['folder'], viewer: ['user', 'group#member'] },
          permissions: { view: { anyOf: ['viewer', { via: 'parent', permission: 'view' }] } },
        },
        document: {
          relations: {
            parent: ['folder'],
            owner: ['user'],
            editor: ['user', { type: 'user', caveat: 'valid_ip' }],
            viewer: ['user', 'user:*', 'group#member'],
            auditor: ['user'],
          },
          permissions: {
            edit: { anyOf: ['owner', 'editor'] },
            view: { anyOf: ['edit', 'viewer', { via: 'parent', permission: 'view' }] },
            audit: { allOf: ['viewer', 'auditor'] },
            read_only: { exclude: { base: 'viewer', subtract: ['editor'] } },
            review_all: { via: 'parent', permission: 'view', all: true },
          },
        },
      },
    },
  };
}

describe('RelationSchema', () => {
  describe('compilation', () => {
    it('compiles the full example schema into rewrite nodes', () => {
      const schema = new RelationSchema(buildSchemaShape());

      assert.ok(schema.hasDefinition('document'));
      assert.ok(schema.isCheckable('document', 'view'));
      assert.ok(schema.isCheckable('document', 'viewer'));
      assert.equal(schema.isCheckable('document', 'missing'), false);
      assert.equal(schema.isCheckable('missing', 'view'), false);

      const view = schema.getPermissionNode('document', 'view');
      assert.equal(view.kind, 'union');
      assert.equal(view.children.length, 3);
      assert.deepEqual(view.children[0], { kind: 'ref', name: 'edit' });
      assert.deepEqual(view.children[2], { kind: 'arrow', via: 'parent', target: 'view', all: false });

      const audit = schema.getPermissionNode('document', 'audit');
      assert.equal(audit.kind, 'intersection');

      const readOnly = schema.getPermissionNode('document', 'read_only');
      assert.equal(readOnly.kind, 'exclusion');
      assert.deepEqual(readOnly.base, { kind: 'ref', name: 'viewer' });
      assert.equal(readOnly.subtract.length, 1);

      const reviewAll = schema.getPermissionNode('document', 'review_all');
      assert.deepEqual(reviewAll, { kind: 'arrow', via: 'parent', target: 'view', all: true });

      const viewerSubjects = schema.getRelationSubjects('document', 'viewer');
      assert.deepEqual(viewerSubjects, [
        { type: 'user', relation: null, wildcard: false, caveat: null },
        { type: 'user', relation: null, wildcard: true, caveat: null },
        { type: 'group', relation: 'member', wildcard: false, caveat: null },
      ]);

      const editorSubjects = schema.getRelationSubjects('document', 'editor');
      assert.deepEqual(editorSubjects[1], { type: 'user', relation: null, wildcard: false, caveat: 'valid_ip' });

      assert.ok(schema.getCaveat('valid_ip'));
    });

    it('supports recursive schemas (folder parent folder)', () => {
      const schema = new RelationSchema(buildSchemaShape());
      const folderView = schema.getPermissionNode('folder', 'view');
      assert.deepEqual(folderView.children[1], { kind: 'arrow', via: 'parent', target: 'view', all: false });
    });
  });

  describe('compile-time failures', () => {
    function withDefinitions(definitions) {
      return { relationSchema: { definitions } };
    }

    it('throws when a name is declared as both relation and permission', () => {
      assert.throws(
        () =>
          new RelationSchema(
            withDefinitions({
              user: {},
              doc: { relations: { view: ['user'] }, permissions: { view: 'view' } },
            }),
          ),
        (error) => error instanceof KerberosRelationsError && /both a relation and a permission/.test(error.message),
      );
    });

    it('throws on a subject type referencing an unknown definition', () => {
      assert.throws(
        () => new RelationSchema(withDefinitions({ doc: { relations: { viewer: ['ghost'] } } })),
        /unknown definition "ghost"/,
      );
    });

    it('throws on an unknown subject relation', () => {
      assert.throws(
        () => new RelationSchema(withDefinitions({ user: {}, doc: { relations: { viewer: ['user#member'] } } })),
        /unknown subject relation "user#member"/,
      );
    });

    it('throws on an unknown caveat reference', () => {
      assert.throws(
        () =>
          new RelationSchema(
            withDefinitions({ user: {}, doc: { relations: { viewer: [{ type: 'user', caveat: 'ghost' }] } } }),
          ),
        /unknown caveat "ghost"/,
      );
    });

    it('throws on a permission referencing an unknown name', () => {
      assert.throws(
        () => new RelationSchema(withDefinitions({ user: {}, doc: { permissions: { view: 'ghost' } } })),
        /unknown relation or permission "ghost"/,
      );
    });

    it('throws on an arrow via a permission instead of a relation', () => {
      assert.throws(
        () =>
          new RelationSchema(
            withDefinitions({
              user: {},
              folder: { relations: { viewer: ['user'] }, permissions: { view: 'viewer' } },
              doc: {
                relations: { parent: ['folder'] },
                permissions: {
                  reparent: { anyOf: ['parent'] },
                  view: { via: 'reparent', permission: 'view' },
                },
              },
            }),
          ),
        /arrow "via" must reference a relation/,
      );
    });

    it('throws on an arrow through a relation with wildcard subjects', () => {
      assert.throws(
        () =>
          new RelationSchema(
            withDefinitions({
              user: {},
              folder: { relations: { viewer: ['user'] }, permissions: { view: 'viewer' } },
              doc: {
                relations: { parent: ['folder:*'] },
                permissions: { view: { via: 'parent', permission: 'view' } },
              },
            }),
          ),
        /no wildcards or subject relations/,
      );
    });

    it('throws on an arrow through a relation with subject-relation subjects', () => {
      assert.throws(
        () =>
          new RelationSchema(
            withDefinitions({
              user: {},
              group: { relations: { member: ['user'] } },
              doc: {
                relations: { parent: ['group#member'] },
                permissions: { view: { via: 'parent', permission: 'member' } },
              },
            }),
          ),
        /no wildcards or subject relations/,
      );
    });

    it('throws when an arrow target is missing on a reached type', () => {
      assert.throws(
        () =>
          new RelationSchema(
            withDefinitions({
              user: {},
              folder: { relations: { viewer: ['user'] } },
              doc: {
                relations: { parent: ['folder'] },
                permissions: { view: { via: 'parent', permission: 'view' } },
              },
            }),
          ),
        /arrow target "view" does not exist on "folder"/,
      );
    });

    it('throws when an expression mixes operators', () => {
      assert.throws(
        () =>
          new RelationSchema(
            withDefinitions({
              user: {},
              doc: { relations: { a: ['user'], b: ['user'] }, permissions: { p: { anyOf: ['a'], allOf: ['b'] } } },
            }),
          ),
        /exactly one of "via", "anyOf", "allOf" or "exclude"/,
      );
    });

    it('throws on an empty operator array', () => {
      assert.throws(
        () => new RelationSchema(withDefinitions({ user: {}, doc: { permissions: { p: { anyOf: [] } } } })),
        /"anyOf" must be a non-empty array/,
      );
    });

    it('throws on reserved characters in names', () => {
      assert.throws(() => new RelationSchema(withDefinitions({ 'doc:x': {} })), /Invalid definition name/);
      assert.throws(
        () => new RelationSchema(withDefinitions({ user: {}, doc: { relations: { 'vie#w': ['user'] } } })),
        /Invalid relation name/,
      );
    });

    it('throws on an empty definitions object', () => {
      assert.throws(() => new RelationSchema(withDefinitions({})), /at least one definition/);
      assert.throws(() => new RelationSchema({ relationSchema: {} }), /definitions must be a non-empty object/);
      assert.throws(() => new RelationSchema({}), /must define a "relationSchema" object/);
    });
  });

  describe('caveats', () => {
    it('throws when a caveat has no match', () => {
      assert.throws(
        () => new RelationSchema({ relationSchema: { caveats: { c: {} }, definitions: { user: {} } } }),
        /Caveat "c" must define a "match" condition/,
      );
    });

    it('throws when an { $expr } caveat is used without a codec', () => {
      assert.throws(
        () =>
          new RelationSchema({
            relationSchema: {
              caveats: { c: { match: { $expr: 'ctx.tier === "pro"' } } },
              definitions: { user: {} },
            },
          }),
        /provide a codec/,
      );
    });

    it('compiles an { $expr } caveat through the safe codec', () => {
      const codec = createSafeExprCodec({ jsep, roots: ['P', 'ctx'] });
      const schema = new RelationSchema(
        {
          relationSchema: {
            caveats: { pro_tier: { match: { $expr: 'ctx.tier === "pro"' } } },
            definitions: { user: {} },
          },
        },
        { codec },
      );

      const caveat = schema.getCaveat('pro_tier');
      assert.equal(caveat.isFulfilled({ ctx: { tier: 'pro' } }), true);
      assert.equal(caveat.isFulfilled({ ctx: { tier: 'free' } }), false);
    });

    it('wraps codec failures in KerberosRelationsError', () => {
      const codec = createSafeExprCodec({ jsep, roots: ['P', 'ctx'] });
      assert.throws(
        () =>
          new RelationSchema(
            {
              relationSchema: {
                // A syntax error fails eagerly at compile (identifier
                // allowlisting happens later, at evaluation time).
                caveats: { bad: { match: { $expr: 'ctx.tier ===' } } },
                definitions: { user: {} },
              },
            },
            { codec },
          ),
        (error) => error instanceof KerberosRelationsError && /Failed to compile caveat "bad"/.test(error.message),
      );
    });
  });

  describe('reference parsing', () => {
    it('parses object refs', () => {
      assert.deepEqual(parseObjectRef('document:readme'), { type: 'document', id: 'readme' });
      assert.throws(() => parseObjectRef('document'), /expected "type:id"/);
      assert.throws(() => parseObjectRef(':x'), /expected "type:id"/);
      assert.throws(() => parseObjectRef('document:'), /expected "type:id"/);
      assert.throws(() => parseObjectRef(42), /expected a "type:id" string/);
    });

    it('parses subject refs including wildcards and usersets', () => {
      assert.deepEqual(parseSubjectRef('user:emilia'), { type: 'user', id: 'emilia', relation: null });
      assert.deepEqual(parseSubjectRef('user:*'), { type: 'user', id: '*', relation: null });
      assert.deepEqual(parseSubjectRef('group:eng#member'), { type: 'group', id: 'eng', relation: 'member' });
      assert.throws(() => parseSubjectRef('group:eng#'), /empty subject relation/);
      assert.throws(() => parseSubjectRef('user:*#member'), /wildcard subject cannot have a relation/);
    });

    it('parses canonical tuple strings', () => {
      assert.deepEqual(parseTuple('document:readme#viewer@user:emilia'), {
        resource: { type: 'document', id: 'readme' },
        relation: 'viewer',
        subject: { type: 'user', id: 'emilia', relation: null },
        caveat: null,
      });

      // Userset subjects keep their inner '#'; subject ids may contain '@'.
      assert.deepEqual(parseTuple('document:readme#viewer@group:eng#member').subject, {
        type: 'group',
        id: 'eng',
        relation: 'member',
      });
      assert.deepEqual(parseTuple('document:readme#viewer@user:bob@mail.com').subject, {
        type: 'user',
        id: 'bob@mail.com',
        relation: null,
      });

      assert.throws(() => parseTuple('document:readme#viewer'), /Invalid tuple/);
      assert.throws(() => parseTuple('document:readme@user:emilia'), /Invalid tuple/);
    });

    it('parses object tuples with caveats', () => {
      assert.deepEqual(
        parseTuple({
          resource: 'document:readme',
          relation: 'editor',
          subject: 'user:bob',
          caveat: { name: 'valid_ip', context: { allowed_ips: ['10.0.0.1'] } },
        }),
        {
          resource: { type: 'document', id: 'readme' },
          relation: 'editor',
          subject: { type: 'user', id: 'bob', relation: null },
          caveat: { name: 'valid_ip', context: { allowed_ips: ['10.0.0.1'] } },
        },
      );

      assert.throws(
        () => parseTuple({ resource: 'document:readme', relation: 'editor', subject: 'user:bob', caveat: 'x' }),
        /Invalid tuple caveat/,
      );
      assert.throws(() => parseTuple(null), /Invalid tuple/);
    });
  });

  describe('validation backends', () => {
    it('accepts the example schema with Zod', () => {
      const { z } = require('zod');
      assert.ok(new RelationSchema(buildSchemaShape(), { z }));
    });

    it('rejects a malformed schema with Zod', () => {
      const { z } = require('zod');
      assert.throws(() => new RelationSchema({ relationSchema: { definitions: 'nope' } }, { z }));
    });

    it('accepts the example schema with JSON Schema + Ajv', () => {
      const Ajv = require('ajv');
      const { registerAjvKeywords } = require('../src/validation');
      const ajv = new Ajv({ allowUnionTypes: true });
      registerAjvKeywords(ajv);
      assert.ok(new RelationSchema(buildSchemaShape(), { ajv }));
    });

    it('accepts the example schema with TypeBox + Ajv', () => {
      const Ajv = require('ajv');
      const { registerAjvKeywords } = require('../src/validation');
      const t = require('@sinclair/typebox').Type;
      const ajv = new Ajv({ allowUnionTypes: true });
      registerAjvKeywords(ajv);
      assert.ok(new RelationSchema(buildSchemaShape(), { ajv, typebox: t }));
    });
  });
});

// Static tuple fixture exercising every algebra feature of the example schema.
function buildStaticTuples() {
  return [
    'document:readme#owner@user:olga',
    'document:readme#viewer@group:eng#member',
    'group:eng#member@user:sara',
    // Transitive membership: leads ⊂ eng.
    'group:eng#member@group:leads#member',
    'group:leads#member@user:lena',
    // Folder hierarchy: readme → docs → root.
    'document:readme#parent@folder:docs',
    'folder:docs#viewer@user:fay',
    'folder:docs#parent@folder:root',
    'folder:root#viewer@user:rita',
    // Wildcard.
    'document:public#viewer@user:*',
    // Caveated editor (object form).
    {
      resource: 'document:readme',
      relation: 'editor',
      subject: 'user:cara',
      caveat: { name: 'valid_ip', context: { allowed_ips: ['10.0.0.1'] } },
    },
    // Intersection (audit = viewer & auditor).
    'document:readme#viewer@user:vera',
    'document:readme#auditor@user:vera',
    // Exclusion (read_only = viewer - editor).
    'document:readme#viewer@user:pete',
    'document:readme#viewer@user:eve',
    'document:readme#editor@user:eve',
    // Intersection arrow (review_all = parent->view all).
    'document:multi#parent@folder:a',
    'document:multi#parent@folder:b',
    'folder:a#viewer@user:ann',
    'folder:b#viewer@user:ann',
    'folder:a#viewer@user:bob',
    'document:orphan#owner@user:olga',
  ];
}

describe('createRelationResolver', () => {
  const { createRelationResolver } = require('../src/Relations/index.js');

  function buildResolver(extra = {}) {
    return createRelationResolver({ schema: buildSchemaShape(), tuples: buildStaticTuples(), ...extra });
  }

  describe('check — static tuples', () => {
    const relations = buildResolver();

    it('checks direct relations', async () => {
      assert.equal(
        await relations.check({ resource: 'document:readme', relation: 'owner', subject: 'user:olga' }),
        true,
      );
      assert.equal(
        await relations.check({ resource: 'document:readme', relation: 'owner', subject: 'user:sara' }),
        false,
      );
    });

    it('evaluates unions with refs', async () => {
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'edit', subject: 'user:olga' }),
        true,
      );
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:olga' }),
        true,
      );
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:nobody' }),
        false,
      );
    });

    it('resolves userset subjects recursively (group in group)', async () => {
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:sara' }),
        true,
      );
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:lena' }),
        true,
      );
    });

    it('walks arrows through the folder hierarchy', async () => {
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:fay' }),
        true,
      );
      // Two arrow hops: document → folder:docs → folder:root.
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:rita' }),
        true,
      );
    });

    it('matches type-wide wildcards', async () => {
      assert.equal(
        await relations.check({ resource: 'document:public', permission: 'view', subject: 'user:anyone' }),
        true,
      );
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:anyone' }),
        false,
      );
    });

    it('evaluates intersections', async () => {
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'audit', subject: 'user:vera' }),
        true,
      );
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'audit', subject: 'user:sara' }),
        false,
      );
    });

    it('evaluates exclusions (order-sensitive)', async () => {
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'read_only', subject: 'user:pete' }),
        true,
      );
      assert.equal(
        await relations.check({ resource: 'document:readme', permission: 'read_only', subject: 'user:eve' }),
        false,
      );
    });

    it('evaluates intersection arrows (.all)', async () => {
      assert.equal(
        await relations.check({ resource: 'document:multi', permission: 'review_all', subject: 'user:ann' }),
        true,
      );
      assert.equal(
        await relations.check({ resource: 'document:multi', permission: 'review_all', subject: 'user:bob' }),
        false,
      );
      // Zero reached objects yield false for `.all`.
      assert.equal(
        await relations.check({ resource: 'document:orphan', permission: 'review_all', subject: 'user:olga' }),
        false,
      );
    });

    it('treats a userset subject as trivially containing itself', async () => {
      assert.equal(
        await relations.check({ resource: 'group:eng', relation: 'member', subject: 'group:eng#member' }),
        true,
      );
    });

    it('throws for unknown permissions and unknown resource types', async () => {
      await assert.rejects(
        () => relations.check({ resource: 'document:readme', permission: 'ghost', subject: 'user:olga' }),
        (error) => error instanceof KerberosRelationsError && /not a relation or permission/.test(error.message),
      );
      await assert.rejects(
        () => relations.check({ resource: 'widget:w1', permission: 'view', subject: 'user:olga' }),
        /not a relation or permission of "widget"/,
      );
      await assert.rejects(
        () => relations.check({ resource: 'document:readme', subject: 'user:olga' }),
        /requires a "relation" or "permission"/,
      );
      await assert.rejects(
        () => relations.check({ resource: 'document:readme', permission: 'view' }),
        /A subject is required/,
      );
    });
  });

  describe('caveats at check time', () => {
    const relations = buildResolver();

    it('grants a caveated tuple when the condition holds for the principal', async () => {
      assert.equal(
        await relations.check({
          resource: 'document:readme',
          permission: 'edit',
          subject: 'user:cara',
          principal: { id: 'cara', roles: ['USER'], attr: { ip: '10.0.0.1' } },
        }),
        true,
      );
      assert.equal(
        await relations.check({
          resource: 'document:readme',
          permission: 'edit',
          subject: 'user:cara',
          principal: { id: 'cara', roles: ['USER'], attr: { ip: '8.8.8.8' } },
        }),
        false,
      );
    });

    it('gives written (tuple) context precedence over check-time context', async () => {
      // Check-time context would allow 8.8.8.8, but the written context pins
      // allowed_ips to 10.0.0.1 — written wins on key collision.
      assert.equal(
        await relations.check({
          resource: 'document:readme',
          permission: 'edit',
          subject: 'user:cara',
          principal: { id: 'cara', roles: ['USER'], attr: { ip: '8.8.8.8' } },
          context: { allowed_ips: ['8.8.8.8'] },
        }),
        false,
      );
    });

    it('fails closed when a caveat condition throws', async () => {
      const throwing = createRelationResolver({
        schema: {
          relationSchema: {
            caveats: {
              boom: {
                match: () => {
                  throw new Error('caveat boom');
                },
              },
            },
            definitions: {
              user: {},
              doc: { relations: { viewer: [{ type: 'user', caveat: 'boom' }] } },
            },
          },
        },
        tuples: [{ resource: 'doc:d1', relation: 'viewer', subject: 'user:u1', caveat: { name: 'boom' } }],
      });

      assert.equal(await throwing.check({ resource: 'doc:d1', relation: 'viewer', subject: 'user:u1' }), false);
    });
  });

  describe('depth guard', () => {
    it('throws a typed error on cyclic relationship data', async () => {
      const relations = createRelationResolver({
        schema: buildSchemaShape(),
        tuples: ['group:a#member@group:b#member', 'group:b#member@group:a#member'],
        maxDepth: 5,
      });

      await assert.rejects(
        () => relations.check({ resource: 'group:a', relation: 'member', subject: 'user:ghost' }),
        (error) => error instanceof KerberosRelationsError && /maximum depth of 5/.test(error.message),
      );
    });
  });

  describe('static tuple validation', () => {
    it('rejects tuples on unknown relations', () => {
      assert.throws(
        () => buildResolver({ tuples: ['document:d#ghost@user:u'] }),
        /"ghost" is not a relation of "document"/,
      );
    });

    it('rejects subjects the schema does not admit', () => {
      // owner admits only plain users.
      assert.throws(
        () => buildResolver({ tuples: ['document:d#owner@group:eng#member'] }),
        /not allowed on "document#owner"/,
      );
      assert.throws(
        () => buildResolver({ tuples: ['document:d#viewer@folder:f'] }),
        /not allowed on "document#viewer"/,
      );
      // A caveat is only admitted where the schema declares it.
      assert.throws(
        () =>
          buildResolver({
            tuples: [{ resource: 'document:d', relation: 'owner', subject: 'user:u', caveat: { name: 'valid_ip' } }],
          }),
        /not allowed on "document#owner"/,
      );
    });

    it('rejects a non-array tuples option', () => {
      assert.throws(() => buildResolver({ tuples: 'document:d#owner@user:u' }), /"tuples" must be an array/);
    });
  });

  describe('cache-backed tuples', () => {
    function buildCache(docs) {
      const reads = [];
      return {
        reads,
        async get(key) {
          reads.push(key);
          return docs[key];
        },
      };
    }

    it('falls back to the cache on a static miss and honors schema admission', async () => {
      const cache = buildCache({
        'rel:document:cached:viewer': ['user:carl', 'group:eng#member', 'folder:not-admitted'],
        // The caveated ref is declared on `editor` — schema admission is
        // per-relation, so this entry belongs in the editor document.
        'rel:document:cached:editor': [
          { subject: 'user:dana', caveat: { name: 'valid_ip', context: { allowed_ips: ['10.0.0.1'] } } },
        ],
      });
      const relations = buildResolver({ cache });

      assert.equal(
        await relations.check({ resource: 'document:cached', permission: 'view', subject: 'user:carl' }),
        true,
      );
      // Static group tuples resolve the userset from the cached doc.
      assert.equal(
        await relations.check({ resource: 'document:cached', permission: 'view', subject: 'user:sara' }),
        true,
      );
      assert.equal(
        await relations.check({
          resource: 'document:cached',
          permission: 'view',
          subject: 'user:dana',
          principal: { id: 'dana', roles: ['USER'], attr: { ip: '10.0.0.1' } },
        }),
        true,
      );
      // The non-admitted entry is skipped, not fatal.
      assert.equal(
        await relations.check({ resource: 'document:cached', permission: 'view', subject: 'folder:not-admitted' }),
        false,
      );
    });

    it('parses JSON string documents', async () => {
      const cache = buildCache({ 'rel:document:jsonic:viewer': '["user:carl"]' });
      const relations = buildResolver({ cache });
      assert.equal(
        await relations.check({ resource: 'document:jsonic', permission: 'view', subject: 'user:carl' }),
        true,
      );
    });

    it('never reads the cache for keys the static index resolves', async () => {
      const cache = buildCache({});
      const relations = buildResolver({ cache });

      assert.equal(
        await relations.check({ resource: 'document:readme', relation: 'owner', subject: 'user:olga' }),
        true,
      );
      assert.deepEqual(cache.reads, []);
    });

    it('treats a corrupt document as empty instead of failing the check', async () => {
      const errors = [];
      const cache = buildCache({
        'rel:document:bad:viewer': { nope: true },
        'rel:document:partial:viewer': ['user:ok', 'garbage-without-type'],
      });
      const relations = buildResolver({
        cache,
        logger: { debug() {}, error: (entry) => errors.push(entry) },
      });

      assert.equal(
        await relations.check({ resource: 'document:bad', permission: 'view', subject: 'user:carl' }),
        false,
      );
      // One unparseable entry poisons the document deterministically — the
      // whole document resolves as empty (fail-closed).
      assert.equal(
        await relations.check({ resource: 'document:partial', permission: 'view', subject: 'user:ok' }),
        false,
      );
      assert.equal(errors.filter((entry) => entry.event === 'Relations.corruptDocument').length, 2);
    });

    it('propagates transient cache failures as KerberosCacheError', async () => {
      const { KerberosCacheError } = require('../src/index.js');
      const relations = buildResolver({
        cache: {
          async get() {
            throw new Error('ECONNRESET');
          },
        },
        cacheRetry: { attempts: 1 },
      });

      await assert.rejects(
        () => relations.check({ resource: 'document:cached', permission: 'view', subject: 'user:carl' }),
        (error) => error instanceof KerberosCacheError,
      );
    });

    it('shares document reads through the memo across list names', async () => {
      const cache = buildCache({ 'rel:document:shared:viewer': ['user:carl'] });
      const relations = buildResolver({ cache });

      const granted = await relations.list({
        resource: 'document:shared',
        subject: 'user:carl',
        relations: ['view', 'read_only'],
      });

      assert.deepEqual([...granted].sort(), ['read_only', 'view']);
      // `view` and `read_only` both need the viewer doc — one read via memo.
      assert.equal(cache.reads.filter((key) => key === 'rel:document:shared:viewer').length, 1);
    });
  });

  describe('engine contract adapter', () => {
    const relations = buildResolver();

    it('maps principal objects to subjects with the default subjectType', async () => {
      assert.equal(
        await relations.check({
          resource: { kind: 'document', id: 'readme' },
          relation: 'view',
          principal: { id: 'olga', roles: ['USER'] },
        }),
        true,
      );
    });

    it('lists granted relations with a shared session', async () => {
      const granted = await relations.list({
        resource: { kind: 'document', id: 'readme' },
        principal: { id: 'olga', roles: ['USER'] },
        relations: ['view', 'edit', 'audit'],
      });
      assert.deepEqual([...granted].sort(), ['edit', 'view']);
    });

    it('supports custom principal/resource mappers', async () => {
      const mapped = buildResolver({
        mapPrincipal: (principal) => `user:${principal.attr.username}`,
        mapResource: (resource) => `document:${resource.attr.slug}`,
      });

      assert.equal(
        await mapped.check({
          resource: { kind: 'ignored', id: 'ignored', attr: { slug: 'readme' } },
          relation: 'view',
          principal: { id: 'ignored', roles: ['USER'], attr: { username: 'olga' } },
        }),
        true,
      );
    });

    it('validates list arguments', async () => {
      await assert.rejects(
        () => relations.list({ resource: 'document:readme', subject: 'user:olga' }),
        /non-empty "relations" array/,
      );
      await assert.rejects(
        () => relations.list({ resource: 'document:readme', subject: 'user:olga', relations: ['ghost'] }),
        /not a relation or permission/,
      );
    });
  });

  describe('lookupSubjects', () => {
    const relations = buildResolver();

    it('expands the full permission tree to terminal subjects', async () => {
      const subjects = await relations.lookupSubjects({ resource: 'document:readme', permission: 'view' });
      assert.deepEqual(subjects, [
        'user:cara',
        'user:eve',
        'user:fay',
        'user:lena',
        'user:olga',
        'user:pete',
        'user:rita',
        'user:sara',
        'user:vera',
      ]);
    });

    it('returns wildcard entries', async () => {
      assert.deepEqual(await relations.lookupSubjects({ resource: 'document:public', permission: 'view' }), ['user:*']);
    });

    it('applies exclusions', async () => {
      // read_only = viewer - editor: cara and eve are editors (caveated
      // entries are treated as present — the result is an upper bound).
      const subjects = await relations.lookupSubjects({ resource: 'document:readme', permission: 'read_only' });
      assert.deepEqual(subjects, ['user:lena', 'user:pete', 'user:sara', 'user:vera']);
    });

    it('represents wildcard-with-exclusions results', async () => {
      const wildcardResolver = createRelationResolver({
        schema: {
          relationSchema: {
            definitions: {
              user: {},
              doc: {
                relations: { viewer: ['user', 'user:*'], blocked: ['user'] },
                permissions: { can_read: { exclude: { base: 'viewer', subtract: ['blocked'] } } },
              },
            },
          },
        },
        tuples: ['doc:d1#viewer@user:*', 'doc:d1#blocked@user:anne'],
      });

      assert.deepEqual(await wildcardResolver.lookupSubjects({ resource: 'doc:d1', permission: 'can_read' }), [
        { subject: 'user:*', exclusions: ['user:anne'] },
      ]);
    });

    it('intersects branches', async () => {
      assert.deepEqual(await relations.lookupSubjects({ resource: 'document:readme', permission: 'audit' }), [
        'user:vera',
      ]);
    });

    it('intersects across .all arrows', async () => {
      assert.deepEqual(await relations.lookupSubjects({ resource: 'document:multi', permission: 'review_all' }), [
        'user:ann',
      ]);
    });

    it('filters by subjectType', async () => {
      const subjects = await relations.lookupSubjects({
        resource: 'group:eng',
        relation: 'member',
        subjectType: 'user',
      });
      assert.deepEqual(subjects, ['user:lena', 'user:sara']);
    });
  });

  describe('lookupResources', () => {
    const relations = buildResolver();

    it('finds resources through direct tuples, groups and wildcards', async () => {
      assert.deepEqual(
        await relations.lookupResources({ subject: 'user:sara', permission: 'view', resourceType: 'document' }),
        ['document:public', 'document:readme'],
      );
      // lena reaches readme transitively (leads ⊂ eng).
      assert.deepEqual(
        await relations.lookupResources({ subject: 'user:lena', permission: 'view', resourceType: 'document' }),
        ['document:public', 'document:readme'],
      );
      // An unknown user still sees the wildcard document.
      assert.deepEqual(
        await relations.lookupResources({ subject: 'user:anyone', permission: 'view', resourceType: 'document' }),
        ['document:public'],
      );
    });

    it('walks arrows and recursive hierarchies', async () => {
      // rita is viewer of folder:root — reaches readme through two hops.
      assert.deepEqual(
        await relations.lookupResources({ subject: 'user:rita', permission: 'view', resourceType: 'document' }),
        ['document:public', 'document:readme'],
      );
      // Same-type recursion: root grants view on the whole folder subtree.
      assert.deepEqual(
        await relations.lookupResources({ subject: 'user:rita', permission: 'view', resourceType: 'folder' }),
        ['folder:docs', 'folder:root'],
      );
    });

    it('verifies candidates for exclusion and intersection paths', async () => {
      // Everyone is a wildcard viewer of document:public, so it is genuinely
      // read_only for pete and eve too.
      assert.deepEqual(
        await relations.lookupResources({ subject: 'user:pete', permission: 'read_only', resourceType: 'document' }),
        ['document:public', 'document:readme'],
      );
      // eve is an editor of readme — the exclusion removes that candidate.
      assert.deepEqual(
        await relations.lookupResources({ subject: 'user:eve', permission: 'read_only', resourceType: 'document' }),
        ['document:public'],
      );
      // .all arrow: ann views both parents, bob only one.
      assert.deepEqual(
        await relations.lookupResources({ subject: 'user:ann', permission: 'review_all', resourceType: 'document' }),
        ['document:multi'],
      );
      assert.deepEqual(
        await relations.lookupResources({ subject: 'user:bob', permission: 'review_all', resourceType: 'document' }),
        [],
      );
    });

    it('truncates to maxResults deterministically', async () => {
      const limited = buildResolver({ maxResults: 1 });
      assert.deepEqual(
        await limited.lookupResources({ subject: 'user:sara', permission: 'view', resourceType: 'document' }),
        ['document:public'],
      );
    });

    it('requires the reverse-index contract when a cache is configured', async () => {
      const cached = buildResolver({ cache: { async get() {} } });
      await assert.rejects(
        () => cached.lookupResources({ subject: 'user:sara', permission: 'view', resourceType: 'document' }),
        (error) => error instanceof KerberosRelationsError && /reverseIndex: true/.test(error.message),
      );
    });

    it('reads backend-maintained reverse documents when opted in', async () => {
      const docs = {
        'rel:rev:user:carl': [{ resource: 'document:cached', relation: 'viewer' }],
        'rel:document:cached:viewer': ['user:carl'],
      };
      const relationsWithReverse = buildResolver({
        cache: {
          async get(key) {
            return docs[key];
          },
        },
        reverseIndex: true,
      });

      // document:public comes from the static wildcard viewer tuple; the
      // cached document comes from the backend-maintained reverse document.
      assert.deepEqual(
        await relationsWithReverse.lookupResources({
          subject: 'user:carl',
          permission: 'view',
          resourceType: 'document',
        }),
        ['document:cached', 'document:public'],
      );
    });

    it('rejects unknown permissions', async () => {
      await assert.rejects(
        () => relations.lookupResources({ subject: 'user:sara', permission: 'ghost', resourceType: 'document' }),
        /not a relation or permission/,
      );
    });
  });

  describe('argument validation backends', () => {
    it('rejects malformed check args with Zod configured', async () => {
      const { z } = require('zod');
      const relations = buildResolver({ z });

      await assert.rejects(
        () => relations.check({ resource: 42, permission: 'view', subject: 'user:olga' }),
        (error) => error instanceof KerberosRelationsError && /Invalid check arguments/.test(error.message),
      );
    });
  });
});

describe('Kerberos relations integration', () => {
  const { Effect, Kerberos } = require('../src/index.js');
  const { createRelationResolver } = require('../src/Relations/index.js');

  const documentPolicy = {
    resourcePolicy: {
      version: 'default',
      resource: 'document',
      importDerivedRoles: ['doc_roles'],
      rules: [{ name: 'viewer-can-view', actions: ['view'], effect: Effect.Allow, derivedRoles: ['DOC_VIEWER'] }],
    },
  };

  const relationDerivedRoles = {
    name: 'doc_roles',
    definitions: [{ name: 'DOC_VIEWER', relation: 'view' }],
  };

  const olga = { id: 'olga', roles: ['USER'] };
  const readme = { id: 'readme', kind: 'document' };

  describe('custom relations resolver (delegation contract)', () => {
    it('activates relation-backed derived roles through check', async () => {
      const seen = [];
      const kerberos = new Kerberos([documentPolicy], [relationDerivedRoles], {
        relations: {
          async check({ principal, resource, relation }, { memo }) {
            seen.push({ principal: principal.id, resource: resource.id, relation, memoIsMap: memo instanceof Map });
            return principal.id === 'olga' && resource.id === 'readme' && relation === 'view';
          },
        },
      });

      assert.equal(await kerberos.isAllowed({ principal: olga, action: 'view', resource: readme }), true);
      assert.equal(
        await kerberos.isAllowed({ principal: { id: 'sam', roles: ['USER'] }, action: 'view', resource: readme }),
        false,
      );
      assert.deepEqual(seen[0], { principal: 'olga', resource: 'readme', relation: 'view', memoIsMap: true });
    });

    it('prefers list over check and passes the deduplicated relation names', async () => {
      const listCalls = [];
      let checkCalls = 0;
      const twoRoleDerived = {
        name: 'doc_roles',
        definitions: [
          { name: 'DOC_VIEWER', relation: 'view' },
          { name: 'DOC_SPECTATOR', relation: 'view' },
          { name: 'DOC_EDITOR', relation: 'edit' },
        ],
      };
      const kerberos = new Kerberos([documentPolicy], [twoRoleDerived], {
        relations: {
          async check() {
            checkCalls += 1;
            return false;
          },
          async list({ relations }) {
            listCalls.push(relations);
            return new Set(['view']);
          },
        },
      });

      assert.equal(await kerberos.isAllowed({ principal: olga, action: 'view', resource: readme }), true);
      assert.equal(checkCalls, 0);
      // 'view' appears in two definitions but is resolved once.
      assert.deepEqual(listCalls, [['view', 'edit']]);
    });

    it('applies parentRoles and condition as synchronous gates', async () => {
      const checked = [];
      const gatedDerived = {
        name: 'doc_roles',
        definitions: [
          {
            name: 'DOC_VIEWER',
            relation: 'view',
            parentRoles: ['EMPLOYEE'],
            condition: { match: ({ R }) => R.attr?.classified !== true },
          },
        ],
      };
      const kerberos = new Kerberos([documentPolicy], [gatedDerived], {
        relations: {
          async check({ relation }) {
            checked.push(relation);
            return true;
          },
        },
      });

      // Gate fails on roles: the resolver is never called.
      assert.equal(await kerberos.isAllowed({ principal: olga, action: 'view', resource: readme }), false);
      assert.equal(checked.length, 0);

      const employee = { id: 'olga', roles: ['EMPLOYEE'] };
      assert.equal(await kerberos.isAllowed({ principal: employee, action: 'view', resource: readme }), true);
      assert.equal(checked.length, 1);

      // Gate fails on the condition: the resolver is not called either.
      assert.equal(
        await kerberos.isAllowed({
          principal: employee,
          action: 'view',
          resource: { ...readme, attr: { classified: true } },
        }),
        false,
      );
      assert.equal(checked.length, 1);
    });

    it('records relation resolution in the decision trace with includeMeta', async () => {
      const kerberos = new Kerberos([documentPolicy], [relationDerivedRoles], {
        relations: {
          async check() {
            return true;
          },
        },
      });

      const response = await kerberos.checkResources({
        principal: olga,
        resources: [{ resource: readme, actions: ['view'] }],
        includeMeta: true,
      });

      const relationEntries = response.results[0].meta.resolution.filter((entry) => entry.source === 'relations');
      assert.deepEqual(relationEntries, [{ source: 'relations', name: 'DOC_VIEWER', relation: 'view', matched: true }]);
      assert.deepEqual(response.results[0].meta.effectiveDerivedRoles, ['DOC_VIEWER']);
    });

    it('traces unresolvable relation-backed roles when no resolver is configured', async () => {
      const kerberos = new Kerberos([documentPolicy], [relationDerivedRoles], {});

      assert.equal(await kerberos.isAllowed({ principal: olga, action: 'view', resource: readme }), false);

      const response = await kerberos.checkResources({
        principal: olga,
        resources: [{ resource: readme, actions: ['view'] }],
        includeMeta: true,
      });
      const relationEntries = response.results[0].meta.resolution.filter((entry) => entry.source === 'relations');
      assert.deepEqual(relationEntries, [
        { source: 'relations', name: 'DOC_VIEWER', relation: 'view', matched: false, reason: 'no-relations-resolver' },
      ]);
    });

    it('follows onError semantics when the resolver fails', async () => {
      const failing = {
        async check() {
          throw new Error('relations backend down');
        },
      };

      const throwing = new Kerberos([documentPolicy], [relationDerivedRoles], { relations: failing });
      await assert.rejects(
        () => throwing.isAllowed({ principal: olga, action: 'view', resource: readme }),
        /relations backend down/,
      );

      const denying = new Kerberos([documentPolicy], [relationDerivedRoles], {
        relations: failing,
        onError: 'deny',
      });
      assert.equal(await denying.isAllowed({ principal: olga, action: 'view', resource: readme }), false);
    });

    it('isolates a failing resource inside a batch', async () => {
      const kerberos = new Kerberos([documentPolicy], [relationDerivedRoles], {
        relations: {
          async check({ resource }) {
            if (resource.id === 'poison') throw new Error('resolver boom');
            return true;
          },
        },
      });

      const response = await kerberos.checkResources({
        principal: olga,
        resources: [
          { resource: { id: 'poison', kind: 'document' }, actions: ['view'] },
          { resource: readme, actions: ['view'] },
        ],
      });

      assert.equal(response.results[0].actions.view, 'EFFECT_DENY');
      assert.equal(response.results[1].actions.view, 'EFFECT_ALLOW');
    });

    it('rejects a relations option without a check method', () => {
      assert.throws(() => new Kerberos([], [], { relations: {} }), /Invalid relations option/);
    });

    it('keeps classic engines working when derived roles mix condition- and relation-backed definitions', async () => {
      const mixedDerived = {
        name: 'doc_roles',
        definitions: [
          { name: 'DOC_VIEWER', relation: 'view' },
          { name: 'OWNER', parentRoles: ['USER'], condition: { match: ({ P, R }) => R.attr?.ownerId === P.id } },
        ],
      };
      const mixedPolicy = {
        resourcePolicy: {
          version: 'default',
          resource: 'document',
          importDerivedRoles: ['doc_roles'],
          rules: [{ actions: ['view'], effect: Effect.Allow, derivedRoles: ['DOC_VIEWER', 'OWNER'] }],
        },
      };

      // No relations resolver: the condition-backed OWNER still works and the
      // relation-backed definition is simply inert.
      const kerberos = new Kerberos([mixedPolicy], [mixedDerived], {});
      assert.equal(
        await kerberos.isAllowed({
          principal: olga,
          action: 'view',
          resource: { ...readme, attr: { ownerId: 'olga' } },
        }),
        true,
      );
      assert.equal(await kerberos.isAllowed({ principal: olga, action: 'view', resource: readme }), false);
    });
  });

  describe('built-in resolver end to end', () => {
    it('authorizes through static tuples', async () => {
      const relations = createRelationResolver({ schema: buildSchemaShape(), tuples: buildStaticTuples() });
      const kerberos = new Kerberos([documentPolicy], [relationDerivedRoles], { relations });

      assert.equal(await kerberos.isAllowed({ principal: olga, action: 'view', resource: readme }), true);
      // sara views through group:eng membership; lena transitively.
      assert.equal(
        await kerberos.isAllowed({ principal: { id: 'sara', roles: ['USER'] }, action: 'view', resource: readme }),
        true,
      );
      assert.equal(
        await kerberos.isAllowed({ principal: { id: 'lena', roles: ['USER'] }, action: 'view', resource: readme }),
        true,
      );
      assert.equal(
        await kerberos.isAllowed({ principal: { id: 'ghost', roles: ['USER'] }, action: 'view', resource: readme }),
        false,
      );
    });

    it('shares relation subproblems across a batch through the memo', async () => {
      const reads = [];
      const cache = {
        async get(key) {
          reads.push(key);
          if (key === 'rel:group:eng:member') return ['user:sara'];
          if (key.startsWith('rel:document:') && key.endsWith(':viewer')) return ['group:eng#member'];
          return undefined;
        },
      };
      const relations = createRelationResolver({ schema: buildSchemaShape(), cache });
      const kerberos = new Kerberos([documentPolicy], [relationDerivedRoles], { relations });

      const response = await kerberos.checkResources({
        principal: { id: 'sara', roles: ['USER'] },
        resources: [
          { resource: { id: 'doc1', kind: 'document' }, actions: ['view'] },
          { resource: { id: 'doc2', kind: 'document' }, actions: ['view'] },
        ],
      });

      assert.equal(response.results[0].actions.view, 'EFFECT_ALLOW');
      assert.equal(response.results[1].actions.view, 'EFFECT_ALLOW');
      // The group membership document is read once for the whole batch.
      assert.equal(reads.filter((key) => key === 'rel:group:eng:member').length, 1);
    });

    it('authorizes cache-backed tuples with an { $expr } caveat end to end', async () => {
      const codec = createSafeExprCodec({ jsep, roots: ['P', 'ctx'] });
      const jsonSchema = {
        relationSchema: {
          caveats: { pro_tier: { match: { $expr: 'ctx.tier === "pro" && P.attr.plan === ctx.tier' } } },
          definitions: {
            user: {},
            document: {
              relations: { viewer: [{ type: 'user', caveat: 'pro_tier' }] },
              permissions: { view: { anyOf: ['viewer'] } },
            },
          },
        },
      };
      const cache = {
        async get(key) {
          if (key === 'rel:document:readme:viewer') {
            return [{ subject: 'user:olga', caveat: { name: 'pro_tier', context: { tier: 'pro' } } }];
          }
          return undefined;
        },
      };
      const relations = createRelationResolver({ schema: jsonSchema, cache, codec });
      const kerberos = new Kerberos([documentPolicy], [relationDerivedRoles], { relations });

      assert.equal(
        await kerberos.isAllowed({
          principal: { id: 'olga', roles: ['USER'], attr: { plan: 'pro' } },
          action: 'view',
          resource: readme,
        }),
        true,
      );
      assert.equal(
        await kerberos.isAllowed({
          principal: { id: 'olga', roles: ['USER'], attr: { plan: 'free' } },
          action: 'view',
          resource: readme,
        }),
        false,
      );
    });
  });
});
