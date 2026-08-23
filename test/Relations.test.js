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

describe('RelationResolver', () => {
  const { RelationResolver } = require('../src/Relations/index.js');

  function buildResolver(extra = {}) {
    return new RelationResolver({ schema: buildSchemaShape(), tuples: buildStaticTuples(), ...extra });
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

    it('surfaces a throwing caveat as a typed error instead of reading it as "not matched"', async () => {
      // An evaluation ERROR is not a "no": in an exclusion subtract position a
      // swallowed caveat error would silently WIDEN access.
      const throwing = new RelationResolver({
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

      await assert.rejects(
        () => throwing.check({ resource: 'doc:d1', relation: 'viewer', subject: 'user:u1' }),
        (error) => error instanceof KerberosRelationsError && /Caveat "boom" threw/.test(error.message),
      );
    });
  });

  describe('depth guard', () => {
    it('throws a typed error on cyclic relationship data', async () => {
      const relations = new RelationResolver({
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

    it('surfaces a corrupt document as KerberosCodecError instead of treating it as empty', async () => {
      // "Corrupt = empty" would silently widen access in exclusion subtract
      // positions; a data error is never read as an answer. Absence (miss)
      // still resolves as empty.
      const { KerberosCodecError } = require('../src/index.js');
      const errors = [];
      const cache = buildCache({
        'rel:document:bad:viewer': { nope: true },
        'rel:document:partial:viewer': ['user:ok', 'garbage-without-type'],
      });
      const relations = buildResolver({
        cache,
        logger: { debug() {}, error: (entry) => errors.push(entry) },
      });

      await assert.rejects(
        () => relations.check({ resource: 'document:bad', permission: 'view', subject: 'user:carl' }),
        (error) => error instanceof KerberosCodecError && /Corrupt relation document/.test(error.message),
      );
      // One unparseable entry poisons the whole document deterministically.
      await assert.rejects(
        () => relations.check({ resource: 'document:partial', permission: 'view', subject: 'user:ok' }),
        (error) => error instanceof KerberosCodecError,
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

    it('evicts rejected reads from a shared memo so callers recover after a transient failure', async () => {
      // A rejected singleflight promise must not stay poisoned in a shared
      // memo: the README invites callers to reuse one memo across calls, and a
      // single transient backend blip would otherwise re-throw forever.
      const { KerberosCacheError } = require('../src/index.js');
      let failures = 1;
      const cache = {
        async get(key) {
          if (failures > 0) {
            failures--;
            throw new Error('ECONNRESET');
          }
          return key === 'rel:document:flaky:viewer' ? ['user:carl'] : undefined;
        },
      };
      const relations = buildResolver({ cache, cacheRetry: { attempts: 1 } });
      const memo = new Map();

      await assert.rejects(
        () => relations.check({ resource: 'document:flaky', permission: 'view', subject: 'user:carl' }, { memo }),
        (error) => error instanceof KerberosCacheError,
      );
      // Same shared memo after the backend recovered: the read retries and succeeds.
      assert.equal(
        await relations.check({ resource: 'document:flaky', permission: 'view', subject: 'user:carl' }, { memo }),
        true,
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
      const wildcardResolver = new RelationResolver({
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
  const { RelationResolver } = require('../src/Relations/index.js');

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
      const relations = new RelationResolver({ schema: buildSchemaShape(), tuples: buildStaticTuples() });
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
      const relations = new RelationResolver({ schema: buildSchemaShape(), cache });
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
      const relations = new RelationResolver({ schema: jsonSchema, cache, codec });
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

describe('RelationResolver telemetry', () => {
  const { RelationResolver } = require('../src/Relations/index.js');

  // Minimal fake OTel tracer/meter capturing spans, counters and histograms.
  function buildFakeTelemetry() {
    const counters = {};
    const histograms = {};
    const spans = [];
    const meter = {
      createCounter(name) {
        counters[name] = [];
        return { add: (value, attributes) => counters[name].push({ value, attributes }) };
      },
      createHistogram(name) {
        histograms[name] = [];
        return { record: (value, attributes) => histograms[name].push({ value, attributes }) };
      },
    };
    const tracer = {
      startActiveSpan(name, options, fn) {
        const span = {
          name,
          attributes: { ...(options?.attributes ?? {}) },
          ended: false,
          setAttribute(key, value) {
            this.attributes[key] = value;
          },
          addEvent() {},
          recordException() {},
          setStatus(status) {
            this.status = status;
          },
          end() {
            this.ended = true;
          },
        };
        spans.push(span);
        return fn(span);
      },
    };
    return { telemetry: { tracer, meter }, counters, histograms, spans };
  }

  it('emits a span, the relations counter and the duration histogram for check', async () => {
    const fake = buildFakeTelemetry();
    const relations = new RelationResolver({
      schema: buildSchemaShape(),
      tuples: buildStaticTuples(),
      telemetry: fake.telemetry,
    });

    assert.equal(
      await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:olga' }),
      true,
    );

    assert.equal(fake.spans.length, 1);
    const span = fake.spans[0];
    assert.equal(span.name, 'Kerberos.relations.check');
    assert.equal(span.attributes['kerberos.resource.kind'], 'document');
    assert.equal(span.attributes['kerberos.relations.name'], 'view');
    assert.equal(span.attributes['kerberos.allowed'], true);
    // Identity attributes are on by default.
    assert.equal(span.attributes['kerberos.relations.subject'], 'user:olga');
    assert.equal(span.attributes['kerberos.resource.id'], 'readme');
    assert.equal(span.ended, true);

    assert.deepEqual(fake.counters['kerberos.relations.checks'], [
      { value: 1, attributes: { 'kerberos.relations.result': 'allow' } },
    ]);
    assert.equal(fake.histograms['kerberos.request.duration'].length, 1);
    assert.equal(fake.histograms['kerberos.request.duration'][0].attributes['kerberos.req_kind'], 'RelationsCheck');
  });

  it('strips identity attributes with includeIdentity: false', async () => {
    const fake = buildFakeTelemetry();
    const relations = new RelationResolver({
      schema: buildSchemaShape(),
      tuples: buildStaticTuples(),
      telemetry: { ...fake.telemetry, includeIdentity: false },
    });

    await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:olga' });

    const span = fake.spans[0];
    assert.equal(span.attributes['kerberos.relations.subject'], undefined);
    assert.equal(span.attributes['kerberos.resource.id'], undefined);
    assert.equal(span.attributes['kerberos.resource.kind'], 'document');
  });

  it('counts one relations check per list name and annotates the span', async () => {
    const fake = buildFakeTelemetry();
    const relations = new RelationResolver({
      schema: buildSchemaShape(),
      tuples: buildStaticTuples(),
      telemetry: fake.telemetry,
    });

    const granted = await relations.list({
      resource: { kind: 'document', id: 'readme' },
      principal: { id: 'olga', roles: ['USER'] },
      relations: ['view', 'edit', 'audit'],
    });
    assert.deepEqual([...granted].sort(), ['edit', 'view']);

    const results = [];
    for (const entry of fake.counters['kerberos.relations.checks']) {
      results.push(entry.attributes['kerberos.relations.result']);
    }
    assert.deepEqual(results.sort(), ['allow', 'allow', 'deny']);

    const span = fake.spans[0];
    assert.equal(span.name, 'Kerberos.relations.list');
    assert.equal(span.attributes['kerberos.relations.requested'], 3);
    assert.equal(span.attributes['kerberos.relations.granted'], 2);
  });

  it('records relation cache reads with the relation kind attribute', async () => {
    const fake = buildFakeTelemetry();
    const relations = new RelationResolver({
      schema: buildSchemaShape(),
      cache: {
        async get(key) {
          if (key === 'rel:document:cached:viewer') return ['user:carl'];
          return undefined;
        },
      },
      telemetry: fake.telemetry,
    });

    assert.equal(
      await relations.check({ resource: 'document:cached', permission: 'view', subject: 'user:carl' }),
      true,
    );

    const cacheRecords = fake.counters['kerberos.cache.requests'];
    assert.ok(cacheRecords.length >= 2);
    for (const record of cacheRecords) {
      assert.equal(record.attributes['kerberos.cache.kind'], 'relation');
    }
    const outcomes = new Set();
    for (const record of cacheRecords) outcomes.add(record.attributes['kerberos.cache.result']);
    assert.ok(outcomes.has('hit'));
    assert.ok(outcomes.has('miss'));
  });

  it('annotates lookup spans with the result count', async () => {
    const fake = buildFakeTelemetry();
    const relations = new RelationResolver({
      schema: buildSchemaShape(),
      tuples: buildStaticTuples(),
      telemetry: fake.telemetry,
    });

    const subjects = await relations.lookupSubjects({ resource: 'document:readme', permission: 'audit' });
    assert.deepEqual(subjects, ['user:vera']);
    assert.equal(fake.spans[0].name, 'Kerberos.relations.lookupSubjects');
    assert.equal(fake.spans[0].attributes['kerberos.result.count'], 1);

    const resources = await relations.lookupResources({
      subject: 'user:rita',
      permission: 'view',
      resourceType: 'folder',
    });
    assert.deepEqual(resources, ['folder:docs', 'folder:root']);
    assert.equal(fake.spans[1].name, 'Kerberos.relations.lookupResources');
    assert.equal(fake.spans[1].attributes['kerberos.result.count'], 2);
  });

  it('never lets a broken tracer or meter affect resolution', async () => {
    const throwingTelemetry = {
      tracer: {
        startActiveSpan() {
          throw new Error('tracer boom');
        },
      },
      meter: {
        createCounter() {
          return {
            add() {
              throw new Error('meter boom');
            },
          };
        },
        createHistogram() {
          return {
            record() {
              throw new Error('meter boom');
            },
          };
        },
      },
    };
    const relations = new RelationResolver({
      schema: buildSchemaShape(),
      tuples: buildStaticTuples(),
      telemetry: throwingTelemetry,
    });

    assert.equal(
      await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:olga' }),
      true,
    );
    assert.equal(
      await relations.check({ resource: 'document:readme', permission: 'view', subject: 'user:ghost' }),
      false,
    );
  });
});

describe('RelationResolver parallel error propagation', () => {
  const { RelationResolver } = require('../src/Relations/index.js');
  const { KerberosCacheError } = require('../src/index.js');

  it('surfaces the first failure from a settled verification wave', async () => {
    // Exclusion forces candidate verification; the editor document read fails
    // with a transient error — the wave settles fully, then the typed cache
    // error surfaces instead of silently reading as "not granted".
    const relations = new RelationResolver({
      schema: buildSchemaShape(),
      cache: {
        async get(key) {
          if (key === 'rel:rev:user:eve') return [{ resource: 'document:d1', relation: 'viewer' }];
          if (key === 'rel:document:d1:viewer') return ['user:eve'];
          if (key === 'rel:document:d1:editor') throw new Error('ECONNRESET');
          return undefined;
        },
      },
      cacheRetry: { attempts: 1 },
      reverseIndex: true,
    });

    await assert.rejects(
      () => relations.lookupResources({ subject: 'user:eve', permission: 'read_only', resourceType: 'document' }),
      (error) => error instanceof KerberosCacheError,
    );
  });

  it('keeps concurrent lookups over a shared memo correct', async () => {
    const relations = new RelationResolver({ schema: buildSchemaShape(), tuples: buildStaticTuples() });
    const memo = new Map();

    const [saraDocs, ritaDocs, subjects] = await Promise.all([
      relations.lookupResources({ subject: 'user:sara', permission: 'view', resourceType: 'document' }, { memo }),
      relations.lookupResources({ subject: 'user:rita', permission: 'view', resourceType: 'document' }, { memo }),
      relations.lookupSubjects({ resource: 'document:readme', permission: 'view' }, { memo }),
    ]);

    assert.deepEqual(saraDocs, ['document:public', 'document:readme']);
    assert.deepEqual(ritaDocs, ['document:public', 'document:readme']);
    assert.ok(subjects.includes('user:sara') && subjects.includes('user:rita'));
  });
});

describe('RelationResolver code-review regressions', () => {
  const { RelationResolver } = require('../src/Relations/index.js');
  const { KerberosCodecError } = require('../src/index.js');

  describe('decision-memo scoping (R1)', () => {
    it('never replays a caveated decision for a different principal on a shared memo', async () => {
      const relations = new RelationResolver({ schema: buildSchemaShape(), tuples: buildStaticTuples() });
      const memo = new Map();

      // cara is a caveated editor (valid_ip via written context 10.0.0.1).
      assert.equal(
        await relations.check(
          {
            resource: 'document:readme',
            permission: 'edit',
            subject: 'user:cara',
            principal: { id: 'cara', roles: ['USER'], attr: { ip: '10.0.0.1' } },
          },
          { memo },
        ),
        true,
      );
      // Same memo, different principal object (wrong ip) — must re-evaluate.
      assert.equal(
        await relations.check(
          {
            resource: 'document:readme',
            permission: 'edit',
            subject: 'user:cara',
            principal: { id: 'cara', roles: ['USER'], attr: { ip: '8.8.8.8' } },
          },
          { memo },
        ),
        false,
      );
    });

    it('never replays decisions across two resolver instances sharing one memo', async () => {
      const schemaA = {
        relationSchema: {
          definitions: { user: {}, doc: { relations: { viewer: ['user'] }, permissions: { view: 'viewer' } } },
        },
      };
      const schemaB = {
        relationSchema: {
          definitions: { user: {}, doc: { relations: { viewer: ['user'] }, permissions: { view: 'viewer' } } },
        },
      };
      const tenantA = new RelationResolver({ schema: schemaA, tuples: ['doc:d1#viewer@user:sara'] });
      const tenantB = new RelationResolver({ schema: schemaB, tuples: [] });
      const memo = new Map();

      assert.equal(
        await tenantA.check({ resource: 'doc:d1', permission: 'view', subject: 'user:sara' }, { memo }),
        true,
      );
      // Identical key strings, different tenant — must NOT leak tenant A's decision.
      assert.equal(
        await tenantB.check({ resource: 'doc:d1', permission: 'view', subject: 'user:sara' }, { memo }),
        false,
      );
    });

    it('still shares decisions when the same principal object is reused (engine batch pattern)', async () => {
      let caveatEvaluations = 0;
      const relations = new RelationResolver({
        schema: {
          relationSchema: {
            caveats: {
              counted: {
                match: () => {
                  caveatEvaluations += 1;
                  return true;
                },
              },
            },
            definitions: {
              user: {},
              doc: { relations: { viewer: [{ type: 'user', caveat: 'counted' }] }, permissions: { view: 'viewer' } },
            },
          },
        },
        tuples: [{ resource: 'doc:d1', relation: 'viewer', subject: 'user:sara', caveat: { name: 'counted' } }],
      });
      const memo = new Map();
      const principal = { id: 'sara', roles: ['USER'] };

      assert.equal(
        await relations.check({ resource: 'doc:d1', permission: 'view', subject: 'user:sara', principal }, { memo }),
        true,
      );
      assert.equal(
        await relations.check({ resource: 'doc:d1', permission: 'view', subject: 'user:sara', principal }, { memo }),
        true,
      );
      // Same object reference → same identity token → memo hit, one evaluation.
      assert.equal(caveatEvaluations, 1);
    });
  });

  describe('exclusion does not corrupt the memoized base set (R2)', () => {
    it('keeps the memoized viewer set intact after a subtracting lookup', async () => {
      const relations = new RelationResolver({
        schema: {
          relationSchema: {
            definitions: {
              user: {},
              doc: {
                relations: { viewer: ['user', 'user:*'], blocked: ['user'] },
                permissions: {
                  can_read: { exclude: { base: 'viewer', subtract: ['blocked'] } },
                  all_viewers: { anyOf: ['viewer'] },
                },
              },
            },
          },
        },
        tuples: ['doc:d1#viewer@user:*', 'doc:d1#blocked@user:anne'],
      });
      const memo = new Map();

      assert.deepEqual(await relations.lookupSubjects({ resource: 'doc:d1', permission: 'can_read' }, { memo }), [
        { subject: 'user:*', exclusions: ['user:anne'] },
      ]);
      // The same memo must still hold the UNCORRUPTED viewer set: anne IS a viewer.
      assert.deepEqual(await relations.lookupSubjects({ resource: 'doc:d1', permission: 'all_viewers' }, { memo }), [
        'user:*',
      ]);
    });
  });

  describe('permission-typed subject refs are rejected at compile (R3)', () => {
    it('throws with a hint when a subject relation references a permission', () => {
      assert.throws(
        () =>
          new RelationResolver({
            schema: {
              relationSchema: {
                definitions: {
                  user: {},
                  group: { relations: { member: ['user'] }, permissions: { admin: 'member' } },
                  document: { relations: { viewer: ['user', 'group#admin'] }, permissions: { view: 'viewer' } },
                },
              },
            },
          }),
        (error) =>
          error instanceof KerberosRelationsError &&
          /subject relations must reference a relation, not a permission/.test(error.message),
      );
    });
  });

  describe('"|" is a reserved name character (R4)', () => {
    it('rejects names containing the admission-key delimiter', () => {
      assert.throws(
        () => new RelationSchema({ relationSchema: { definitions: { 'a|b': {} } } }),
        /Invalid definition name/,
      );
      assert.throws(
        () =>
          new RelationSchema({
            relationSchema: { definitions: { user: {}, doc: { relations: { 'b|c': ['user'] } } } },
          }),
        /Invalid relation name/,
      );
    });
  });

  describe('errors are never read as an answer in subtract positions (R6)', () => {
    it('rejects instead of granting read_only when the editor document is corrupt', async () => {
      const relations = new RelationResolver({
        schema: buildSchemaShape(),
        cache: {
          async get(key) {
            if (key === 'rel:document:d1:viewer') return ['user:eve'];
            if (key === 'rel:document:d1:editor') return { corrupt: true };
            return undefined;
          },
        },
      });

      // eve IS an editor whose document is corrupt — silently treating it as
      // empty would grant her read_only (viewer − editor). It must throw.
      await assert.rejects(
        () => relations.check({ resource: 'document:d1', permission: 'read_only', subject: 'user:eve' }),
        (error) => error instanceof KerberosCodecError,
      );
    });

    it('rejects instead of widening access when a subtrahend caveat throws', async () => {
      const relations = new RelationResolver({
        schema: {
          relationSchema: {
            caveats: {
              boom: {
                match: () => {
                  throw new Error('boom');
                },
              },
            },
            definitions: {
              user: {},
              doc: {
                relations: { viewer: ['user'], blocked: [{ type: 'user', caveat: 'boom' }] },
                permissions: { can_read: { exclude: { base: 'viewer', subtract: ['blocked'] } } },
              },
            },
          },
        },
        tuples: [
          'doc:d1#viewer@user:eve',
          { resource: 'doc:d1', relation: 'blocked', subject: 'user:eve', caveat: { name: 'boom' } },
        ],
      });

      await assert.rejects(
        () => relations.check({ resource: 'doc:d1', permission: 'can_read', subject: 'user:eve' }),
        (error) => error instanceof KerberosRelationsError && /threw during evaluation/.test(error.message),
      );
    });

    it('rejects on corrupt reverse documents instead of narrowing the reverse index', async () => {
      const relations = new RelationResolver({
        schema: buildSchemaShape(),
        cache: {
          async get(key) {
            if (key === 'rel:rev:user:sara') return { corrupt: true };
            return undefined;
          },
        },
        reverseIndex: true,
      });

      await assert.rejects(
        () => relations.lookupResources({ subject: 'user:sara', permission: 'view', resourceType: 'document' }),
        (error) => error instanceof KerberosCodecError && /Corrupt reverse document/.test(error.message),
      );
    });
  });
});

describe('RelationResolver contract hardening', () => {
  const { RelationResolver } = require('../src/Relations/index.js');
  const { Effect, Kerberos } = require('../src/index.js');

  it('compiled schema getters return copies and frozen structures (R5)', () => {
    const schema = new RelationSchema(buildSchemaShape());

    // Mutating the introspection copies must not affect the compiled schema.
    schema.definitions.get('document').permissions.set('view', { kind: 'ref', name: 'owner' });
    schema.caveats.delete('valid_ip');
    assert.equal(schema.getPermissionNode('document', 'view').kind, 'union');
    assert.ok(schema.getCaveat('valid_ip'));

    // Refs and rewrite nodes are frozen.
    assert.ok(Object.isFrozen(schema.getRelationSubjects('document', 'viewer')));
    assert.ok(Object.isFrozen(schema.getRelationSubjects('document', 'viewer')[0]));
    assert.ok(Object.isFrozen(schema.getPermissionNode('document', 'view')));
    assert.ok(Object.isFrozen(schema.getPermissionNode('document', 'view').children));
  });

  it('validates list arguments through a configured backend (M1)', async () => {
    const { z } = require('zod');
    const relations = new RelationResolver({ schema: buildSchemaShape(), tuples: buildStaticTuples(), z });

    await assert.rejects(
      () => relations.list({ resource: 'document:readme', subject: 'user:olga', relations: [42] }),
      (error) => error instanceof KerberosRelationsError && /Invalid list arguments/.test(error.message),
    );
  });

  it('records argument errors on the telemetry span (M2)', async () => {
    const spans = [];
    const relations = new RelationResolver({
      schema: buildSchemaShape(),
      telemetry: {
        tracer: {
          startActiveSpan(name, options, fn) {
            const span = {
              name,
              status: null,
              exceptions: [],
              setAttribute() {},
              addEvent() {},
              recordException(error) {
                this.exceptions.push(error);
              },
              setStatus(status) {
                this.status = status;
              },
              end() {},
            };
            spans.push(span);
            return fn(span);
          },
        },
      },
    });

    await assert.rejects(() => relations.check({ resource: 'document:readme', subject: 'user:olga' }));
    assert.equal(spans.length, 1);
    assert.equal(spans[0].status?.code, 2);
    assert.equal(spans[0].exceptions.length, 1);
  });

  it('rejects ambiguous object-form ids and wildcard principal ids (M3)', async () => {
    const relations = new RelationResolver({ schema: buildSchemaShape(), tuples: buildStaticTuples() });

    await assert.rejects(
      () => relations.check({ resource: { kind: 'document', id: 'a#b' }, relation: 'view', subject: 'user:olga' }),
      /ids must not contain ":" or "#"/,
    );
    await assert.rejects(
      () => relations.check({ resource: { kind: 'doc:ument', id: 'a' }, relation: 'view', subject: 'user:olga' }),
      /kinds must not contain/,
    );
    await assert.rejects(
      () =>
        relations.check({
          resource: { kind: 'document', id: 'readme' },
          relation: 'view',
          principal: { id: '*', roles: ['USER'] },
        }),
      /Invalid principal id/,
    );
  });

  it('rejects direct self-referencing permissions at compile (M4)', () => {
    assert.throws(
      () =>
        new RelationSchema({
          relationSchema: {
            definitions: {
              user: {},
              doc: { relations: { viewer: ['user'] }, permissions: { view: { anyOf: ['view', 'viewer'] } } },
            },
          },
        }),
      /directly references itself/,
    );
  });

  it('protects tuple written context from mutating caveats (M5)', async () => {
    const writtenContext = { allowed: true };
    const relations = new RelationResolver({
      schema: {
        relationSchema: {
          caveats: {
            mutator: {
              match: ({ ctx }) => {
                const verdict = ctx.allowed === true;
                ctx.allowed = false; // attempts to poison the stored context
                return verdict;
              },
            },
          },
          definitions: {
            user: {},
            doc: { relations: { viewer: [{ type: 'user', caveat: 'mutator' }] } },
          },
        },
      },
      tuples: [
        {
          resource: 'doc:d1',
          relation: 'viewer',
          subject: 'user:u1',
          caveat: { name: 'mutator', context: writtenContext },
        },
      ],
    });

    assert.equal(await relations.check({ resource: 'doc:d1', relation: 'viewer', subject: 'user:u1' }), true);
    // Second evaluation still sees the original written context.
    assert.equal(await relations.check({ resource: 'doc:d1', relation: 'viewer', subject: 'user:u1' }), true);
    assert.equal(writtenContext.allowed, true);
  });

  it('omits concrete subjects covered by an unexcluded wildcard (M6)', async () => {
    const relations = new RelationResolver({
      schema: {
        relationSchema: {
          definitions: {
            user: {},
            doc: { relations: { viewer: ['user', 'user:*'] }, permissions: { view: 'viewer' } },
          },
        },
      },
      tuples: ['doc:d1#viewer@user:*', 'doc:d1#viewer@user:alice'],
    });

    assert.deepEqual(await relations.lookupSubjects({ resource: 'doc:d1', permission: 'view' }), ['user:*']);
  });

  it('keeps actionsSet/allowActionsSet out of serialized policy shapes (M7)', async () => {
    const { ResourcePolicy, RolePolicy } = require('../src/index.js');
    const resourcePolicy = new ResourcePolicy({
      resourcePolicy: {
        version: 'default',
        resource: 'expense',
        rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
      },
    });
    const rolePolicy = new RolePolicy({
      rolePolicy: { role: 'USER', version: 'default', rules: [{ resource: 'expense', allowActions: ['view'] }] },
    });

    assert.equal(JSON.stringify(resourcePolicy.shape).includes('actionsSet'), false);
    assert.equal(JSON.stringify(rolePolicy.shape).includes('allowActionsSet'), false);
    // The hot-path Sets still exist as non-enumerable fields.
    assert.ok(resourcePolicy.rules[0].actionsSet instanceof Set);
    assert.ok(rolePolicy.rules[0].allowActionsSet instanceof Set);

    // And evaluation still works.
    const kerberos = new Kerberos(
      [
        {
          resourcePolicy: {
            version: 'default',
            resource: 'expense',
            rules: [{ actions: ['view'], effect: Effect.Allow, roles: ['USER'] }],
          },
        },
      ],
      [],
    );
    assert.equal(
      await kerberos.isAllowed({
        principal: { id: 'u', roles: ['USER'] },
        action: 'view',
        resource: { id: 'e1', kind: 'expense' },
      }),
      true,
    );
  });
});

describe('RelationResolver lookup edge cases', () => {
  const { RelationResolver } = require('../src/Relations/index.js');

  it('truncates lookupSubjects deterministically at maxResults', async () => {
    const relations = new RelationResolver({
      schema: {
        relationSchema: {
          definitions: { user: {}, doc: { relations: { viewer: ['user'] }, permissions: { view: 'viewer' } } },
        },
      },
      tuples: ['doc:d1#viewer@user:a', 'doc:d1#viewer@user:b', 'doc:d1#viewer@user:c'],
      maxResults: 2,
    });

    assert.deepEqual(await relations.lookupSubjects({ resource: 'doc:d1', permission: 'view' }), ['user:a', 'user:b']);
  });

  it('filters by subjectType including wildcard entries', async () => {
    const relations = new RelationResolver({
      schema: {
        relationSchema: {
          definitions: {
            user: {},
            bot: {},
            doc: { relations: { viewer: ['user', 'bot', 'user:*'] }, permissions: { view: 'viewer' } },
          },
        },
      },
      tuples: ['doc:d1#viewer@user:*', 'doc:d1#viewer@bot:crawler'],
    });

    assert.deepEqual(await relations.lookupSubjects({ resource: 'doc:d1', permission: 'view', subjectType: 'bot' }), [
      'bot:crawler',
    ]);
    assert.deepEqual(await relations.lookupSubjects({ resource: 'doc:d1', permission: 'view', subjectType: 'user' }), [
      'user:*',
    ]);
  });

  it('handles duplicate names in list()', async () => {
    const relations = new RelationResolver({ schema: buildSchemaShape(), tuples: buildStaticTuples() });

    const granted = await relations.list({
      resource: 'document:readme',
      subject: 'user:olga',
      relations: ['view', 'view', 'edit'],
    });
    assert.deepEqual([...granted].sort(), ['edit', 'view']);
  });
});
