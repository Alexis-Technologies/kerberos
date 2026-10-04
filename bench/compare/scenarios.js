/**
 * The scenarios of the cross-library comparison, written once in a neutral
 * shape (Kerberos's own request shape, which is also Cerbos's). Every adapter
 * translates them into its library's idiom OUTSIDE the timed loop and must
 * reproduce the expected decisions before anything is measured.
 */

const RULE_COUNT = 1_000;
const BATCH_SIZE = 100;

const owner = { id: 'u1', roles: ['USER'] };
const stranger = { id: 'u2', roles: ['USER'] };
const guest = { id: 'g1', roles: ['GUEST'] };

const post = { kind: 'post', id: 'p1', attr: {} };
const ownedDocument = { kind: 'document', id: 'd1', attr: { ownerId: 'u1' } };
const report = { kind: 'report', id: 'r1', attr: {} };

// Every second document belongs to the owner, the rest to someone else.
const documents = [];
const ownedIds = [];
for (let i = 0; i < BATCH_SIZE; i++) {
  const ownerId = i % 2 === 0 ? 'u1' : 'u3';
  documents.push({ kind: 'document', id: `d${i}`, attr: { ownerId } });
  if (ownerId === 'u1') ownedIds.push(`d${i}`);
}

const ruleActions = [];
for (let i = 0; i < RULE_COUNT; i++) ruleActions.push(`act${i}`);

/**
 * `type: 'check'` scenarios time one decision on the `allow` request and verify
 * both requests first; `type: 'batch'` scenarios time one call that returns the
 * ids of the documents the principal may view.
 */
const SCENARIOS = [
  {
    id: 'rbac',
    title: 'Role check',
    description: 'A USER may view a post. One rule, no condition.',
    type: 'check',
    unit: 'ops/s',
    allow: { principal: owner, resource: post, action: 'view' },
    deny: { principal: guest, resource: post, action: 'view' },
  },
  {
    id: 'abac',
    title: 'Ownership condition',
    description: 'A USER may view a document they own: one role-gated rule with an attribute condition.',
    type: 'check',
    unit: 'ops/s',
    allow: { principal: owner, resource: ownedDocument, action: 'view' },
    deny: { principal: stranger, resource: ownedDocument, action: 'view' },
  },
  {
    id: 'rules',
    title: '1,000 rules',
    description: `${RULE_COUNT.toLocaleString('en-US')} rules, one action each; the request matches the last one.`,
    type: 'check',
    unit: 'ops/s',
    ruleActions,
    allow: { principal: owner, resource: report, action: ruleActions[RULE_COUNT - 1] },
    deny: { principal: owner, resource: report, action: `act${RULE_COUNT}` },
  },
  {
    id: 'batch',
    title: `Filter ${BATCH_SIZE} documents`,
    description: `The ownership rule over a list of ${BATCH_SIZE} documents, half of them owned: one call returns the visible ids.`,
    type: 'batch',
    unit: 'batches/s',
    action: 'view',
    resources: documents,
    allow: { principal: owner, expectedIds: ownedIds },
    deny: { principal: stranger, expectedIds: [] },
  },
];

function getScenario(id) {
  const scenario = SCENARIOS.find((candidate) => candidate.id === id);
  if (!scenario) throw new Error(`unknown scenario "${id}"`);
  return scenario;
}

module.exports = { SCENARIOS, getScenario, RULE_COUNT, BATCH_SIZE };
