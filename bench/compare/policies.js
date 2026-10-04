/**
 * Policy sources for the out-of-JavaScript engines, generated from the same
 * scenario definitions the adapters use, so the 1 000-rule case cannot drift
 * from RULE_COUNT. Rego targets OPA 1.x (v1 syntax: `if`, `contains`, `in`).
 */
const { getScenario } = require('./scenarios.js');

/** OPA entrypoints, one per scenario (`rbac`/`abac`/`rules` → boolean, `batch` → set of ids). */
const OPA_ENTRYPOINTS = {
  rbac: 'authz/rbac/allow',
  abac: 'authz/abac/allow',
  rules: 'authz/rules/allow',
  batch: 'authz/batch/allowed',
};

function regoModules() {
  const rules = getScenario('rules').ruleActions.map(
    (action) =>
      `allow if {\n\tinput.action == "${action}"\n\tinput.resource.kind == "report"\n\t"USER" in input.principal.roles\n}`,
  );
  return {
    'rbac.rego': `package authz.rbac

allow if {
\tinput.action == "view"
\tinput.resource.kind == "post"
\t"USER" in input.principal.roles
}
`,
    'abac.rego': `package authz.abac

allow if {
\tinput.action == "view"
\tinput.resource.kind == "document"
\t"USER" in input.principal.roles
\tinput.resource.attr.ownerId == input.principal.id
}
`,
    // One Rego rule per policy rule: OPA's rule indexer narrows them by the
    // \`input.action ==\` equality, which is the most favourable layout for OPA.
    'rules.rego': `package authz.rules\n\n${rules.join('\n\n')}\n`,
    'batch.rego': `package authz.batch

allowed contains resource.id if {
\t"USER" in input.principal.roles
\tsome resource in input.resources
\tresource.kind == "document"
\tresource.attr.ownerId == input.principal.id
}
`,
  };
}

function cerbosPolicies() {
  const rules = getScenario('rules')
    .ruleActions.map((action) => `    - actions: ["${action}"]\n      effect: EFFECT_ALLOW\n      roles: ["USER"]`)
    .join('\n');
  return {
    'post.yaml': `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: post
  rules:
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["USER"]
`,
    'document.yaml': `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: document
  rules:
    - actions: ["view"]
      effect: EFFECT_ALLOW
      roles: ["USER"]
      condition:
        match:
          expr: request.resource.attr.ownerId == request.principal.id
`,
    'report.yaml': `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: report
  rules:
${rules}
`,
  };
}

module.exports = { OPA_ENTRYPOINTS, regoModules, cerbosPolicies };
