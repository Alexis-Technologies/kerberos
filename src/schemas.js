const ALL_ACTIONS = '*';

const Effect = {
  Allow: 'EFFECT_ALLOW',
  Deny: 'EFFECT_DENY',
};

class ZodSchemas {
  static buildScopeString(z) {
    return z.string().regex(/^[a-zA-Z0-9._-]*$/, 'Scope must contain only alphanumeric characters, dots, hyphens and underscores');
  }

  static buildRequestPrincipal(z) {
    return z.object({
      id: z.string(),
      policyVersion: z.string().optional(),
      scope: ZodSchemas.buildScopeString(z).optional(),
      roles: z.array(z.string()).nonempty(),
      attr: z.record(z.string(), z.unknown()).optional(),
    });
  }

  static buildRequestResource(z) {
    return z.object({
      id: z.string(),
      kind: z.string(),
      policyVersion: z.string().optional(),
      scope: ZodSchemas.buildScopeString(z).optional(),
      attr: z.record(z.string(), z.unknown()).optional(),
    });
  }

  static buildRequest(z) {
    return z.object({
      principal: ZodSchemas.buildRequestPrincipal(z),
      resource: ZodSchemas.buildRequestResource(z),
      P: ZodSchemas.buildRequestPrincipal(z),
      R: ZodSchemas.buildRequestResource(z),
      actions: z.array(z.string()).nonempty(),
      reqId: z.string().optional(),
      callId: z.string().optional(),
      includeMeta: z.boolean().optional(),
    });
  }
}

module.exports = {
  ZodSchemas,
  ALL_ACTIONS,
  Effect,
};
