const ALL_ACTIONS = '*';

const Effect = {
  Allow: 'EFFECT_ALLOW',
  Deny: 'EFFECT_DENY',
};

class ZodSchemas {
  static buildRequestPrincipal(z) {
    return z.object({
      id: z.string(),
      roles: z.array(z.string()).nonempty(),
      attr: z.record(z.string(), z.unknown()).optional(),
    });
  }

  static buildRequestResource(z) {
    return z.object({
      id: z.string(),
      kind: z.string(),
      attr: z.record(z.string(), z.unknown()).optional(),
    });
  }

  static buildRequest(z) {
    return z.object({
      principal: ZodSchemas.buildRequestPrincipal(z),
      resource: ZodSchemas.buildRequestResource(z),
      P: ZodSchemas.buildRequestPrincipal(z),
      R: ZodSchemas.buildRequestResource(z),
    });
  }
}

module.exports = {
  ZodSchemas,
  ALL_ACTIONS,
  Effect,
};
