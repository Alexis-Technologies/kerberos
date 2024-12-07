const { z } = require('zod');

const RequestPrincipalSchema = z.object({
  id: z.string(),
  roles: z.array(z.string()).nonempty(),
  attr: z.record(z.string(), z.unknown()).optional(),
});

const RequestResourceSchema = z.object({
  id: z.string(),
  kind: z.string(),
  attr: z.record(z.string(), z.unknown()).optional(),
});

const RequestSchema = z.object({
  principal: RequestPrincipalSchema,
  resource: RequestResourceSchema,
  P: RequestPrincipalSchema,
  R: RequestResourceSchema,
});

const ALL_ACTIONS = '*';

const Effect = {
  Allow: 'EFFECT_ALLOW',
  Deny: 'EFFECT_DENY',
};

module.exports = {
  RequestPrincipalSchema,
  RequestResourceSchema,
  RequestSchema,
  ALL_ACTIONS,
  Effect,
};
