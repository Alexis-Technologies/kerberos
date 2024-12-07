import { z } from 'zod';

export const RequestPrincipalSchema = z.object({
  id: z.string(),
  roles: z.array(z.string()).nonempty(),
  attr: z.record(z.string(), z.unknown()),
});

export const RequestResourceSchema = z.object({
  id: z.string(),
  kind: z.string(),
  attr: z.record(z.string(), z.unknown()),
});

export const RequestSchema = z
  .object({
    principal: RequestPrincipalSchema,
    resource: RequestResourceSchema,
    P: RequestPrincipalSchema,
    R: RequestResourceSchema,
  });

export const ALL_ACTIONS = '*';

export const Effect = {
  Allow: 'EFFECT_ALLOW',
  Deny: 'EFFECT_DENY',
};
