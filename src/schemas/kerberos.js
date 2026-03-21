const { ResourcePolicy } = require('../ResourcePolicy/index.js');
const { DerivedRoles } = require('../DerivedRoles/index.js');
const { JsonSchemas, TypeBoxSchemas, ZodSchemas } = require('./index.js');

class KerberosZodSchemas extends ZodSchemas {
  static buildResourcePolicyInstance(z) {
    return z.instanceof(ResourcePolicy);
  }

  static buildDerivedRolesInstance(z) {
    return z.instanceof(DerivedRoles);
  }

  static buildIsAllowedArgs(z) {
    return z.object({
      principal: ZodSchemas.buildRequestPrincipal(z),
      action: z.string(),
      resource: ZodSchemas.buildRequestResource(z),
    });
  }

  static buildCheckResourcesArgs(z) {
    return z.object({
      reqId: z.string().optional(),
      principal: ZodSchemas.buildRequestPrincipal(z),
      resources: z
        .array(
          z.object({
            resource: ZodSchemas.buildRequestResource(z),
            actions: z.array(z.string()).nonempty(),
          })
        )
        .nonempty(),
      includeMeta: z.boolean().optional(),
    });
  }
}

class KerberosJsonSchemas extends JsonSchemas {
  static buildResourcePolicyInstance() {
    return JsonSchemas.buildInstanceOfShape(ResourcePolicy);
  }

  static buildDerivedRolesInstance() {
    return JsonSchemas.buildInstanceOfShape(DerivedRoles);
  }

  static buildIsAllowedArgs() {
    return JsonSchemas.buildObjectShape(
      {
        principal: JsonSchemas.buildRequestPrincipal(),
        action: { type: 'string' },
        resource: JsonSchemas.buildRequestResource(),
      },
      ['principal', 'action', 'resource']
    );
  }

  static buildCheckResourcesArgs() {
    return JsonSchemas.buildObjectShape(
      {
        reqId: { type: 'string' },
        principal: JsonSchemas.buildRequestPrincipal(),
        resources: JsonSchemas.buildNonEmptyArrayShape(
          JsonSchemas.buildObjectShape(
            {
              resource: JsonSchemas.buildRequestResource(),
              actions: JsonSchemas.buildNonEmptyArrayShape({ type: 'string' }),
            },
            ['resource', 'actions']
          )
        ),
        includeMeta: { type: 'boolean' },
      },
      ['principal', 'resources']
    );
  }
}

class KerberosTypeBoxSchemas extends TypeBoxSchemas {
  static buildResourcePolicyInstance(t) {
    return TypeBoxSchemas.buildInstanceOfShape(t, ResourcePolicy);
  }

  static buildDerivedRolesInstance(t) {
    return TypeBoxSchemas.buildInstanceOfShape(t, DerivedRoles);
  }

  static buildIsAllowedArgs(t) {
    return t.Object({
      principal: TypeBoxSchemas.buildRequestPrincipal(t),
      action: t.String(),
      resource: TypeBoxSchemas.buildRequestResource(t),
    });
  }

  static buildCheckResourcesArgs(t) {
    return t.Object({
      reqId: t.Optional(t.String()),
      principal: TypeBoxSchemas.buildRequestPrincipal(t),
      resources: TypeBoxSchemas.buildNonEmptyArrayShape(
        t,
        t.Object({
          resource: TypeBoxSchemas.buildRequestResource(t),
          actions: TypeBoxSchemas.buildNonEmptyArrayShape(t, t.String()),
        })
      ),
      includeMeta: t.Optional(t.Boolean()),
    });
  }
}

module.exports = {
  KerberosJsonSchemas,
  KerberosTypeBoxSchemas,
  KerberosZodSchemas,
};
