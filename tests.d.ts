import type {
  Effect,
  Kerberos,
  RequestPrincipal,
  RequestResource,
  TypeBoxLike,
  ValidationOptions,
} from '@alexify/kerberos';

export type PrincipalMockSchema = RequestPrincipal & { name: string };
export class PrincipalMock {
  constructor(schema: PrincipalMockSchema, options?: ValidationOptions);
  get id(): string;
  get name(): string;
  get roles(): string[];
  get attr(): Record<string, unknown> | undefined;
  get policyVersion(): string | undefined;
  get scope(): string | undefined;
}
export class PrincipalMockZodSchemas {
  static buildShape(z: unknown): unknown;
}
export class PrincipalMockJsonSchemas {
  static buildShape(): Record<string, unknown>;
}
export class PrincipalMockTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
}

export type PrincipalsMockSchema =
  | [PrincipalMock, ...PrincipalMock[]]
  | Record<string, Omit<PrincipalMockSchema, 'name'>>;
export class PrincipalsMock {
  constructor(schemas: PrincipalsMockSchema, options?: ValidationOptions);
  get mocks(): PrincipalMock[];
  get(name: string): PrincipalMock | undefined;
}
export class PrincipalsMockZodSchemas {
  static buildShape(z: unknown, PrincipalMock: typeof PrincipalMock): unknown;
}
export class PrincipalsMockJsonSchemas {
  static buildShape(PrincipalMock: typeof PrincipalMock): Record<string, unknown>;
}
export class PrincipalsMockTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike, PrincipalMock: typeof PrincipalMock): unknown;
}

export type ResourceMockSchema = RequestResource & { name: string };
export class ResourceMock {
  constructor(schema: ResourceMockSchema, options?: ValidationOptions);
  get id(): string;
  get name(): string;
  get kind(): string;
  get attr(): Record<string, unknown> | undefined;
  get policyVersion(): string | undefined;
  get scope(): string | undefined;
}
export class ResourceMockZodSchemas {
  static buildShape(z: unknown): unknown;
}
export class ResourceMockJsonSchemas {
  static buildShape(): Record<string, unknown>;
}
export class ResourceMockTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
}

export type ResourcesMockSchema =
  | [ResourceMock, ...ResourceMock[]]
  | Record<string, Omit<ResourceMockSchema, 'name'>>;
export class ResourcesMock {
  constructor(schemas: ResourcesMockSchema, options?: ValidationOptions);
  get mocks(): ResourceMock[];
  get(name: string): ResourceMock | undefined;
  getById(id: string): ResourceMock | undefined;
}
export class ResourcesMockZodSchemas {
  static buildShape(z: unknown, ResourceMock: typeof ResourceMock): unknown;
}
export class ResourcesMockJsonSchemas {
  static buildShape(ResourceMock: typeof ResourceMock): Record<string, unknown>;
}
export class ResourcesMockTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike, ResourceMock: typeof ResourceMock): unknown;
}

export type Describe = (name: string, fn: () => void) => void;
export type It = (name: string, fn: () => void) => void;
export type Assert = {
  ok(value: unknown, message?: string): void;
  strictEqual(actual: unknown, expected: unknown, message?: string): void;
};

export type KerberosTestInputSchema = {
  principals: PrincipalsMock | string[];
  resources: ResourcesMock | string[];
  actions: string[];
};
export type KerberosTestExpectedItemSchema = {
  principal: PrincipalMock | string;
  resource: ResourceMock | string;
  actions: Record<string, Effect | boolean>;
};
export type KerberosTestSchema = {
  name: string;
  input: KerberosTestInputSchema;
  expected: KerberosTestExpectedItemSchema[];
};
export class KerberosTest {
  constructor(schema: KerberosTestSchema, kerberos?: Kerberos, options?: ValidationOptions);
  run(
    {
      kerberos,
      principals,
      resources,
      effectAsBoolean,
    }: {
      kerberos?: Kerberos;
      principals?: PrincipalsMock[];
      resources?: ResourcesMock[];
      effectAsBoolean?: boolean;
    },
    { describe, it, assert }: { describe: Describe; it: It; assert: Assert },
  ): void;
}
export class KerberosTestZodSchemas {
  static buildShape(z: unknown): unknown;
}
export class KerberosTestJsonSchemas {
  static buildShape(): Record<string, unknown>;
}
export class KerberosTestTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike): unknown;
}

export type TestsPolicySchema = {
  name: string;
  principals: PrincipalsMock | PrincipalsMockSchema;
  resources: ResourcesMock | ResourcesMockSchema;
  tests: KerberosTest[] | KerberosTestSchema[];
};
export class KerberosTests {
  constructor(kerberos: Kerberos, policies: [TestsPolicySchema, ...TestsPolicySchema[]], options?: ValidationOptions);
  run(
    { effectAsBoolean }: { effectAsBoolean?: boolean },
    { describe, it, assert }: { describe: Describe; it: It; assert: Assert },
  ): void;
}
export class KerberosTestsZodSchemas {
  static buildShape(z: unknown, KerberosTest: typeof KerberosTest): unknown;
}
export class KerberosTestsJsonSchemas {
  static buildShape(KerberosTest: typeof KerberosTest): Record<string, unknown>;
}
export class KerberosTestsTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike, KerberosTest: typeof KerberosTest): unknown;
}
