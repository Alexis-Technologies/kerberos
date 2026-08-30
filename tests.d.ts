import type {
  Effect,
  Kerberos,
  RequestPrincipal,
  RequestResource,
  TypeBoxLike,
  ValidationOptions,
} from './index.js';

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
  static buildShape(z: unknown, principalMockClass: typeof PrincipalMock): unknown;
}
export class PrincipalsMockJsonSchemas {
  static buildShape(principalMockClass: typeof PrincipalMock): Record<string, unknown>;
}
export class PrincipalsMockTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike, principalMockClass: typeof PrincipalMock): unknown;
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
  static buildShape(z: unknown, resourceMockClass: typeof ResourceMock): unknown;
}
export class ResourcesMockJsonSchemas {
  static buildShape(resourceMockClass: typeof ResourceMock): Record<string, unknown>;
}
export class ResourcesMockTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike, resourceMockClass: typeof ResourceMock): unknown;
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
  /** Optional: deep-compared against the checkResources response outputs for this resource. */
  outputs?: unknown[];
};
export type KerberosTestSchema = {
  name: string;
  input: KerberosTestInputSchema;
  expected: KerberosTestExpectedItemSchema[];
};
export class KerberosTest {
  constructor(schema: KerberosTestSchema, kerberos?: Kerberos, options?: ValidationOptions);
  /** Parses/validates one test fixture shape with the configured backend. */
  static parseShape(shape: unknown, options?: ValidationOptions & { schema?: unknown }): KerberosTestSchema;
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
  static parsePolicies(policies: unknown, options?: ValidationOptions): TestsPolicySchema[];
  static parseTests(tests: unknown, kerberos?: Kerberos, options?: ValidationOptions): KerberosTest[];
  static buildPrincipalsMock(principals: unknown, options?: ValidationOptions): PrincipalsMock;
  static buildResourcesMock(resources: unknown, options?: ValidationOptions): ResourcesMock;
  run(
    { effectAsBoolean }: { effectAsBoolean?: boolean },
    { describe, it, assert }: { describe: Describe; it: It; assert: Assert },
  ): void;
}
export class KerberosTestsZodSchemas {
  static buildShape(z: unknown, kerberosTestClass: typeof KerberosTest): unknown;
}
export class KerberosTestsJsonSchemas {
  static buildShape(kerberosTestClass: typeof KerberosTest): Record<string, unknown>;
}
export class KerberosTestsTypeBoxSchemas {
  static buildShape(typebox: TypeBoxLike, kerberosTestClass: typeof KerberosTest): unknown;
}
