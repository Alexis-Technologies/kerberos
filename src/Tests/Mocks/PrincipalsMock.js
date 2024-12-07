import { z } from 'zod';

import { PrincipalMock, PrincipalMockSchema } from './PrincipalMock.js';

export const PrincipalsMockSchema = z.union([z.array(z.instanceof(PrincipalMock)).nonempty(), z.record(PrincipalMockSchema.shape.name, PrincipalMockSchema.omit({ name: true }))]);

export class PrincipalsMock {
  constructor(principals) {
    const parsedPrincipals = PrincipalsMockSchema.parse(principals);
    this.principals = new Map();
    if (Array.isArray(parsedPrincipals)) {
      parsedPrincipals.forEach((principal) => this.principals.set(principal.name, principal));
    } else {
      Object.entries(parsedPrincipals).forEach(([name, principal]) => {
        const mock = new PrincipalMock({ ...principal, name });
        this.principals.set(mock.name, mock);
      });
    }
  }

  get mocks() {
    return [...this.principals.values()];
  }

  get(name) {
    return this.principals.get(name);
  }
}
