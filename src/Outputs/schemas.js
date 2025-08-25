const { ConditionsZodSchemas } = require('../Conditions');
const { ZodSchemas } = require('../schemas.js');

class OutputsZodSchemas extends ZodSchemas {
  static buildShape(z) {
    return z.object({
      when: z.object({
        ruleActivated: z
          .function({
            input: [ConditionsZodSchemas.buildFullRequest(z)],
            output: z.unknown(),
          })
          .optional(),
        conditionNotMet: z
          .function({
            input: [ConditionsZodSchemas.buildFullRequest(z)],
            output: z.unknown(),
          })
          .optional(),
      }),
    });
  }
}

module.exports = { OutputsZodSchemas };
