const LEGACY_EXCLUDED_FOR_TABLE = new Set([
  'principalRoles',
  'principalScope',
  'principalPolicyVersion',
  'resourceScope',
  'resourcePolicyVersion',
  'outputs',
  'meta',
]);

const LEGACY_READABLE_HEADERS_MAP = {
  callId: 'Call ID',
  reqId: 'Request ID',
  timestamp: 'Timestamp',
  reqKind: 'Request kind',
  principalId: 'Principal ID',
  principalScope: 'Principal Scope',
  principalPolicyVersion: 'Principal Policy Version',
  resourceKind: 'Resource kind',
  resourceId: 'Resource ID',
  resourceScope: 'Resource Scope',
  resourcePolicyVersion: 'Resource Policy Version',
  action: 'Action',
  effect: 'Effect',
  outputs: 'Outputs',
  meta: 'Meta',
};

function hasMethod(value, methodName) {
  return typeof value?.[methodName] === 'function';
}

// A console-like logger is identified by console-SPECIFIC methods (table /
// group / groupEnd). A bare `.log` is deliberately NOT part of this test:
// structured loggers such as winston and consola expose `.log` alongside
// `.info`/`.debug`, and classifying them as console-like routed their audit
// entries into the legacy writer — where `logger.log(summaryString)` misfires
// (winston reads the first arg as a level) and the per-entry writes land on
// `debug`, silently losing the audit trail. Only true console-likes have
// table/group.
function isConsoleLikeLogger(logger) {
  return hasMethod(logger, 'table') || hasMethod(logger, 'group') || hasMethod(logger, 'groupEnd');
}

function isStructuredLogger(logger) {
  return hasMethod(logger, 'info') || hasMethod(logger, 'debug');
}

function buildAuditEntries(input, reqKind, callId) {
  const auditEntries = [];

  for (const { req, result } of input) {
    for (const action of req.actions) {
      const auditEntry = {
        callId,
        reqId: req.reqId,
        timestamp: new Date().toISOString(),
        reqKind,
        principalId: req.P.id,
        // The role layer decides outcomes, and roles change over time — an
        // audit entry must record the set the decision was based on.
        principalRoles: req.P.roles,
        principalScope: req.P.scope,
        principalPolicyVersion: req.P.policyVersion,
        resourceKind: req.R.kind,
        resourceId: req.R.id,
        resourceScope: req.R.scope,
        resourcePolicyVersion: req.R.policyVersion,
        action,
        effect: result.effects.get(action),
        outputs: result.outputs ? [...result.outputs.values()] : [],
        meta: result.meta,
        validationErrors: result.validationErrors,
      };

      if (!auditEntry.callId) delete auditEntry.callId;
      if (!auditEntry.reqId) delete auditEntry.reqId;
      if (!auditEntry.principalScope) delete auditEntry.principalScope;
      if (!auditEntry.principalPolicyVersion) delete auditEntry.principalPolicyVersion;
      if (!auditEntry.resourceScope) delete auditEntry.resourceScope;
      if (!auditEntry.resourcePolicyVersion) delete auditEntry.resourcePolicyVersion;
      if (!auditEntry.meta) delete auditEntry.meta;
      if (!auditEntry.validationErrors) delete auditEntry.validationErrors;

      auditEntries.push(auditEntry);
    }
  }

  return auditEntries;
}

function buildLegacyTableEntries(auditEntries) {
  return auditEntries.map((auditEntry) => {
    const tableEntry = { ...auditEntry };
    const excludedForTable = new Set(LEGACY_EXCLUDED_FOR_TABLE);
    excludedForTable.add(tableEntry.reqId ? 'callId' : 'reqId');

    for (const key of Object.keys(tableEntry)) {
      if (excludedForTable.has(key)) {
        delete tableEntry[key];
        continue;
      }

      tableEntry[LEGACY_READABLE_HEADERS_MAP[key]] = tableEntry[key];
      delete tableEntry[key];
    }

    return tableEntry;
  });
}

function buildIsAllowedSummary(input) {
  if (input.length !== 1) return null;

  const [{ req, result }] = input;
  const [action] = req.actions;
  const effect = result.effects.get(action);

  return `Principal ${req.P.id} is ${effect === 'EFFECT_ALLOW' || effect === true ? 'ALLOWED' : 'DENIED'} to perform action ${action} on resource ${req.R.id}`;
}

function buildStructuredMessage(auditEntry) {
  if (auditEntry.reqKind === 'IsAllowed') {
    return `Kerberos.js authorization decision for ${auditEntry.principalId} on ${auditEntry.resourceId}`;
  }

  return `Kerberos.js ${auditEntry.reqKind} audit log`;
}

function createDisabledLoggerWriter() {
  return {
    enabled: false,
    write() {},
    info() {},
    debug() {},
    error() {},
  };
}

function createLegacyLoggerWriter(logger) {
  return {
    enabled: true,
    write(input, reqKind, callId) {
      logger.group?.('Kerberos.js');

      if (reqKind === 'IsAllowed') {
        const summary = buildIsAllowedSummary(input);
        if (summary) logger.log?.(summary);
      }

      const auditEntries = buildAuditEntries(input, reqKind, callId);
      logger.table?.(buildLegacyTableEntries(auditEntries));

      if (hasMethod(logger, 'debug')) {
        for (const auditEntry of auditEntries) logger.debug(auditEntry, 'Kerberos.js request log');
      }

      logger.groupEnd?.();
    },
    // Decision-level entries that must not be filtered out at production log
    // levels (unlike lifecycle `debug` events) — e.g. PlanResources results.
    info(entry, message) {
      if (hasMethod(logger, 'info')) {
        logger.info(entry, message);
        return;
      }
      logger.log?.(message, entry);
    },
    debug(entry, message) {
      logger.debug?.(entry, message);
    },
    error(entry, message) {
      if (hasMethod(logger, 'error')) {
        logger.error(entry, message);
        return;
      }

      logger.debug?.(entry, message);
    },
  };
}

function createStructuredLoggerWriter(logger) {
  const sink = hasMethod(logger, 'child') ? logger.child({ component: 'Kerberos.js' }) : logger;
  const writeMethod = hasMethod(sink, 'info') ? sink.info.bind(sink) : sink.debug.bind(sink);
  const debugMethod = hasMethod(sink, 'debug') ? sink.debug.bind(sink) : writeMethod;
  const errorMethod = hasMethod(sink, 'error') ? sink.error.bind(sink) : writeMethod;

  return {
    enabled: true,
    write(input, reqKind, callId) {
      const auditEntries = buildAuditEntries(input, reqKind, callId);

      for (const auditEntry of auditEntries) {
        writeMethod(auditEntry, buildStructuredMessage(auditEntry));
      }
    },
    // Same level as decision audit entries (`write`) — plan results are
    // decisions, not lifecycle noise, so they survive a `level: 'info'` sink.
    info(entry, message) {
      writeMethod(entry, message);
    },
    debug(entry, message) {
      debugMethod(entry, message);
    },
    error(entry, message) {
      errorMethod(entry, message);
    },
  };
}

function createLoggerWriter(logger) {
  if (!logger) return createDisabledLoggerWriter();
  if (logger === true) return createLegacyLoggerWriter(console);
  if (typeof logger !== 'object') return createDisabledLoggerWriter();
  // Console-likes (console itself, custom table/group loggers) → legacy writer.
  if (isConsoleLikeLogger(logger)) return createLegacyLoggerWriter(logger);
  // Structured loggers (Pino, winston, consola, bunyan) → structured writer,
  // even though several of them also expose `.log`.
  if (isStructuredLogger(logger)) return createStructuredLoggerWriter(logger);
  // A bare `console.log`-only shim (no table/group, no info/debug): preserve the
  // legacy behavior of emitting the summary line rather than silently dropping it.
  if (hasMethod(logger, 'log')) return createLegacyLoggerWriter(logger);
  return createDisabledLoggerWriter();
}

module.exports = {
  buildAuditEntries,
  buildLegacyTableEntries,
  createLoggerWriter,
};
