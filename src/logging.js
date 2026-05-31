const LEGACY_EXCLUDED_FOR_TABLE = new Set(['principalScope', 'principalPolicyVersion', 'resourceScope', 'resourcePolicyVersion', 'outputs', 'meta']);

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

function isLegacyLogger(logger) {
  return hasMethod(logger, 'log') || hasMethod(logger, 'table') || hasMethod(logger, 'group') || hasMethod(logger, 'groupEnd');
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
      };

      if (!auditEntry.callId) delete auditEntry.callId;
      if (!auditEntry.reqId) delete auditEntry.reqId;
      if (!auditEntry.principalScope) delete auditEntry.principalScope;
      if (!auditEntry.principalPolicyVersion) delete auditEntry.principalPolicyVersion;
      if (!auditEntry.resourceScope) delete auditEntry.resourceScope;
      if (!auditEntry.resourcePolicyVersion) delete auditEntry.resourcePolicyVersion;
      if (!auditEntry.meta) delete auditEntry.meta;

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
  const debugMethod = hasMethod(sink, 'debug')
    ? sink.debug.bind(sink)
    : writeMethod;
  const errorMethod = hasMethod(sink, 'error')
    ? sink.error.bind(sink)
    : writeMethod;

  return {
    enabled: true,
    write(input, reqKind, callId) {
      const auditEntries = buildAuditEntries(input, reqKind, callId);

      for (const auditEntry of auditEntries) {
        writeMethod(auditEntry, buildStructuredMessage(auditEntry));
      }
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
  if (isLegacyLogger(logger)) return createLegacyLoggerWriter(logger);
  if (isStructuredLogger(logger)) return createStructuredLoggerWriter(logger);
  return createDisabledLoggerWriter();
}

module.exports = {
  buildAuditEntries,
  buildLegacyTableEntries,
  createLoggerWriter,
};
