/**
 * Error thrown by the Cerbos importer (`@alexify/kerberos/cerbos`) when a
 * document, expression or YAML construct falls outside the supported subset.
 *
 * The importer's governing invariant is that it REFUSES TO GUESS: anything it
 * cannot translate faithfully throws instead of being dropped or approximated,
 * because a silently-skipped rule or a mistranslated condition would change
 * authorization decisions without a trace.
 */
class KerberosImportError extends Error {
  /**
   * @param {string} message
   * @param {{ line?: number }} [info]
   */
  constructor(message, { line } = {}) {
    super(typeof line === 'number' ? `line ${line}: ${message}` : message);
    this.name = 'KerberosImportError';
    if (typeof line === 'number') this.line = line;
  }
}

module.exports = { KerberosImportError };
