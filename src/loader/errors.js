/**
 * Error thrown by the policy loader (`@alexify/kerberos/loader`) for I/O,
 * format and bundle-integrity failures.
 */
class KerberosLoaderError extends Error {
  /**
   * @param {string} message
   * @param {{ file?: string }} [info]
   */
  constructor(message, { file } = {}) {
    super(file ? `${file}: ${message}` : message);
    this.name = 'KerberosLoaderError';
    if (file) this.file = file;
  }
}

module.exports = { KerberosLoaderError };
