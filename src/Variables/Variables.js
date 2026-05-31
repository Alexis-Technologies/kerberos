const { parseVariablesShape } = require('./validation');

/**
 * Represents a set of lazily evaluated request variables.
 */
class Variables {
  /**
   * Parses a variables shape with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parseVariablesShape(shape, options);
  }

  #shape = null;

  /**
   * @param {unknown} shape
   * @param {object} [options]
   */
  constructor(shape, options = {}) {
    this.#shape = Variables.parseShape(shape, options);
  }

  get shape() {
    return this.#shape;
  }

  /**
   * Evaluates all variable functions for a request.
   *
   * @param {Record<string, unknown>} req
   * @returns {Record<string, unknown>}
   */
  get(req) {
    const result = {};
    for (const name in this.#shape) {
      if (!Object.prototype.hasOwnProperty.call(this.#shape, name)) continue;
      const value = this.#shape[name](req);
      // A variable literally named `__proto__` must become an own entry on `V`
      // rather than mutating the prototype of the request context. `defineProperty`
      // bypasses the `__proto__` setter and stores it as a plain data property.
      if (name === '__proto__') {
        Object.defineProperty(result, name, { value, enumerable: true, writable: true, configurable: true });
      } else {
        result[name] = value;
      }
    }
    return result;
  }
}

module.exports = { Variables };
