const { parseOutputsShape } = require('./validation');

/**
 * Evaluates policy outputs for activated rules.
 */
class Outputs {
  /**
   * Parses an outputs shape with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parseOutputsShape(shape, options);
  }

  #shape = null;

  /**
   * @param {unknown} shape
   * @param {object} [options]
   */
  constructor(shape, options = {}) {
    this.#shape = Outputs.parseShape(shape, options);
  }

  get shape() {
    return this.#shape;
  }

  /**
   * Builds the output payload for the current rule.
   *
   * @param {Record<string, unknown>} req
   * @param {boolean} isConditionFulfilled
   * @param {string} src
   * @returns {{ src: string, val: unknown }}
   */
  build(req, isConditionFulfilled, src) {
    try {
      let outputFunction = null;

      if (typeof this.#shape === 'function') {
        outputFunction = this.#shape;
      } else if (isConditionFulfilled && this.#shape.when.ruleActivated) {
        outputFunction = this.#shape.when.ruleActivated;
      } else if (!isConditionFulfilled && this.#shape.when.conditionNotMet) {
        outputFunction = this.#shape.when.conditionNotMet;
      }

      return { src, val: outputFunction?.(req) ?? null };
    } catch (error) {
      // If output function fails, add error information
      return { src, val: { error: 'Output function evaluation failed', message: error.message } };
    }
  }
}

module.exports = { Outputs };
