const { parseConstantsShape } = require('./validation');

/**
 * Represents a reusable constants bag.
 */
class Constants {
  /**
   * Parses a constants shape with the configured validation backend.
   *
   * @param {unknown} shape
   * @param {object} [options]
   * @returns {unknown}
   */
  static parseShape(shape, options = {}) {
    return parseConstantsShape(shape, options);
  }

  #shape = null;

  /**
   * @param {unknown} shape
   * @param {object} [options]
   */
  constructor(shape, options = {}) {
    this.#shape = Constants.parseShape(shape, options);
  }

  get shape() {
    return this.#shape;
  }

  /**
   * Returns the parsed constants object.
   *
   * @returns {unknown}
   */
  get() {
    return this.shape;
  }
}

module.exports = { Constants };
