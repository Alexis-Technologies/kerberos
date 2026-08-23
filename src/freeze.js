/**
 * Recursively freezes a plain object/array tree in place. Functions and
 * already-frozen nodes are left untouched (user-supplied condition/variable
 * functions must stay callable and extensible for seams like EXPR_META).
 *
 * Shared hardening util: the codec deep-freezes cached expression ASTs
 * against cross-consumer mutation, and the policy classes freeze their parsed
 * shapes so live engine state cannot be rewritten post-construction (the
 * constructor-time duplicate/deny guards would otherwise be bypassable by
 * mutating `policy.shape` afterwards).
 *
 * @param {unknown} node
 * @returns {unknown} the same node, frozen
 */
function deepFreeze(node) {
  if (!node || typeof node !== 'object' || Object.isFrozen(node)) return node;
  Object.freeze(node);
  for (const key of Object.keys(node)) deepFreeze(node[key]);
  return node;
}

/**
 * Deep-copies the plain-object/array spine of a parsed policy shape while
 * keeping functions and class instances by reference. The policy constructors
 * clone their input before normalizing, so they never mutate (or freeze) a
 * caller-owned document — the same shape literal can construct any number of
 * instances, and the frozen result is always engine-owned.
 *
 * An own `__proto__` key is copied as a plain data property (defineProperty
 * bypasses the setter) — same discipline as the codec's deepTransform.
 *
 * @param {unknown} value
 * @returns {unknown}
 */
function cloneShapeTree(value) {
  if (Array.isArray(value)) {
    const out = new Array(value.length);
    for (let i = 0; i < value.length; i++) out[i] = cloneShapeTree(value[i]);
    return out;
  }
  if (value && typeof value === 'object') {
    const proto = Object.getPrototypeOf(value);
    // Class instances (Conditions, Variables, ...) are shared by reference —
    // they own their internals and freezing/cloning them is not ours to do.
    if (proto !== Object.prototype && proto !== null) return value;
    const out = {};
    for (const key of Object.keys(value)) {
      const cloned = cloneShapeTree(value[key]);
      if (key === '__proto__') {
        Object.defineProperty(out, key, { value: cloned, enumerable: true, writable: true, configurable: true });
      } else {
        out[key] = cloned;
      }
    }
    return out;
  }
  return value;
}

module.exports = { cloneShapeTree, deepFreeze };
