/**
 * The active derived roles of one resource policy, resolved lazily.
 *
 * The decision walk only ever asks "is derived role X active?" (and, for an
 * active one, which parent roles it stands for) about the names that the
 * rules of the requested actions reference. This view answers exactly those
 * questions on demand — each imported set evaluates a name's definitions the
 * first time it is asked, and never evaluates a definition nobody asks about.
 * It exposes the `has` / `get` / `keys` subset of the Map the walk used to
 * receive, so `ResourcePolicy.evaluateRules` and `ruleCoversRole` read it
 * unchanged.
 *
 * `keys()` lists the names that were resolved AND are active, in the order
 * the eager Map would have held them (import order, definition order, then
 * relation-granted names) — that is what `meta.effectiveDerivedRoles`
 * reports.
 *
 * Platform-neutral, zero dependencies.
 */
class DerivedRoleView {
  // One `DerivedRoles#createActivation(req)` per imported set, import order.
  #activations;

  // Relation-backed names the resolver granted → their parentRoles (or null).
  #granted;

  // name → { parentRoles } | null, once resolved (allocated on first use).
  #resolved = null;

  /**
   * @param {ReadonlyArray<{ names: readonly string[], resolve(name: string): { parentRoles: string[] } | null }>} activations
   * @param {ReadonlyMap<string, string[] | null> | null} [granted]
   */
  constructor(activations, granted = null) {
    this.#activations = activations;
    this.#granted = granted;
  }

  #resolve(name) {
    if (this.#granted === null) {
      if (this.#activations.length === 0) return null;
      // One imported set and no relation grants (the common case): the set's
      // own activation already memoizes per name.
      if (this.#activations.length === 1) return this.#activations[0].resolve(name);
    }
    this.#resolved ??= new Map();
    let state = this.#resolved.get(name);
    if (state !== undefined) return state;
    state = null;
    // Same precedence as the eager Map: a later set's active definition
    // overrides an earlier one, and a relation grant overrides both.
    for (const activation of this.#activations) {
      const active = activation.resolve(name);
      if (active) state = active;
    }
    if (this.#granted?.has(name)) state = { parentRoles: this.#granted.get(name) };
    this.#resolved.set(name, state);
    return state;
  }

  /**
   * Resolves every remaining condition-backed name so `keys()` lists all
   * active derived roles — for `meta.effectiveDerivedRoles`, which (like
   * Cerbos's) reports every active imported role, not only the ones a rule
   * asked about. Runs after the decision is made; a definition whose
   * condition throws here simply counts as inactive, as in Cerbos, and can
   * never affect the decision.
   */
  settle() {
    this.#resolved ??= new Map();
    for (const activation of this.#activations) {
      for (const name of activation.names) {
        if (this.#resolved.has(name)) continue;
        let state = null;
        for (const candidate of this.#activations) {
          try {
            const active = candidate.resolve(name);
            if (active) state = active;
          } catch {
            // meta only — an erroring definition is not active
          }
        }
        if (this.#granted?.has(name)) state = { parentRoles: this.#granted.get(name) };
        this.#resolved.set(name, state);
      }
    }
  }

  // Single-set views skip their own memo; read the set's answer instead.
  #peekSingle(name) {
    return this.#granted === null && this.#activations.length === 1 ? this.#activations[0].peek(name) : null;
  }

  has(name) {
    return this.#resolve(name) !== null;
  }

  /** The active role's `parentRoles` (null when ungated); undefined when inactive. */
  get(name) {
    return this.#resolve(name)?.parentRoles;
  }

  *keys() {
    const seen = new Set();
    const emit = (name) => {
      if (seen.has(name)) return false;
      seen.add(name);
      return Boolean(this.#resolved?.get(name) ?? this.#peekSingle(name));
    };
    for (const activation of this.#activations) {
      for (const name of activation.names) if (emit(name)) yield name;
    }
    if (this.#granted) for (const name of this.#granted.keys()) if (emit(name)) yield name;
  }
}

// No imported set, or none resolved: nothing can activate.
const NO_DERIVED_ROLES = new DerivedRoleView([]);

module.exports = { DerivedRoleView, NO_DERIVED_ROLES };
