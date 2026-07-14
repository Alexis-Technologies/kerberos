const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert').strict;

const nodeRuntime = require('../src/runtime/node.js');
const browserRuntime = require('../src/runtime/browser.js');

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Temporarily replaces a global property, returning a restore function.
 * Node exposes `crypto` / `performance` as configurable globals, so
 * defineProperty-based swapping is safe here.
 */
function replaceGlobal(name, value) {
  const original = Object.getOwnPropertyDescriptor(globalThis, name);
  Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  return () => {
    if (original) Object.defineProperty(globalThis, name, original);
    else delete globalThis[name];
  };
}

describe('Runtime modules', () => {
  describe('interface parity', () => {
    it('should export the exact same interface from both runtimes', () => {
      assert.deepEqual(Object.keys(nodeRuntime).sort(), Object.keys(browserRuntime).sort());
      assert.deepEqual(Object.keys(nodeRuntime).sort(), ['generateCallId', 'getNow']);
      assert.equal(typeof nodeRuntime.generateCallId, 'function');
      assert.equal(typeof nodeRuntime.getNow, 'function');
      assert.equal(typeof browserRuntime.generateCallId, 'function');
      assert.equal(typeof browserRuntime.getNow, 'function');
    });
  });

  describe('node runtime', () => {
    it('should generate UUID v4 call ids', () => {
      assert.match(nodeRuntime.generateCallId(), UUID_V4_REGEX);
    });

    it('should generate unique call ids', () => {
      const ids = new Set();
      for (let i = 0; i < 5000; i++) ids.add(nodeRuntime.generateCallId());
      assert.equal(ids.size, 5000);
    });

    it('should return a finite, non-decreasing timestamp', () => {
      const first = nodeRuntime.getNow();
      const second = nodeRuntime.getNow();
      assert.ok(Number.isFinite(first));
      assert.ok(second >= first);
    });
  });

  describe('browser runtime (native globals path)', () => {
    it('should generate UUID v4 call ids', () => {
      assert.match(browserRuntime.generateCallId(), UUID_V4_REGEX);
    });

    it('should generate unique call ids', () => {
      const ids = new Set();
      for (let i = 0; i < 5000; i++) ids.add(browserRuntime.generateCallId());
      assert.equal(ids.size, 5000);
    });

    it('should return a finite, non-decreasing timestamp', () => {
      const first = browserRuntime.getNow();
      const second = browserRuntime.getNow();
      assert.ok(Number.isFinite(first));
      assert.ok(second >= first);
    });
  });

  describe('browser runtime (fallback paths)', () => {
    let restoreCrypto;
    let restorePerformance;

    beforeEach(() => {
      restoreCrypto = replaceGlobal('crypto', undefined);
      restorePerformance = replaceGlobal('performance', undefined);
    });

    afterEach(() => {
      restoreCrypto();
      restorePerformance();
    });

    it('should fall back to a pseudo UUID v4 when crypto.randomUUID is unavailable', () => {
      assert.equal(globalThis.crypto, undefined);
      const id = browserRuntime.generateCallId();
      assert.match(id, UUID_V4_REGEX);
    });

    it('should generate unique pseudo UUIDs', () => {
      const ids = new Set();
      for (let i = 0; i < 5000; i++) ids.add(browserRuntime.generateCallId());
      assert.equal(ids.size, 5000);
    });

    it('should fall back to Date.now when performance is unavailable', () => {
      assert.equal(globalThis.performance, undefined);
      const before = Date.now();
      const now = browserRuntime.getNow();
      const after = Date.now();
      assert.ok(Number.isFinite(now));
      assert.ok(now >= before && now <= after);
    });

    it('should handle crypto objects without randomUUID (older Safari)', () => {
      const restore = replaceGlobal('crypto', {});
      try {
        assert.match(browserRuntime.generateCallId(), UUID_V4_REGEX);
      } finally {
        restore();
      }
    });
  });

  describe('browser entry (browser.js)', () => {
    it('should load in Node and expose the same exports as index.js', () => {
      const browserEntry = require('../browser.js');
      const nodeEntry = require('../index.js');
      assert.deepEqual(Object.keys(browserEntry).sort(), Object.keys(nodeEntry).sort());
      assert.equal(browserEntry.Kerberos, nodeEntry.Kerberos);
    });
  });
});
