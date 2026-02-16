import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateKeyPair, sign, verify, toHex } from './index';
import { KeyManager } from './key-rotation';
import type { KeyRotationPolicy, ManagedKeyPair } from './key-rotation';

// ─── Constructor validation ────────────────────────────────────────────────────

describe('KeyManager constructor', () => {
  it('rejects maxAgeMs <= 0', () => {
    expect(() => new KeyManager({ maxAgeMs: 0, overlapPeriodMs: 0 })).toThrow(
      /maxAgeMs must be positive/,
    );
    expect(() => new KeyManager({ maxAgeMs: -1, overlapPeriodMs: 0 })).toThrow(
      /maxAgeMs must be positive/,
    );
  });

  it('rejects negative overlapPeriodMs', () => {
    expect(() => new KeyManager({ maxAgeMs: 1000, overlapPeriodMs: -1 })).toThrow(
      /overlapPeriodMs must be non-negative/,
    );
  });

  it('rejects overlapPeriodMs >= maxAgeMs', () => {
    expect(() => new KeyManager({ maxAgeMs: 1000, overlapPeriodMs: 1000 })).toThrow(
      /overlapPeriodMs.*must be less than maxAgeMs/,
    );
    expect(() => new KeyManager({ maxAgeMs: 1000, overlapPeriodMs: 2000 })).toThrow(
      /overlapPeriodMs.*must be less than maxAgeMs/,
    );
  });

  it('accepts valid policy parameters', () => {
    expect(() => new KeyManager({ maxAgeMs: 1000, overlapPeriodMs: 500 })).not.toThrow();
    expect(() => new KeyManager({ maxAgeMs: 86400000, overlapPeriodMs: 0 })).not.toThrow();
  });
});

// ─── initialize() ──────────────────────────────────────────────────────────────

describe('KeyManager.initialize', () => {
  it('creates an active managed key pair', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    const managed = await km.initialize();

    expect(managed.status).toBe('active');
    expect(managed.keyPair.privateKey).toBeInstanceOf(Uint8Array);
    expect(managed.keyPair.publicKey).toBeInstanceOf(Uint8Array);
    expect(managed.keyPair.privateKey.length).toBe(32);
    expect(managed.keyPair.publicKey.length).toBe(32);
    expect(typeof managed.createdAt).toBe('string');
    expect(managed.rotatedAt).toBeUndefined();
  });

  it('throws if called twice', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await km.initialize();
    await expect(km.initialize()).rejects.toThrow('already initialized');
  });

  it('sets the key as current()', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    const managed = await km.initialize();
    const current = km.current();
    expect(current.keyPair.publicKeyHex).toBe(managed.keyPair.publicKeyHex);
  });
});

// ─── Pre-initialization guards ─────────────────────────────────────────────────

describe('pre-initialization guards', () => {
  it('current() throws before initialization', () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    expect(() => km.current()).toThrow('not initialized');
  });

  it('needsRotation() throws before initialization', () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    expect(() => km.needsRotation()).toThrow('not initialized');
  });

  it('rotate() throws before initialization', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await expect(km.rotate()).rejects.toThrow('not initialized');
  });

  it('verifyWithAnyKey() throws before initialization', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await expect(
      km.verifyWithAnyKey(new Uint8Array(0), new Uint8Array(0)),
    ).rejects.toThrow('not initialized');
  });

  it('retireExpired() throws before initialization', () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    expect(() => km.retireExpired()).toThrow('not initialized');
  });
});

// ─── needsRotation() ──────────────────────────────────────────────────────────

describe('KeyManager.needsRotation', () => {
  it('returns false when key is fresh', async () => {
    const km = new KeyManager({ maxAgeMs: 100000, overlapPeriodMs: 1000 });
    await km.initialize();
    expect(km.needsRotation()).toBe(false);
  });

  it('returns true when key age exceeds maxAgeMs', async () => {
    const km = new KeyManager({ maxAgeMs: 50, overlapPeriodMs: 10 });
    await km.initialize();

    // Wait for the key to age past maxAgeMs
    await new Promise((resolve) => setTimeout(resolve, 60));

    expect(km.needsRotation()).toBe(true);
  });
});

// ─── rotate() ──────────────────────────────────────────────────────────────────

describe('KeyManager.rotate', () => {
  it('creates a new active key and puts old key in rotating status', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await km.initialize();

    const originalKey = km.current().keyPair.publicKeyHex;
    const { previous, current } = await km.rotate();

    expect(previous.status).toBe('rotating');
    expect(previous.rotatedAt).toBeDefined();
    expect(previous.keyPair.publicKeyHex).toBe(originalKey);

    expect(current.status).toBe('active');
    expect(current.keyPair.publicKeyHex).not.toBe(originalKey);

    // current() should return the new key
    expect(km.current().keyPair.publicKeyHex).toBe(current.keyPair.publicKeyHex);
  });

  it('fires the onRotation callback with old and new public key hex', async () => {
    const onRotation = vi.fn();
    const km = new KeyManager({
      maxAgeMs: 10000,
      overlapPeriodMs: 1000,
      onRotation,
    });
    await km.initialize();
    const originalKey = km.current().keyPair.publicKeyHex;

    const { current } = await km.rotate();

    expect(onRotation).toHaveBeenCalledOnce();
    expect(onRotation).toHaveBeenCalledWith(originalKey, current.keyPair.publicKeyHex);
  });

  it('supports multiple rotations', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await km.initialize();

    await km.rotate();
    await km.rotate();
    await km.rotate();

    const allKeys = km.all();
    expect(allKeys.length).toBe(4); // 1 initial + 3 rotations

    // Only one should be active
    const active = allKeys.filter((k) => k.status === 'active');
    expect(active.length).toBe(1);
  });

  it('all previous keys are in rotating status after multiple rotations', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 5000 });
    await km.initialize();

    await km.rotate();
    await km.rotate();

    const allKeys = km.all();
    const rotating = allKeys.filter((k) => k.status === 'rotating');
    expect(rotating.length).toBe(2);
  });
});

// ─── all() ─────────────────────────────────────────────────────────────────────

describe('KeyManager.all', () => {
  it('returns all managed key pairs', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await km.initialize();

    expect(km.all().length).toBe(1);

    await km.rotate();
    expect(km.all().length).toBe(2);
  });

  it('returns a copy, not a reference to internals', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await km.initialize();

    const allKeys = km.all();
    allKeys.push({} as ManagedKeyPair);

    expect(km.all().length).toBe(1); // Original not affected
  });
});

// ─── verifyWithAnyKey() ────────────────────────────────────────────────────────

describe('KeyManager.verifyWithAnyKey', () => {
  it('verifies a signature made with the current active key', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 5000 });
    await km.initialize();

    const message = new TextEncoder().encode('hello');
    const signature = await sign(message, km.current().keyPair.privateKey);

    const result = await km.verifyWithAnyKey(message, signature);
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(km.current().keyPair.publicKeyHex);
  });

  it('verifies a signature made with a rotating key (overlap period)', async () => {
    const km = new KeyManager({ maxAgeMs: 100000, overlapPeriodMs: 60000 }); // long overlap
    await km.initialize();

    const message = new TextEncoder().encode('overlap-test');
    const oldKey = km.current();
    const signature = await sign(message, oldKey.keyPair.privateKey);

    await km.rotate();

    // Old key is now rotating, should still verify during overlap
    const result = await km.verifyWithAnyKey(message, signature);
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(oldKey.keyPair.publicKeyHex);
  });

  it('rejects an invalid signature', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await km.initialize();

    const message = new TextEncoder().encode('hello');
    const fakeSignature = new Uint8Array(64); // All zeros

    const result = await km.verifyWithAnyKey(message, fakeSignature);
    expect(result.valid).toBe(false);
    expect(result.keyId).toBe('');
  });

  it('rejects a signature from an unknown key', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await km.initialize();

    const unknownKey = await generateKeyPair();
    const message = new TextEncoder().encode('hello');
    const signature = await sign(message, unknownKey.privateKey);

    const result = await km.verifyWithAnyKey(message, signature);
    expect(result.valid).toBe(false);
    expect(result.keyId).toBe('');
  });

  it('verifies against new key after rotation', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 5000 });
    await km.initialize();

    await km.rotate();

    const message = new TextEncoder().encode('new-key-test');
    const signature = await sign(message, km.current().keyPair.privateKey);

    const result = await km.verifyWithAnyKey(message, signature);
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(km.current().keyPair.publicKeyHex);
  });
});

// ─── retireExpired() ───────────────────────────────────────────────────────────

describe('KeyManager.retireExpired', () => {
  it('retires keys whose overlap period has expired', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 30 });
    await km.initialize();

    await km.rotate();

    // Wait for the overlap period to expire
    await new Promise((resolve) => setTimeout(resolve, 50));

    const retired = km.retireExpired();
    expect(retired.length).toBe(1);
    expect(retired[0]!.status).toBe('retired');
  });

  it('does not retire keys still within overlap period', async () => {
    const km = new KeyManager({ maxAgeMs: 100000, overlapPeriodMs: 60000 });
    await km.initialize();

    await km.rotate();

    const retired = km.retireExpired();
    expect(retired.length).toBe(0);
  });

  it('does not retire the active key', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await km.initialize();

    const retired = km.retireExpired();
    expect(retired.length).toBe(0);
  });

  it('retired keys are not eligible for verification', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 30 });
    await km.initialize();

    const message = new TextEncoder().encode('retired-test');
    const oldKey = km.current();
    const signature = await sign(message, oldKey.keyPair.privateKey);

    await km.rotate();

    // Wait for overlap to expire
    await new Promise((resolve) => setTimeout(resolve, 50));
    km.retireExpired();

    // The old key should no longer verify (it's retired and past overlap)
    const result = await km.verifyWithAnyKey(message, signature);
    expect(result.valid).toBe(false);
  });
});

// ─── Full lifecycle ────────────────────────────────────────────────────────────

describe('KeyManager full lifecycle', () => {
  it('initialize -> sign -> rotate -> verify old -> verify new -> retire -> reject old', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 50 });

    // Step 1: Initialize
    await km.initialize();
    const firstKey = km.current();

    // Step 2: Sign with first key
    const msg = new TextEncoder().encode('lifecycle-test');
    const sig = await sign(msg, firstKey.keyPair.privateKey);

    // Step 3: Rotate
    const { current: secondKey } = await km.rotate();

    // Step 4: Verify old signature (still in overlap)
    let result = await km.verifyWithAnyKey(msg, sig);
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(firstKey.keyPair.publicKeyHex);

    // Step 5: Sign and verify with new key
    const sig2 = await sign(msg, secondKey.keyPair.privateKey);
    result = await km.verifyWithAnyKey(msg, sig2);
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(secondKey.keyPair.publicKeyHex);

    // Step 6: Wait for overlap to expire and retire
    await new Promise((resolve) => setTimeout(resolve, 60));
    const retired = km.retireExpired();
    expect(retired.length).toBe(1);

    // Step 7: Old signature should no longer verify
    result = await km.verifyWithAnyKey(msg, sig);
    expect(result.valid).toBe(false);

    // But new key still works
    result = await km.verifyWithAnyKey(msg, sig2);
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Edge case: negative maxAgeMs throws
// ---------------------------------------------------------------------------
describe('KeyManager edge case: negative maxAgeMs throws', () => {
  it('throws for maxAgeMs = -1', () => {
    expect(
      () => new KeyManager({ maxAgeMs: -1, overlapPeriodMs: 0 }),
      'negative maxAgeMs should throw',
    ).toThrow(/maxAgeMs must be positive/);
  });

  it('throws for maxAgeMs = -1000', () => {
    expect(
      () => new KeyManager({ maxAgeMs: -1000, overlapPeriodMs: 0 }),
      'large negative maxAgeMs should throw',
    ).toThrow(/maxAgeMs must be positive/);
  });

  it('throws for maxAgeMs = -Number.MAX_SAFE_INTEGER', () => {
    expect(
      () => new KeyManager({ maxAgeMs: -Number.MAX_SAFE_INTEGER, overlapPeriodMs: 0 }),
      'extremely negative maxAgeMs should throw',
    ).toThrow(/maxAgeMs must be positive/);
  });

  it('throws for maxAgeMs = 0 (zero is not positive)', () => {
    expect(
      () => new KeyManager({ maxAgeMs: 0, overlapPeriodMs: 0 }),
      'zero maxAgeMs should throw because it is not positive',
    ).toThrow(/maxAgeMs must be positive/);
  });

  it('does not throw for maxAgeMs = 1 (smallest valid value)', () => {
    expect(
      () => new KeyManager({ maxAgeMs: 1, overlapPeriodMs: 0 }),
      'maxAgeMs = 1 should be the smallest accepted value',
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Edge case: zero overlapPeriodMs works
// ---------------------------------------------------------------------------
describe('KeyManager edge case: zero overlapPeriodMs works', () => {
  it('accepts overlapPeriodMs = 0 without throwing', () => {
    expect(
      () => new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 0 }),
      'zero overlapPeriodMs should be accepted',
    ).not.toThrow();
  });

  it('initializes and rotates with zero overlap', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 0 });
    const managed = await km.initialize();
    expect(managed.status, 'initial key should be active').toBe('active');

    const { previous, current } = await km.rotate();
    expect(previous.status, 'old key should be in rotating status').toBe('rotating');
    expect(current.status, 'new key should be active').toBe('active');
  });

  it('with zero overlap, rotating keys are immediately eligible for retirement', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 0 });
    await km.initialize();

    const oldKey = km.current();
    const message = new TextEncoder().encode('zero-overlap-test');
    const signature = await sign(message, oldKey.keyPair.privateKey);

    await km.rotate();

    // With 0 overlap, the old key should be immediately retirable
    // Need just a tiny delay for the timestamp to differ
    await new Promise((resolve) => setTimeout(resolve, 5));
    const retired = km.retireExpired();
    expect(retired.length, 'old key should be retired immediately with zero overlap').toBe(1);
    expect(retired[0]!.status, 'retired key should have retired status').toBe('retired');

    // After retirement, old signature should not verify
    const result = await km.verifyWithAnyKey(message, signature);
    expect(result.valid, 'signature from retired key should not verify').toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Edge case: overlapPeriodMs >= maxAgeMs throws
// ---------------------------------------------------------------------------
describe('KeyManager edge case: overlapPeriodMs >= maxAgeMs throws', () => {
  it('throws when overlapPeriodMs equals maxAgeMs', () => {
    expect(
      () => new KeyManager({ maxAgeMs: 5000, overlapPeriodMs: 5000 }),
      'overlapPeriodMs equal to maxAgeMs should throw',
    ).toThrow(/overlapPeriodMs.*must be less than maxAgeMs/);
  });

  it('throws when overlapPeriodMs is greater than maxAgeMs', () => {
    expect(
      () => new KeyManager({ maxAgeMs: 5000, overlapPeriodMs: 10000 }),
      'overlapPeriodMs greater than maxAgeMs should throw',
    ).toThrow(/overlapPeriodMs.*must be less than maxAgeMs/);
  });

  it('throws when overlapPeriodMs is just 1ms greater than maxAgeMs', () => {
    expect(
      () => new KeyManager({ maxAgeMs: 1000, overlapPeriodMs: 1001 }),
      'overlapPeriodMs just over maxAgeMs should throw',
    ).toThrow(/overlapPeriodMs.*must be less than maxAgeMs/);
  });

  it('accepts overlapPeriodMs that is 1ms less than maxAgeMs', () => {
    expect(
      () => new KeyManager({ maxAgeMs: 1000, overlapPeriodMs: 999 }),
      'overlapPeriodMs just under maxAgeMs should be accepted',
    ).not.toThrow();
  });

  it('throws when both are the same large value', () => {
    expect(
      () => new KeyManager({ maxAgeMs: 86400000, overlapPeriodMs: 86400000 }),
      'equal large values should throw',
    ).toThrow(/overlapPeriodMs.*must be less than maxAgeMs/);
  });
});

// ---------------------------------------------------------------------------
// Edge case: double initialization throws
// ---------------------------------------------------------------------------
describe('KeyManager edge case: double initialization throws', () => {
  it('second initialize() call throws "already initialized"', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await km.initialize();
    await expect(
      km.initialize(),
    ).rejects.toThrow('already initialized');
  });

  it('state is preserved after failed second initialize', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    const firstKey = await km.initialize();

    try {
      await km.initialize();
    } catch {
      // expected
    }

    // The key manager should still be in a valid state with the original key
    const current = km.current();
    expect(current.keyPair.publicKeyHex, 'current key should remain unchanged after failed re-initialization').toBe(firstKey.keyPair.publicKeyHex);
    expect(km.all().length, 'key count should remain 1 after failed re-initialization').toBe(1);
  });

  it('double initialization after rotate still throws', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await km.initialize();
    await km.rotate();

    await expect(
      km.initialize(),
    ).rejects.toThrow('already initialized');

    // Should still have 2 keys (initial + rotated)
    expect(km.all().length, 'key count should be 2 after init + rotate + failed re-init').toBe(2);
  });

  it('operations still work normally after failed re-initialization', async () => {
    const km = new KeyManager({ maxAgeMs: 10000, overlapPeriodMs: 1000 });
    await km.initialize();

    try {
      await km.initialize();
    } catch {
      // expected
    }

    // All normal operations should still work
    expect(km.needsRotation(), 'needsRotation should still work').toBe(false);

    const { current } = await km.rotate();
    expect(current.status, 'rotate should still produce an active key').toBe('active');

    const message = new TextEncoder().encode('post-failure-test');
    const sig = await sign(message, current.keyPair.privateKey);
    const result = await km.verifyWithAnyKey(message, sig);
    expect(result.valid, 'verification should still work after failed re-initialization').toBe(true);
  });
});
