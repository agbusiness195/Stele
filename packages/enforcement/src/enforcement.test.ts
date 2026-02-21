import { describe, it, expect } from 'vitest';
import { generateKeyPair, sha256String } from '@grith/crypto';
import type { HashHex, KeyPair } from '@grith/crypto';
import {
  Monitor,
  MonitorDeniedError,
  CapabilityError,
  CapabilityGate,
  verifyMerkleProof,
  createProvenanceRecord,
  buildProvenanceChain,
  verifyProvenance,
  queryProvenance,
  createDefenseConfig,
  analyzeDefense,
  addDefenseLayer,
  disableLayer,
} from './index';
import type {
  AuditEntry,
  RateLimitState,
  CapabilityManifest,
  ProvenanceRecord,
  ProvenanceChain,
  DefenseLayer,
  DefenseInDepthConfig,
  DefenseAnalysis,
} from './index';

// ─── Shared fixtures ───────────────────────────────────────────────────────────

const COVENANT_ID: HashHex = 'a'.repeat(64);

const CONSTRAINTS = [
  "permit file.read on '/data/**'",
  "deny file.write on '/system/**' severity critical",
  "deny network.send on '**' severity high",
].join('\n');

// ─── MonitorDeniedError ────────────────────────────────────────────────────────

describe('MonitorDeniedError', () => {
  it('has correct name, action, resource, and severity', () => {
    const rule = {
      type: 'deny' as const,
      action: 'file.write',
      resource: '/system/**',
      severity: 'critical' as const,
      line: 2,
    };
    const err = new MonitorDeniedError('file.write', '/system/config', rule, 'critical');

    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(MonitorDeniedError);
    expect(err.name).toBe('MonitorDeniedError');
    expect(err.action).toBe('file.write');
    expect(err.resource).toBe('/system/config');
    expect(err.matchedRule).toBe(rule);
    expect(err.severity).toBe('critical');
    expect(err.message).toContain("'file.write'");
    expect(err.message).toContain("'/system/config'");
    expect(err.message).toContain('matched deny rule');
  });

  it('message describes "no matching permit rule" when matchedRule is undefined', () => {
    const err = new MonitorDeniedError('file.delete', '/tmp/test', undefined, undefined);

    expect(err.name).toBe('MonitorDeniedError');
    expect(err.action).toBe('file.delete');
    expect(err.resource).toBe('/tmp/test');
    expect(err.matchedRule).toBeUndefined();
    expect(err.severity).toBeUndefined();
    expect(err.message).toContain('no matching permit rule');
  });
});

// ─── CapabilityError ───────────────────────────────────────────────────────────

describe('CapabilityError', () => {
  it('has correct name and action with default message', () => {
    const err = new CapabilityError('file.delete');

    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(CapabilityError);
    expect(err.name).toBe('CapabilityError');
    expect(err.action).toBe('file.delete');
    expect(err.message).toContain("'file.delete'");
  });

  it('accepts a custom message', () => {
    const err = new CapabilityError('network.send', 'Custom message here');

    expect(err.name).toBe('CapabilityError');
    expect(err.action).toBe('network.send');
    expect(err.message).toBe('Custom message here');
  });
});

// ─── Monitor ───────────────────────────────────────────────────────────────────

describe('Monitor', () => {
  describe('evaluate — enforce mode', () => {
    it('permits allowed actions', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      const result = await monitor.evaluate('file.read', '/data/users');

      expect(result.permitted).toBe(true);
      expect(result.matchedRule).toBeDefined();
      expect(result.matchedRule!.type).toBe('permit');
    });

    it('blocks denied actions by throwing MonitorDeniedError', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await expect(
        monitor.evaluate('file.write', '/system/config'),
      ).rejects.toThrow(MonitorDeniedError);

      try {
        await monitor.evaluate('file.write', '/system/passwd');
      } catch (err) {
        expect(err).toBeInstanceOf(MonitorDeniedError);
        const mde = err as MonitorDeniedError;
        expect(mde.action).toBe('file.write');
        expect(mde.resource).toBe('/system/passwd');
        expect(mde.severity).toBe('critical');
      }
    });

    it('blocks actions with no matching permit rule (default deny)', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await expect(
        monitor.evaluate('file.delete', '/data/users'),
      ).rejects.toThrow(MonitorDeniedError);
    });

    it('blocks network.send on any resource', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await expect(
        monitor.evaluate('network.send', '/api/external'),
      ).rejects.toThrow(MonitorDeniedError);
    });
  });

  describe('evaluate — log_only mode', () => {
    it('permits denied actions without throwing', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'log_only' });

      // Should not throw even though the action is denied
      const result = await monitor.evaluate('file.write', '/system/config');

      expect(result.permitted).toBe(false);
      expect(result.matchedRule).toBeDefined();
      expect(result.matchedRule!.type).toBe('deny');
    });

    it('still logs violations via the onViolation callback', async () => {
      const violations: AuditEntry[] = [];
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, {
        mode: 'log_only',
        onViolation: (entry) => violations.push(entry),
      });

      await monitor.evaluate('file.write', '/system/config');

      expect(violations).toHaveLength(1);
      expect(violations[0]!.action).toBe('file.write');
      expect(violations[0]!.outcome).toBe('EXECUTED'); // log_only overrides to EXECUTED
    });

    it('records audit entries for denied actions', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'log_only' });

      await monitor.evaluate('network.send', '/anywhere');

      const log = monitor.getAuditLog();
      expect(log.entries).toHaveLength(1);
      expect(log.entries[0]!.action).toBe('network.send');
      expect(log.entries[0]!.outcome).toBe('EXECUTED'); // log_only mode
    });
  });

  describe('execute', () => {
    it('runs the handler when the action is permitted', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      const result = await monitor.execute(
        'file.read',
        '/data/users',
        async (resource, _ctx) => {
          return { data: `contents of ${resource}` };
        },
      );

      expect(result).toEqual({ data: 'contents of /data/users' });
    });

    it('throws MonitorDeniedError when the action is denied', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await expect(
        monitor.execute(
          'file.write',
          '/system/config',
          async () => 'should not run',
        ),
      ).rejects.toThrow(MonitorDeniedError);
    });

    it('propagates handler errors and still creates an audit entry', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await expect(
        monitor.execute(
          'file.read',
          '/data/test',
          async () => {
            throw new Error('disk failure');
          },
        ),
      ).rejects.toThrow('disk failure');

      const log = monitor.getAuditLog();
      expect(log.entries).toHaveLength(1);
      expect(log.entries[0]!.outcome).toBe('EXECUTED');
      expect(log.entries[0]!.error).toBe('disk failure');
    });
  });

  describe('audit log', () => {
    it('records entries for both permitted and denied actions', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/users');
      try {
        await monitor.evaluate('file.write', '/system/config');
      } catch {
        // expected
      }

      const log = monitor.getAuditLog();
      expect(log.covenantId).toBe(COVENANT_ID);
      expect(log.entries).toHaveLength(2);
      expect(log.count).toBe(2);
      expect(log.entries[0]!.action).toBe('file.read');
      expect(log.entries[0]!.outcome).toBe('EXECUTED');
      expect(log.entries[1]!.action).toBe('file.write');
      expect(log.entries[1]!.outcome).toBe('DENIED');
    });

    it('entries contain correct fields', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/report', { user: 'alice' });

      const entry = monitor.getAuditEntry(0);
      expect(entry).toBeDefined();
      expect(entry!.index).toBe(0);
      expect(entry!.timestamp).toBeTruthy();
      expect(entry!.action).toBe('file.read');
      expect(entry!.resource).toBe('/data/report');
      expect(entry!.context).toEqual({ user: 'alice' });
      expect(entry!.result.permitted).toBe(true);
      expect(entry!.outcome).toBe('EXECUTED');
      expect(entry!.hash).toBeTruthy();
      expect(entry!.previousHash).toBeTruthy();
    });

    it('hash chain links entries together', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      await monitor.evaluate('file.read', '/data/b');
      await monitor.evaluate('file.read', '/data/c');

      const log = monitor.getAuditLog();
      const entries = log.entries;

      // First entry links to genesis hash
      expect(entries[0]!.previousHash).toBe('0'.repeat(64));

      // Subsequent entries link to the previous entry's hash
      expect(entries[1]!.previousHash).toBe(entries[0]!.hash);
      expect(entries[2]!.previousHash).toBe(entries[1]!.hash);

      // Each entry has a unique hash
      const hashes = new Set(entries.map((e) => e.hash));
      expect(hashes.size).toBe(3);
    });
  });

  describe('verifyAuditLogIntegrity', () => {
    it('returns true for an empty log', () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS);
      expect(monitor.verifyAuditLogIntegrity()).toBe(true);
    });

    it('returns true for an unmodified log', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      await monitor.evaluate('file.read', '/data/b');
      await monitor.evaluate('file.read', '/data/c');

      expect(monitor.verifyAuditLogIntegrity()).toBe(true);
    });

    it('returns false when an entry hash is tampered', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      await monitor.evaluate('file.read', '/data/b');

      // Tamper with the first entry's hash
      const entry = monitor.getAuditEntry(0)!;
      entry.hash = 'f'.repeat(64) as HashHex;

      expect(monitor.verifyAuditLogIntegrity()).toBe(false);
    });

    it('returns false when an entry action is tampered', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      await monitor.evaluate('file.read', '/data/b');

      // Tamper with the first entry's action field
      const entry = monitor.getAuditEntry(0)!;
      entry.action = 'file.write';

      expect(monitor.verifyAuditLogIntegrity()).toBe(false);
    });

    it('returns false when the previousHash linkage is broken', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      await monitor.evaluate('file.read', '/data/b');
      await monitor.evaluate('file.read', '/data/c');

      // Tamper with the second entry's previousHash
      const entry = monitor.getAuditEntry(1)!;
      entry.previousHash = '0'.repeat(64) as HashHex;

      expect(monitor.verifyAuditLogIntegrity()).toBe(false);
    });
  });

  describe('Merkle tree', () => {
    it('computeMerkleRoot returns genesis hash for empty log', () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS);
      expect(monitor.computeMerkleRoot()).toBe('0'.repeat(64));
    });

    it('computeMerkleRoot produces consistent results', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      await monitor.evaluate('file.read', '/data/b');

      const root1 = monitor.computeMerkleRoot();
      const root2 = monitor.computeMerkleRoot();

      expect(root1).toBe(root2);
      expect(root1).not.toBe('0'.repeat(64));
    });

    it('computeMerkleRoot changes when new entries are added', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      const root1 = monitor.computeMerkleRoot();

      await monitor.evaluate('file.read', '/data/b');
      const root2 = monitor.computeMerkleRoot();

      expect(root1).not.toBe(root2);
    });

    it('generateMerkleProof → verifyMerkleProof round-trip succeeds', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      await monitor.evaluate('file.read', '/data/b');
      await monitor.evaluate('file.read', '/data/c');
      await monitor.evaluate('file.read', '/data/d');

      // Verify proof for each entry
      for (let i = 0; i < 4; i++) {
        const proof = monitor.generateMerkleProof(i);
        expect(proof.entryHash).toBe(monitor.getAuditEntry(i)!.hash);
        expect(proof.index).toBe(i);
        expect(proof.merkleRoot).toBe(monitor.computeMerkleRoot());
        expect(verifyMerkleProof(proof)).toBe(true);
      }
    });

    it('generateMerkleProof → verifyMerkleProof round-trip with a single entry', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');

      const proof = monitor.generateMerkleProof(0);
      expect(verifyMerkleProof(proof)).toBe(true);
    });

    it('generateMerkleProof → verifyMerkleProof round-trip with odd number of entries', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      await monitor.evaluate('file.read', '/data/b');
      await monitor.evaluate('file.read', '/data/c');

      for (let i = 0; i < 3; i++) {
        const proof = monitor.generateMerkleProof(i);
        expect(verifyMerkleProof(proof)).toBe(true);
      }
    });

    it('verifyMerkleProof fails with a tampered entry hash', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      await monitor.evaluate('file.read', '/data/b');
      await monitor.evaluate('file.read', '/data/c');

      const proof = monitor.generateMerkleProof(1);
      // Tamper with the entry hash
      proof.entryHash = 'f'.repeat(64) as HashHex;

      expect(verifyMerkleProof(proof)).toBe(false);
    });

    it('verifyMerkleProof fails with a tampered merkle root', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      await monitor.evaluate('file.read', '/data/b');

      const proof = monitor.generateMerkleProof(0);
      proof.merkleRoot = 'b'.repeat(64) as HashHex;

      expect(verifyMerkleProof(proof)).toBe(false);
    });

    it('generateMerkleProof throws for out-of-range index', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');

      expect(() => monitor.generateMerkleProof(-1)).toThrow();
      expect(() => monitor.generateMerkleProof(1)).toThrow();
      expect(() => monitor.generateMerkleProof(100)).toThrow();
    });
  });

  describe('callbacks', () => {
    it('fires onAction callback for every evaluation', async () => {
      const actions: AuditEntry[] = [];
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, {
        mode: 'enforce',
        onAction: (entry) => actions.push(entry),
      });

      await monitor.evaluate('file.read', '/data/a');
      try {
        await monitor.evaluate('file.write', '/system/x');
      } catch {
        // expected
      }

      expect(actions).toHaveLength(2);
      expect(actions[0]!.action).toBe('file.read');
      expect(actions[1]!.action).toBe('file.write');
    });

    it('fires onViolation callback only for denied actions', async () => {
      const violations: AuditEntry[] = [];
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, {
        mode: 'enforce',
        onViolation: (entry) => violations.push(entry),
      });

      await monitor.evaluate('file.read', '/data/a');
      try {
        await monitor.evaluate('file.write', '/system/x');
      } catch {
        // expected
      }

      expect(violations).toHaveLength(1);
      expect(violations[0]!.action).toBe('file.write');
    });
  });

  describe('reset', () => {
    it('clears the audit log', async () => {
      const monitor = new Monitor(COVENANT_ID, CONSTRAINTS, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/a');
      await monitor.evaluate('file.read', '/data/b');
      expect(monitor.getAuditLog().count).toBe(2);

      monitor.reset();

      expect(monitor.getAuditLog().count).toBe(0);
      expect(monitor.getAuditLog().entries).toHaveLength(0);
      expect(monitor.computeMerkleRoot()).toBe('0'.repeat(64));
    });
  });
});

// ─── CapabilityGate ────────────────────────────────────────────────────────────

describe('CapabilityGate', () => {
  async function createGate(constraints?: string) {
    const keyPair = await generateKeyPair();
    return CapabilityGate.fromConstraints(
      COVENANT_ID,
      constraints ?? CONSTRAINTS,
      keyPair,
      'node',
    );
  }

  describe('fromConstraints', () => {
    it('only exposes permitted capabilities from permit statements', async () => {
      const gate = await createGate();

      const capabilities = gate.listCapabilities();
      expect(capabilities).toContain('file.read');
      // deny statements should not create capabilities
      expect(capabilities).not.toContain('file.write');
      expect(capabilities).not.toContain('network.send');
    });
  });

  describe('hasCapability', () => {
    it('returns true for permitted actions', async () => {
      const gate = await createGate();

      expect(gate.hasCapability('file.read')).toBe(true);
    });

    it('returns false for denied/unknown actions', async () => {
      const gate = await createGate();

      expect(gate.hasCapability('file.write')).toBe(false);
      expect(gate.hasCapability('network.send')).toBe(false);
      expect(gate.hasCapability('file.delete')).toBe(false);
      expect(gate.hasCapability('unknown.action')).toBe(false);
    });
  });

  describe('register', () => {
    it('registers a handler for a permitted action', async () => {
      const gate = await createGate();

      expect(() => {
        gate.register('file.read', async (resource) => `read ${resource}`);
      }).not.toThrow();
    });

    it('throws CapabilityError for a non-permitted action', async () => {
      const gate = await createGate();

      expect(() => {
        gate.register('file.write', async () => 'nope');
      }).toThrow(CapabilityError);
    });
  });

  describe('execute', () => {
    it('runs handler for a permitted action with matching resource', async () => {
      const gate = await createGate();
      gate.register('file.read', async (resource) => `data from ${resource}`);

      const result = await gate.execute<string>('file.read', '/data/users');
      expect(result).toBe('data from /data/users');
    });

    it('returns IMPOSSIBLE for completely unregistered/non-permitted actions', async () => {
      const gate = await createGate();

      await expect(
        gate.execute('unknown.action', '/whatever'),
      ).rejects.toThrow(CapabilityError);

      try {
        await gate.execute('unknown.action', '/whatever');
      } catch (err) {
        expect(err).toBeInstanceOf(CapabilityError);
        expect((err as CapabilityError).message).toContain('impossible');
      }

      // Verify execution log records IMPOSSIBLE
      const log = gate.getExecutionLog();
      expect(log.length).toBeGreaterThanOrEqual(1);
      expect(log[0]!.outcome).toBe('IMPOSSIBLE');
    });

    it('throws MonitorDeniedError when constraints deny the action at runtime', async () => {
      // Use constraints that permit file.read on /data/** but also deny on /data/secret
      const constraintsWithConflict = [
        "permit file.read on '/data/**'",
        "deny file.read on '/data/secret' severity critical",
      ].join('\n');
      const gate = await createGate(constraintsWithConflict);
      gate.register('file.read', async (resource) => `data from ${resource}`);

      // /data/secret is denied (deny wins at higher specificity)
      await expect(
        gate.execute('file.read', '/data/secret'),
      ).rejects.toThrow(MonitorDeniedError);

      // /data/public should still work
      const result = await gate.execute<string>('file.read', '/data/public');
      expect(result).toBe('data from /data/public');
    });

    it('throws CapabilityError when handler not registered but capability exists', async () => {
      const gate = await createGate();
      // Don't register any handler for file.read

      await expect(
        gate.execute('file.read', '/data/users'),
      ).rejects.toThrow(CapabilityError);

      const log = gate.getExecutionLog();
      const entry = log[log.length - 1]!;
      expect(entry.outcome).toBe('IMPOSSIBLE');
      expect(entry.error).toContain('No handler registered');
    });
  });

  describe('generateManifest → verifyManifest round-trip', () => {
    it('generates a valid manifest and verifies it', async () => {
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(
        COVENANT_ID,
        CONSTRAINTS,
        keyPair,
        'node',
      );

      const manifest = await gate.generateManifest();

      expect(manifest.covenantId).toBe(COVENANT_ID);
      expect(manifest.runtimeType).toBe('node');
      expect(manifest.runtimePublicKey).toBe(keyPair.publicKeyHex);
      expect(manifest.capabilities).toHaveLength(1); // only 1 permit statement
      expect(manifest.capabilities[0]!.action).toBe('file.read');
      expect(manifest.capabilities[0]!.resource).toBe('/data/**');
      expect(manifest.manifestHash).toBeTruthy();
      expect(manifest.runtimeSignature).toBeTruthy();
      expect(manifest.generatedAt).toBeTruthy();

      // Verify the manifest
      const isValid = await CapabilityGate.verifyManifest(manifest);
      expect(isValid).toBe(true);
    });

    it('verifyManifest fails with a tampered manifest hash', async () => {
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(
        COVENANT_ID,
        CONSTRAINTS,
        keyPair,
      );

      const manifest = await gate.generateManifest();
      manifest.manifestHash = 'f'.repeat(64) as HashHex;

      const isValid = await CapabilityGate.verifyManifest(manifest);
      expect(isValid).toBe(false);
    });

    it('verifyManifest fails with a tampered capability', async () => {
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(
        COVENANT_ID,
        CONSTRAINTS,
        keyPair,
      );

      const manifest = await gate.generateManifest();
      manifest.capabilities[0]!.action = 'file.write'; // tamper

      const isValid = await CapabilityGate.verifyManifest(manifest);
      expect(isValid).toBe(false);
    });

    it('verifyManifest fails with a tampered signature', async () => {
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(
        COVENANT_ID,
        CONSTRAINTS,
        keyPair,
      );

      const manifest = await gate.generateManifest();
      // Replace first chars of signature
      manifest.runtimeSignature = 'ff' + manifest.runtimeSignature.slice(2);

      const isValid = await CapabilityGate.verifyManifest(manifest);
      expect(isValid).toBe(false);
    });
  });

  describe('proveImpossible', () => {
    it('classifies permitted and non-permitted actions correctly', async () => {
      const gate = await createGate();

      const result = await gate.proveImpossible([
        'file.read',
        'file.write',
        'network.send',
        'file.delete',
        'process.exec',
      ]);

      expect(result.possible).toContain('file.read');
      expect(result.impossible).toContain('file.write');
      expect(result.impossible).toContain('network.send');
      expect(result.impossible).toContain('file.delete');
      expect(result.impossible).toContain('process.exec');
      expect(result.manifestHash).toBeTruthy();
    });

    it('returns empty arrays when given no actions', async () => {
      const gate = await createGate();

      const result = await gate.proveImpossible([]);

      expect(result.possible).toHaveLength(0);
      expect(result.impossible).toHaveLength(0);
      expect(result.manifestHash).toBeTruthy();
    });
  });

  describe('execution log', () => {
    it('records all execution attempts', async () => {
      const gate = await createGate();
      gate.register('file.read', async (resource) => `data from ${resource}`);

      await gate.execute('file.read', '/data/test1');
      await gate.execute('file.read', '/data/test2');
      try {
        await gate.execute('unknown.action', '/whatever');
      } catch {
        // expected
      }

      const log = gate.getExecutionLog();
      expect(log).toHaveLength(3);
      expect(log[0]!.outcome).toBe('EXECUTED');
      expect(log[1]!.outcome).toBe('EXECUTED');
      expect(log[2]!.outcome).toBe('IMPOSSIBLE');
    });
  });
});

// ─── Extended Monitor tests ──────────────────────────────────────────────────

describe('Monitor - extended', () => {
  describe('evaluate with various CCL constructs', () => {
    it('permits action matching wildcard ** resource', async () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      const result = await monitor.evaluate('file.read', '/any/path/at/all', {});
      expect(result.permitted).toBe(true);
    });

    it('permits action with single wildcard * segment', async () => {
      const constraints = "permit file.read on '/data/*'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      const result = await monitor.evaluate('file.read', '/data/file.csv', {});
      expect(result.permitted).toBe(true);
    });

    it('denies action in enforce mode and throws MonitorDeniedError', async () => {
      const constraints = "deny file.write on '**' severity critical";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      await expect(
        monitor.evaluate('file.write', '/any/path', {})
      ).rejects.toThrow(MonitorDeniedError);
    });

    it('denies action in audit mode but does not throw', async () => {
      const constraints = "deny file.write on '**' severity critical";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'log_only' });

      const result = await monitor.evaluate('file.write', '/any/path', {});
      expect(result.permitted).toBe(false);
      expect(result.matchedRule?.type).toBe('deny');
    });

    it('deny-wins over permit for same action/resource', async () => {
      const constraints = [
        "permit file.write on '/data/**'",
        "deny file.write on '/data/secret/**' severity high",
      ].join('\n');
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'log_only' });

      // Permitted path
      const r1 = await monitor.evaluate('file.write', '/data/public/file.txt', {});
      expect(r1.permitted).toBe(true);

      // Denied path (more specific deny wins)
      const r2 = await monitor.evaluate('file.write', '/data/secret/key.pem', {});
      expect(r2.permitted).toBe(false);
    });

    it('handles conditions in evaluation', async () => {
      const constraints = "permit file.read on '/data/**' when user = 'admin'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'log_only' });

      const r1 = await monitor.evaluate('file.read', '/data/file.csv', { user: 'admin' });
      expect(r1.permitted).toBe(true);

      const r2 = await monitor.evaluate('file.read', '/data/file.csv', { user: 'guest' });
      expect(r2.permitted).toBe(false);
    });

    it('handles multiple permit rules', async () => {
      const constraints = [
        "permit file.read on '/data/**'",
        "permit api.call on '/v1/**'",
        "permit review.generate on '/reviews/**'",
      ].join('\n');
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'log_only' });

      expect((await monitor.evaluate('file.read', '/data/a', {})).permitted).toBe(true);
      expect((await monitor.evaluate('api.call', '/v1/users', {})).permitted).toBe(true);
      expect((await monitor.evaluate('review.generate', '/reviews/pr-123', {})).permitted).toBe(true);
      expect((await monitor.evaluate('file.delete', '/data/a', {})).permitted).toBe(false);
    });
  });

  describe('audit log operations', () => {
    it('records all evaluated actions in audit log', async () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      for (let i = 0; i < 10; i++) {
        await monitor.evaluate('file.read', `/data/file-${i}`, {});
      }

      const log = monitor.getAuditLog();
      expect(log.count).toBe(10);
      expect(log.entries).toHaveLength(10);
    });

    it('audit log entries have correct structure', async () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/data/test.csv', { user: 'alice' });

      const entry = monitor.getAuditLog().entries[0]!;
      expect(entry.action).toBe('file.read');
      expect(entry.resource).toBe('/data/test.csv');
      expect(entry.outcome).toBe('EXECUTED');
      expect(entry.timestamp).toBeTruthy();
      expect(entry.hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('audit log entries form a hash chain', async () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      for (let i = 0; i < 5; i++) {
        await monitor.evaluate('file.read', `/file-${i}`, {});
      }

      const entries = monitor.getAuditLog().entries;
      expect(entries[0]!.previousHash).toBe('0'.repeat(64));

      for (let i = 1; i < entries.length; i++) {
        expect(entries[i]!.previousHash).toBe(entries[i - 1]!.hash);
      }
    });

    it('verifyAuditLogIntegrity detects tampering', async () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      for (let i = 0; i < 5; i++) {
        await monitor.evaluate('file.read', `/file-${i}`, {});
      }

      expect(monitor.verifyAuditLogIntegrity()).toBe(true);
    });

    it('empty audit log is valid', () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      expect(monitor.verifyAuditLogIntegrity()).toBe(true);
      expect(monitor.getAuditLog().count).toBe(0);
    });
  });

  describe('Merkle tree operations', () => {
    it('computes Merkle root for audit log', async () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      for (let i = 0; i < 8; i++) {
        await monitor.evaluate('file.read', `/file-${i}`, {});
      }

      const root = monitor.computeMerkleRoot();
      expect(root).toMatch(/^[0-9a-f]{64}$/);
    });

    it('Merkle root changes when new entries added', async () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      await monitor.evaluate('file.read', '/file-0', {});
      const root1 = monitor.computeMerkleRoot();

      await monitor.evaluate('file.read', '/file-1', {});
      const root2 = monitor.computeMerkleRoot();

      expect(root1).not.toBe(root2);
    });

    it('generates Merkle proof for specific entry', async () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      for (let i = 0; i < 8; i++) {
        await monitor.evaluate('file.read', `/file-${i}`, {});
      }

      const proof = monitor.generateMerkleProof(3);
      expect(proof).toBeDefined();
      if (proof) {
        expect(verifyMerkleProof(proof)).toBe(true);
      }
    });

    it('Merkle proof for first entry', async () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      for (let i = 0; i < 4; i++) {
        await monitor.evaluate('file.read', `/file-${i}`, {});
      }

      const proof = monitor.generateMerkleProof(0);
      expect(proof).toBeDefined();
      if (proof) {
        expect(verifyMerkleProof(proof)).toBe(true);
      }
    });

    it('Merkle proof for last entry', async () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      for (let i = 0; i < 4; i++) {
        await monitor.evaluate('file.read', `/file-${i}`, {});
      }

      const proof = monitor.generateMerkleProof(3);
      expect(proof).toBeDefined();
      if (proof) {
        expect(verifyMerkleProof(proof)).toBe(true);
      }
    });

    it('Merkle root is deterministic for same log', async () => {
      const constraints = "permit file.read on '**'";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      for (let i = 0; i < 4; i++) {
        await monitor.evaluate('file.read', `/file-${i}`, {});
      }

      const root1 = monitor.computeMerkleRoot();
      const root2 = monitor.computeMerkleRoot();
      expect(root1).toBe(root2);
    });
  });

  describe('rate limiting', () => {
    it('tracks rate limit state across evaluations', async () => {
      const constraints = [
        "permit api.call on '**'",
        "limit api.call 5 per 60 seconds severity medium",
      ].join('\n');
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      // Should succeed 5 times
      for (let i = 0; i < 5; i++) {
        const r = await monitor.evaluate('api.call', '/endpoint', {});
        expect(r.permitted).toBe(true);
      }
    });

    it('non-rate-limited actions are not affected by limit rules', async () => {
      const constraints = [
        "permit file.read on '**'",
        "permit api.call on '**'",
        "limit api.call 3 per 60 seconds severity medium",
      ].join('\n');
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      // file.read has no limit
      for (let i = 0; i < 20; i++) {
        const r = await monitor.evaluate('file.read', `/data/file-${i}`, {});
        expect(r.permitted).toBe(true);
      }
    });
  });

  describe('MonitorDeniedError properties', () => {
    it('has correct action and resource properties', async () => {
      const constraints = "deny file.delete on '**' severity critical";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      try {
        await monitor.evaluate('file.delete', '/important/file', {});
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(MonitorDeniedError);
        const denied = err as MonitorDeniedError;
        expect(denied.action).toBe('file.delete');
        expect(denied.resource).toBe('/important/file');
        expect(denied.severity).toBe('critical');
      }
    });

    it('includes matched rule information', async () => {
      const constraints = "deny network.send on '/external/**' severity high";
      const monitor = new Monitor(COVENANT_ID, constraints, { mode: 'enforce' });

      try {
        await monitor.evaluate('network.send', '/external/api', {});
        expect.fail('Should have thrown');
      } catch (err) {
        const denied = err as MonitorDeniedError;
        expect(denied.matchedRule).toBeDefined();
        expect(denied.matchedRule?.type).toBe('deny');
      }
    });
  });
});

// ─── Extended CapabilityGate tests ──────────────────────────────────────────

describe('CapabilityGate - extended', () => {
  describe('fromConstraints parsing', () => {
    it('parses multiple permit rules into capabilities', async () => {
      const constraints = [
        "permit file.read on '/data/**'",
        "permit api.call on '/v1/**'",
        "deny file.delete on '**' severity critical",
      ].join('\n');

      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, constraints, keyPair);
      expect(gate.hasCapability('file.read')).toBe(true);
      expect(gate.hasCapability('api.call')).toBe(true);
      expect(gate.hasCapability('file.delete')).toBe(false);
    });

    it('handles simple constraints', async () => {
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, "permit file.read on '**'", keyPair);
      expect(gate.hasCapability('file.read')).toBe(true);
    });
  });

  describe('capability manifest', () => {
    it('generates manifest listing all capabilities', async () => {
      const constraints = [
        "permit file.read on '/data/**'",
        "permit api.call on '/v1/**'",
      ].join('\n');

      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, constraints, keyPair);
      const manifest = await gate.generateManifest();

      expect(manifest.covenantId).toBe(COVENANT_ID);
      expect(manifest.capabilities).toBeDefined();
      expect(manifest.capabilities.length).toBeGreaterThan(0);
    });

    it('manifest includes capability hashes', async () => {
      const constraints = "permit file.read on '/data/**'";
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, constraints, keyPair);
      const manifest = await gate.generateManifest();

      expect(manifest.manifestHash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('verifyManifest returns true for unmodified manifest', async () => {
      const constraints = "permit file.read on '/data/**'";
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, constraints, keyPair);
      const manifest = await gate.generateManifest();

      expect(await CapabilityGate.verifyManifest(manifest)).toBe(true);
    });

    it('verifyManifest returns false for tampered manifest', async () => {
      const constraints = "permit file.read on '/data/**'";
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, constraints, keyPair);
      const manifest = await gate.generateManifest();

      const tampered = { ...manifest, manifestHash: 'f'.repeat(64) };
      expect(await CapabilityGate.verifyManifest(tampered)).toBe(false);
    });
  });

  describe('proveImpossible', () => {
    it('proves denied action is impossible', async () => {
      const constraints = "deny file.delete on '**' severity critical";
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, constraints, keyPair);

      const proof = await gate.proveImpossible(['file.delete']);
      expect(proof).toBeDefined();
      expect(proof.impossible).toContain('file.delete');
      expect(proof.possible).not.toContain('file.delete');
    });

    it('proves unpermitted action is impossible', async () => {
      const constraints = "permit file.read on '/data/**'";
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, constraints, keyPair);

      // file.write is not permitted
      const proof = await gate.proveImpossible(['file.write']);
      expect(proof).toBeDefined();
      expect(proof.impossible).toContain('file.write');
    });
  });

  describe('register and execute', () => {
    it('registers handler and executes permitted action', async () => {
      const constraints = "permit file.read on '/data/**'";
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, constraints, keyPair);

      gate.register('file.read', async (resource: string) => {
        return `read: ${resource}`;
      });

      const result = await gate.execute('file.read', '/data/test.csv');
      expect(result).toBe('read: /data/test.csv');
    });

    it('throws CapabilityError for non-permitted action', async () => {
      const constraints = "deny file.delete on '**' severity critical";
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, constraints, keyPair);

      // file.delete has no permit, so execute should throw CapabilityError
      await expect(
        gate.execute('file.delete', '/important/file')
      ).rejects.toThrow(CapabilityError);
    });

    it('throws CapabilityError for unregistered action', async () => {
      const constraints = "permit file.read on '**'";
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, constraints, keyPair);

      // Don't register any handler
      await expect(
        gate.execute('file.read', '/data/test')
      ).rejects.toThrow(CapabilityError);
    });

    it('execution log tracks outcomes', async () => {
      const constraints = [
        "permit file.read on '**'",
        "deny file.write on '**' severity critical",
      ].join('\n');
      const keyPair = await generateKeyPair();
      const gate = await CapabilityGate.fromConstraints(COVENANT_ID, constraints, keyPair);

      gate.register('file.read', async (r) => `read ${r}`);

      await gate.execute('file.read', '/data/a');

      try {
        await gate.execute('file.write', '/data/b');
      } catch {
        // Expected - file.write is not permitted (no permit rule)
      }

      const log = gate.getExecutionLog();
      expect(log).toHaveLength(2);
      expect(log[0]!.outcome).toBe('EXECUTED');
      expect(log[1]!.outcome).toBe('IMPOSSIBLE');
    });
  });
});

// ─── Behavioral Provenance ────────────────────────────────────────────────────

describe('Behavioral Provenance', () => {
  const TEST_COVENANT_ID = 'b'.repeat(64);

  describe('createProvenanceRecord', () => {
    it('creates a record with all required fields', () => {
      const record = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/users',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'permit-file-read',
      });

      expect(record.actionId).toBeTruthy();
      expect(record.action).toBe('file.read');
      expect(record.resource).toBe('/data/users');
      expect(record.timestamp).toBeGreaterThan(0);
      expect(record.covenantId).toBe(TEST_COVENANT_ID);
      expect(record.ruleReference).toBe('permit-file-read');
      expect(record.authorizationHash).toBeTruthy();
      expect(record.previousRecordHash).toBe('genesis');
      expect(record.recordHash).toBeTruthy();
    });

    it('uses "genesis" as previousRecordHash when not provided', () => {
      const record = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/test',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      expect(record.previousRecordHash).toBe('genesis');
    });

    it('uses provided previousRecordHash when given', () => {
      const first = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      const second = createProvenanceRecord({
        action: 'file.write',
        resource: '/data/b',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-2',
        previousRecordHash: first.recordHash,
      });

      expect(second.previousRecordHash).toBe(first.recordHash);
    });

    it('generates unique actionIds for each record', () => {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      const r2 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      expect(r1.actionId).not.toBe(r2.actionId);
      expect(r1.recordHash).not.toBe(r2.recordHash);
    });

    it('produces deterministic authorizationHash for same covenant and rule', () => {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      const r2 = createProvenanceRecord({
        action: 'file.write',
        resource: '/data/b',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      // Same covenantId + ruleReference should produce the same authorizationHash
      expect(r1.authorizationHash).toBe(r2.authorizationHash);
    });

    it('produces different authorizationHash for different rules', () => {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      const r2 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-2',
      });

      expect(r1.authorizationHash).not.toBe(r2.authorizationHash);
    });
  });

  describe('buildProvenanceChain', () => {
    it('builds an empty chain', () => {
      const chain = buildProvenanceChain('agent-1', []);

      expect(chain.agentId).toBe('agent-1');
      expect(chain.records).toHaveLength(0);
      expect(chain.chainHead).toBe('genesis');
      expect(chain.chainLength).toBe(0);
      expect(chain.integrityVerified).toBe(true);
    });

    it('builds a valid chain from properly linked records', () => {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      const r2 = createProvenanceRecord({
        action: 'file.write',
        resource: '/data/b',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-2',
        previousRecordHash: r1.recordHash,
      });

      const r3 = createProvenanceRecord({
        action: 'api.call',
        resource: '/v1/users',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-3',
        previousRecordHash: r2.recordHash,
      });

      const chain = buildProvenanceChain('agent-1', [r1, r2, r3]);

      expect(chain.agentId).toBe('agent-1');
      expect(chain.records).toHaveLength(3);
      expect(chain.chainHead).toBe(r3.recordHash);
      expect(chain.chainLength).toBe(3);
      expect(chain.integrityVerified).toBe(true);
    });

    it('detects broken chain linkage', () => {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      const r2 = createProvenanceRecord({
        action: 'file.write',
        resource: '/data/b',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-2',
        // Intentionally NOT linking to r1
      });

      const chain = buildProvenanceChain('agent-1', [r1, r2]);

      expect(chain.integrityVerified).toBe(false);
    });

    it('returns a copy of records, not a reference', () => {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      const records = [r1];
      const chain = buildProvenanceChain('agent-1', records);

      // Modifying original array should not affect chain
      records.push(createProvenanceRecord({
        action: 'file.write',
        resource: '/data/b',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-2',
      }));

      expect(chain.records).toHaveLength(1);
    });

    it('builds a single-record chain', () => {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      const chain = buildProvenanceChain('agent-1', [r1]);

      expect(chain.chainHead).toBe(r1.recordHash);
      expect(chain.chainLength).toBe(1);
      expect(chain.integrityVerified).toBe(true);
    });
  });

  describe('verifyProvenance', () => {
    it('returns valid for a correct chain', () => {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      const r2 = createProvenanceRecord({
        action: 'file.write',
        resource: '/data/b',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-2',
        previousRecordHash: r1.recordHash,
      });

      const chain = buildProvenanceChain('agent-1', [r1, r2]);
      const result = verifyProvenance(chain);

      expect(result.valid).toBe(true);
      expect(result.brokenLinks).toHaveLength(0);
      expect(result.orphanedRecords).toHaveLength(0);
    });

    it('returns valid for an empty chain', () => {
      const chain = buildProvenanceChain('agent-1', []);
      const result = verifyProvenance(chain);

      expect(result.valid).toBe(true);
      expect(result.brokenLinks).toHaveLength(0);
      expect(result.orphanedRecords).toHaveLength(0);
    });

    it('detects broken links in the chain', () => {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      // r2 does not link to r1 (uses a fake previous hash)
      const r2: ProvenanceRecord = {
        ...createProvenanceRecord({
          action: 'file.write',
          resource: '/data/b',
          covenantId: TEST_COVENANT_ID,
          ruleReference: 'rule-2',
          previousRecordHash: 'fake-hash-value',
        }),
      };

      const chain = buildProvenanceChain('agent-1', [r1, r2]);
      const result = verifyProvenance(chain);

      expect(result.valid).toBe(false);
      expect(result.brokenLinks).toContain(1);
    });

    it('detects orphaned records that reference non-existent hashes', () => {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      // Create r2 with a previousRecordHash that does not exist in the chain
      const r2: ProvenanceRecord = {
        ...createProvenanceRecord({
          action: 'file.write',
          resource: '/data/b',
          covenantId: TEST_COVENANT_ID,
          ruleReference: 'rule-2',
          previousRecordHash: 'nonexistent-hash-abc123',
        }),
      };

      const chain = buildProvenanceChain('agent-1', [r1, r2]);
      const result = verifyProvenance(chain);

      expect(result.valid).toBe(false);
      expect(result.orphanedRecords).toContain(1);
    });

    it('reports both broken links and orphaned records', () => {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/a',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });

      const r2 = createProvenanceRecord({
        action: 'file.write',
        resource: '/data/b',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-2',
        previousRecordHash: r1.recordHash,
      });

      // r3 references a non-existent hash, breaking the link AND being orphaned
      const r3: ProvenanceRecord = {
        ...createProvenanceRecord({
          action: 'api.call',
          resource: '/v1/test',
          covenantId: TEST_COVENANT_ID,
          ruleReference: 'rule-3',
          previousRecordHash: 'completely-invalid-hash',
        }),
      };

      const chain = buildProvenanceChain('agent-1', [r1, r2, r3]);
      const result = verifyProvenance(chain);

      expect(result.valid).toBe(false);
      expect(result.brokenLinks).toContain(2);
      expect(result.orphanedRecords).toContain(2);
    });
  });

  describe('queryProvenance', () => {
    function buildTestChain(): ProvenanceChain {
      const r1 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/users',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
      });
      // Override timestamp for predictable testing
      (r1 as any).timestamp = 1000;

      const r2 = createProvenanceRecord({
        action: 'file.write',
        resource: '/data/logs',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-2',
        previousRecordHash: r1.recordHash,
      });
      (r2 as any).timestamp = 2000;

      const r3 = createProvenanceRecord({
        action: 'api.call',
        resource: '/v1/users',
        covenantId: 'c'.repeat(64),
        ruleReference: 'rule-3',
        previousRecordHash: r2.recordHash,
      });
      (r3 as any).timestamp = 3000;

      const r4 = createProvenanceRecord({
        action: 'file.read',
        resource: '/data/config',
        covenantId: TEST_COVENANT_ID,
        ruleReference: 'rule-1',
        previousRecordHash: r3.recordHash,
      });
      (r4 as any).timestamp = 4000;

      return buildProvenanceChain('agent-1', [r1, r2, r3, r4]);
    }

    it('queries by action', () => {
      const chain = buildTestChain();
      const results = queryProvenance(chain, { action: 'file.read' });

      expect(results).toHaveLength(2);
      expect(results.every((r) => r.action === 'file.read')).toBe(true);
    });

    it('queries by resource', () => {
      const chain = buildTestChain();
      const results = queryProvenance(chain, { resource: '/data/users' });

      expect(results).toHaveLength(1);
      expect(results[0]!.resource).toBe('/data/users');
    });

    it('queries by covenantId', () => {
      const chain = buildTestChain();
      const results = queryProvenance(chain, { covenantId: TEST_COVENANT_ID });

      expect(results).toHaveLength(3);
      expect(results.every((r) => r.covenantId === TEST_COVENANT_ID)).toBe(true);
    });

    it('queries by time range', () => {
      const chain = buildTestChain();
      const results = queryProvenance(chain, {
        timeRange: { start: 1500, end: 3500 },
      });

      expect(results).toHaveLength(2);
      expect(results.every((r) => r.timestamp >= 1500 && r.timestamp <= 3500)).toBe(true);
    });

    it('queries with multiple filters combined (AND logic)', () => {
      const chain = buildTestChain();
      const results = queryProvenance(chain, {
        action: 'file.read',
        covenantId: TEST_COVENANT_ID,
      });

      expect(results).toHaveLength(2);
      expect(results.every((r) => r.action === 'file.read' && r.covenantId === TEST_COVENANT_ID)).toBe(true);
    });

    it('returns empty array when no records match', () => {
      const chain = buildTestChain();
      const results = queryProvenance(chain, { action: 'network.send' });

      expect(results).toHaveLength(0);
    });

    it('returns all records when no filters are specified', () => {
      const chain = buildTestChain();
      const results = queryProvenance(chain, {});

      expect(results).toHaveLength(4);
    });
  });
});

// ─── Defense in Depth ─────────────────────────────────────────────────────────

describe('Defense in Depth', () => {
  describe('createDefenseConfig', () => {
    it('creates a config with default values', () => {
      const config = createDefenseConfig();

      expect(config.layers).toHaveLength(3);
      expect(config.minimumLayers).toBe(2);
      expect(config.maxAcceptableBreachProbability).toBe(0.001);

      // Check default layers
      const runtime = config.layers.find((l) => l.type === 'runtime');
      const attestation = config.layers.find((l) => l.type === 'attestation');
      const proof = config.layers.find((l) => l.type === 'proof');

      expect(runtime).toBeDefined();
      expect(runtime!.bypassProbability).toBe(0.1);
      expect(runtime!.active).toBe(true);

      expect(attestation).toBeDefined();
      expect(attestation!.bypassProbability).toBe(0.05);
      expect(attestation!.active).toBe(true);

      expect(proof).toBeDefined();
      expect(proof!.bypassProbability).toBe(0.01);
      expect(proof!.active).toBe(true);
    });

    it('accepts custom bypass probabilities', () => {
      const config = createDefenseConfig({
        runtimeBypass: 0.2,
        attestationBypass: 0.1,
        proofBypass: 0.05,
      });

      const runtime = config.layers.find((l) => l.type === 'runtime')!;
      const attestation = config.layers.find((l) => l.type === 'attestation')!;
      const proof = config.layers.find((l) => l.type === 'proof')!;

      expect(runtime.bypassProbability).toBe(0.2);
      expect(attestation.bypassProbability).toBe(0.1);
      expect(proof.bypassProbability).toBe(0.05);
    });

    it('accepts custom minimum layers and threshold', () => {
      const config = createDefenseConfig({
        minimumLayers: 3,
        maxBreachProb: 0.0001,
      });

      expect(config.minimumLayers).toBe(3);
      expect(config.maxAcceptableBreachProbability).toBe(0.0001);
    });

    it('all layers have lastVerified timestamps', () => {
      const before = Date.now();
      const config = createDefenseConfig();
      const after = Date.now();

      for (const layer of config.layers) {
        expect(layer.lastVerified).toBeGreaterThanOrEqual(before);
        expect(layer.lastVerified).toBeLessThanOrEqual(after);
      }
    });
  });

  describe('analyzeDefense', () => {
    it('computes breach probability as product of active layer bypass probabilities', () => {
      const config = createDefenseConfig({
        runtimeBypass: 0.1,
        attestationBypass: 0.05,
        proofBypass: 0.01,
      });

      const analysis = analyzeDefense(config);

      // 0.1 * 0.05 * 0.01 = 0.00005
      expect(analysis.independentBreachProbability).toBeCloseTo(0.00005, 10);
      expect(analysis.activeLayers).toBe(3);
    });

    it('reports meetsThreshold correctly when below threshold', () => {
      const config = createDefenseConfig({
        runtimeBypass: 0.1,
        attestationBypass: 0.05,
        proofBypass: 0.01,
        maxBreachProb: 0.001,
      });

      const analysis = analyzeDefense(config);

      // 0.00005 <= 0.001 → meets threshold
      expect(analysis.meetsThreshold).toBe(true);
    });

    it('reports meetsThreshold correctly when above threshold', () => {
      const config = createDefenseConfig({
        runtimeBypass: 0.5,
        attestationBypass: 0.5,
        proofBypass: 0.5,
        maxBreachProb: 0.001,
      });

      const analysis = analyzeDefense(config);

      // 0.5 * 0.5 * 0.5 = 0.125 > 0.001 → does not meet threshold
      expect(analysis.meetsThreshold).toBe(false);
    });

    it('identifies the weakest layer (highest bypass probability)', () => {
      const config = createDefenseConfig({
        runtimeBypass: 0.1,
        attestationBypass: 0.05,
        proofBypass: 0.01,
      });

      const analysis = analyzeDefense(config);

      expect(analysis.weakestLayer).toBeDefined();
      expect(analysis.weakestLayer!.name).toBe('runtime');
      expect(analysis.weakestLayer!.bypassProbability).toBe(0.1);
    });

    it('handles disabled layers by excluding them from probability calculation', () => {
      const config = createDefenseConfig({
        runtimeBypass: 0.1,
        attestationBypass: 0.05,
        proofBypass: 0.01,
      });

      const withDisabled = disableLayer(config, 'proof');
      const analysis = analyzeDefense(withDisabled);

      // Only runtime (0.1) and attestation (0.05) are active
      // 0.1 * 0.05 = 0.005
      expect(analysis.independentBreachProbability).toBeCloseTo(0.005, 10);
      expect(analysis.activeLayers).toBe(2);
    });

    it('returns breach probability of 1 when no layers are active', () => {
      let config = createDefenseConfig();
      config = disableLayer(config, 'runtime');
      config = disableLayer(config, 'attestation');
      config = disableLayer(config, 'proof');

      const analysis = analyzeDefense(config);

      expect(analysis.independentBreachProbability).toBe(1);
      expect(analysis.activeLayers).toBe(0);
      expect(analysis.meetsThreshold).toBe(false);
      expect(analysis.weakestLayer).toBeNull();
    });

    it('provides recommendation when below minimum layers', () => {
      let config = createDefenseConfig({ minimumLayers: 3 });
      config = disableLayer(config, 'proof');

      const analysis = analyzeDefense(config);

      expect(analysis.activeLayers).toBe(2);
      expect(analysis.recommendation).toContain('2');
      expect(analysis.recommendation).toContain('3');
      expect(analysis.recommendation).toContain('required');
    });

    it('provides recommendation to strengthen weakest layer when threshold not met', () => {
      const config = createDefenseConfig({
        runtimeBypass: 0.5,
        attestationBypass: 0.5,
        proofBypass: 0.5,
        maxBreachProb: 0.001,
      });

      const analysis = analyzeDefense(config);

      expect(analysis.meetsThreshold).toBe(false);
      expect(analysis.recommendation).toContain('Strengthen');
    });

    it('provides positive recommendation when threshold is met', () => {
      const config = createDefenseConfig({
        runtimeBypass: 0.1,
        attestationBypass: 0.05,
        proofBypass: 0.01,
        maxBreachProb: 0.001,
      });

      const analysis = analyzeDefense(config);

      expect(analysis.meetsThreshold).toBe(true);
      expect(analysis.recommendation).toContain('meets threshold');
    });

    it('returns the analyzed config in the result', () => {
      const config = createDefenseConfig();
      const analysis = analyzeDefense(config);

      expect(analysis.config).toBe(config);
    });
  });

  describe('addDefenseLayer', () => {
    it('adds a custom layer to the configuration', () => {
      const config = createDefenseConfig();
      const customLayer: DefenseLayer = {
        name: 'network-isolation',
        type: 'runtime',
        bypassProbability: 0.02,
        active: true,
        lastVerified: Date.now(),
      };

      const updated = addDefenseLayer(config, customLayer);

      expect(updated.layers).toHaveLength(4);
      expect(updated.layers[3]!.name).toBe('network-isolation');
      expect(updated.layers[3]!.bypassProbability).toBe(0.02);
    });

    it('does not modify the original config', () => {
      const config = createDefenseConfig();
      const originalLength = config.layers.length;

      addDefenseLayer(config, {
        name: 'extra',
        type: 'proof',
        bypassProbability: 0.03,
        active: true,
        lastVerified: Date.now(),
      });

      expect(config.layers).toHaveLength(originalLength);
    });

    it('added layer affects breach probability analysis', () => {
      const config = createDefenseConfig({
        runtimeBypass: 0.1,
        attestationBypass: 0.05,
        proofBypass: 0.01,
      });

      const beforeAnalysis = analyzeDefense(config);
      const beforeProb = beforeAnalysis.independentBreachProbability;

      const updated = addDefenseLayer(config, {
        name: 'extra-proof',
        type: 'proof',
        bypassProbability: 0.02,
        active: true,
        lastVerified: Date.now(),
      });

      const afterAnalysis = analyzeDefense(updated);
      const afterProb = afterAnalysis.independentBreachProbability;

      // Adding a layer should reduce breach probability
      expect(afterProb).toBeLessThan(beforeProb);
      // 0.00005 * 0.02 = 0.000001
      expect(afterProb).toBeCloseTo(0.000001, 10);
    });

    it('can add inactive layers without affecting breach probability', () => {
      const config = createDefenseConfig();
      const beforeAnalysis = analyzeDefense(config);

      const updated = addDefenseLayer(config, {
        name: 'inactive-layer',
        type: 'attestation',
        bypassProbability: 0.5,
        active: false,
        lastVerified: Date.now(),
      });

      const afterAnalysis = analyzeDefense(updated);

      expect(afterAnalysis.independentBreachProbability).toBe(beforeAnalysis.independentBreachProbability);
      expect(afterAnalysis.activeLayers).toBe(beforeAnalysis.activeLayers);
    });
  });

  describe('disableLayer', () => {
    it('disables a named layer', () => {
      const config = createDefenseConfig();
      const updated = disableLayer(config, 'runtime');

      const runtimeLayer = updated.layers.find((l) => l.name === 'runtime')!;
      expect(runtimeLayer.active).toBe(false);
    });

    it('does not modify the original config', () => {
      const config = createDefenseConfig();
      disableLayer(config, 'runtime');

      const runtimeLayer = config.layers.find((l) => l.name === 'runtime')!;
      expect(runtimeLayer.active).toBe(true);
    });

    it('leaves other layers unchanged', () => {
      const config = createDefenseConfig();
      const updated = disableLayer(config, 'runtime');

      const attestation = updated.layers.find((l) => l.name === 'attestation')!;
      const proof = updated.layers.find((l) => l.name === 'proof')!;

      expect(attestation.active).toBe(true);
      expect(proof.active).toBe(true);
    });

    it('disabling below minimum triggers warning in analysis', () => {
      const config = createDefenseConfig({ minimumLayers: 3 });
      const updated = disableLayer(config, 'proof');
      const analysis = analyzeDefense(updated);

      expect(analysis.activeLayers).toBe(2);
      expect(analysis.recommendation).toContain('required');
    });

    it('disabling a non-existent layer name returns unchanged config', () => {
      const config = createDefenseConfig();
      const updated = disableLayer(config, 'nonexistent');

      expect(updated.layers.filter((l) => l.active)).toHaveLength(3);
    });

    it('multiple disables work correctly', () => {
      let config = createDefenseConfig();
      config = disableLayer(config, 'runtime');
      config = disableLayer(config, 'attestation');

      const activeLayers = config.layers.filter((l) => l.active);
      expect(activeLayers).toHaveLength(1);
      expect(activeLayers[0]!.name).toBe('proof');
    });
  });

  describe('threshold checking end-to-end', () => {
    it('default config meets default threshold', () => {
      const config = createDefenseConfig();
      const analysis = analyzeDefense(config);

      // 0.1 * 0.05 * 0.01 = 0.00005 <= 0.001
      expect(analysis.meetsThreshold).toBe(true);
    });

    it('high bypass probabilities fail threshold', () => {
      const config = createDefenseConfig({
        runtimeBypass: 0.3,
        attestationBypass: 0.2,
        proofBypass: 0.1,
        maxBreachProb: 0.001,
      });

      const analysis = analyzeDefense(config);

      // 0.3 * 0.2 * 0.1 = 0.006 > 0.001
      expect(analysis.meetsThreshold).toBe(false);
    });

    it('adding layers can bring breach probability below threshold', () => {
      const config = createDefenseConfig({
        runtimeBypass: 0.3,
        attestationBypass: 0.2,
        proofBypass: 0.1,
        maxBreachProb: 0.001,
      });

      // Initially does not meet threshold
      expect(analyzeDefense(config).meetsThreshold).toBe(false);

      // Add a strong additional layer
      const updated = addDefenseLayer(config, {
        name: 'hardware-enclave',
        type: 'proof',
        bypassProbability: 0.01,
        active: true,
        lastVerified: Date.now(),
      });

      // 0.3 * 0.2 * 0.1 * 0.01 = 0.00006 <= 0.001
      const analysis = analyzeDefense(updated);
      expect(analysis.meetsThreshold).toBe(true);
      expect(analysis.activeLayers).toBe(4);
    });
  });
});
