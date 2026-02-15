import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  generateKeyPair,
  sha256String,
  toHex,
  fromHex,
  verify,
  canonicalizeJson,
} from '@stele/crypto';
import type { KeyPair } from '@stele/crypto';
import { buildCovenant, PROTOCOL_VERSION } from '@stele/core';
import type { CovenantDocument } from '@stele/core';

import {
  buildDiscoveryDocument,
  validateDiscoveryDocument,
  buildKeyEntry,
  buildKeySet,
  WELL_KNOWN_PATH,
  CONFIGURATION_PATH,
  STELE_MEDIA_TYPE,
  MAX_DOCUMENT_AGE_MS,
  DiscoveryClient,
  DiscoveryServer,
} from '../index.js';
import type {
  DiscoveryDocument,
  AgentKeyEntry,
  CrossPlatformVerificationRequest,
} from '../index.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const TEST_ISSUER = 'https://platform.example';

/** Build a minimal valid discovery document (unsigned). */
function makeMinimalDoc(): DiscoveryDocument {
  return {
    issuer: TEST_ISSUER,
    keys_endpoint: `${TEST_ISSUER}/.well-known/stele/keys`,
    covenants_endpoint: `${TEST_ISSUER}/.well-known/stele/covenants`,
    protocol_versions_supported: ['1.0'],
    signature_schemes_supported: ['ed25519'],
    hash_algorithms_supported: ['sha256'],
    enforcement_types_supported: ['capability', 'monitor', 'audit'],
    proof_types_supported: ['capability_manifest', 'audit_log', 'zkp'],
    updated_at: new Date().toISOString(),
  };
}

/** Create a mock Response-like object. */
function mockResponse(body: unknown, ok = true, status = 200): Response {
  return {
    ok,
    status,
    statusText: ok ? 'OK' : 'Internal Server Error',
    json: async () => body,
    headers: new Headers(),
    redirected: false,
    type: 'basic' as Response['type'],
    url: '',
    body: null,
    bodyUsed: false,
    clone: () => mockResponse(body, ok, status),
    text: async () => JSON.stringify(body),
    arrayBuffer: async () => new ArrayBuffer(0),
    blob: async () => new Blob(),
    formData: async () => new FormData(),
  } as Response;
}

/** Build a real signed covenant for server tests. */
async function buildTestCovenant(kp: KeyPair): Promise<CovenantDocument> {
  const beneficiaryKp = await generateKeyPair();
  return buildCovenant({
    issuer: {
      id: 'issuer-1',
      publicKey: kp.publicKeyHex,
      role: 'issuer',
    },
    beneficiary: {
      id: 'beneficiary-1',
      publicKey: beneficiaryKp.publicKeyHex,
      role: 'beneficiary',
    },
    constraints: "permit read on '/data'",
    privateKey: kp.privateKey,
  });
}

// ─── Constants ────────────────────────────────────────────────────────────────

describe('Constants', () => {
  it('WELL_KNOWN_PATH is /.well-known/stele', () => {
    expect(WELL_KNOWN_PATH).toBe('/.well-known/stele');
  });

  it('CONFIGURATION_PATH is /.well-known/stele/configuration', () => {
    expect(CONFIGURATION_PATH).toBe('/.well-known/stele/configuration');
  });

  it('STELE_MEDIA_TYPE is application/stele+json', () => {
    expect(STELE_MEDIA_TYPE).toBe('application/stele+json');
  });

  it('MAX_DOCUMENT_AGE_MS is 24 hours in milliseconds', () => {
    expect(MAX_DOCUMENT_AGE_MS).toBe(86_400_000);
  });
});

// ─── Discovery Document Building ─────────────────────────────────────────────

describe('buildDiscoveryDocument', () => {
  it('builds a document with minimal options', async () => {
    const doc = await buildDiscoveryDocument({ issuer: TEST_ISSUER });

    expect(doc.issuer).toBe(TEST_ISSUER);
    expect(doc.keys_endpoint).toBe(`${TEST_ISSUER}/.well-known/stele/keys`);
    expect(doc.covenants_endpoint).toBe(`${TEST_ISSUER}/.well-known/stele/covenants`);
    expect(doc.verification_endpoint).toBe(`${TEST_ISSUER}/.well-known/stele/verify`);
    expect(doc.reputation_endpoint).toBe(`${TEST_ISSUER}/.well-known/stele/reputation`);
    expect(doc.breach_endpoint).toBe(`${TEST_ISSUER}/.well-known/stele/breach`);
    expect(doc.protocol_versions_supported).toContain(PROTOCOL_VERSION);
    expect(doc.signature_schemes_supported).toContain('ed25519');
    expect(doc.hash_algorithms_supported).toContain('sha256');
    expect(doc.enforcement_types_supported).toEqual(
      expect.arrayContaining(['capability', 'monitor', 'audit']),
    );
    expect(doc.proof_types_supported).toEqual(
      expect.arrayContaining(['capability_manifest', 'audit_log', 'zkp']),
    );
    expect(typeof doc.updated_at).toBe('string');
    expect(doc.signature).toBeUndefined();
    expect(doc.signing_key).toBeUndefined();
  });

  it('strips trailing slashes from issuer URL', async () => {
    const doc = await buildDiscoveryDocument({ issuer: 'https://example.com///' });
    expect(doc.issuer).toBe('https://example.com');
    expect(doc.keys_endpoint).toMatch(/^https:\/\/example\.com\//);
  });

  it('sets platform_name, contact, and policy_url when provided', async () => {
    const doc = await buildDiscoveryDocument({
      issuer: TEST_ISSUER,
      platformName: 'My Platform',
      contact: 'https://contact.example',
      policyUrl: 'https://policy.example',
    });

    expect(doc.platform_name).toBe('My Platform');
    expect(doc.contact).toBe('https://contact.example');
    expect(doc.policy_url).toBe('https://policy.example');
  });

  it('includes additional protocol versions without duplicating defaults', async () => {
    const doc = await buildDiscoveryDocument({
      issuer: TEST_ISSUER,
      additionalVersions: ['2.0', PROTOCOL_VERSION],
    });

    const count = doc.protocol_versions_supported.filter(
      (v) => v === PROTOCOL_VERSION,
    ).length;
    expect(count).toBe(1);
    expect(doc.protocol_versions_supported).toContain('2.0');
  });

  it('includes additional enforcement types without duplicates', async () => {
    const doc = await buildDiscoveryDocument({
      issuer: TEST_ISSUER,
      additionalEnforcementTypes: ['bond', 'capability'],
    });

    expect(doc.enforcement_types_supported).toContain('bond');
    const capCount = doc.enforcement_types_supported.filter(
      (t) => t === 'capability',
    ).length;
    expect(capCount).toBe(1);
  });

  it('includes additional proof types without duplicates', async () => {
    const doc = await buildDiscoveryDocument({
      issuer: TEST_ISSUER,
      additionalProofTypes: ['tee', 'zkp'],
    });

    expect(doc.proof_types_supported).toContain('tee');
    const zkpCount = doc.proof_types_supported.filter((t) => t === 'zkp').length;
    expect(zkpCount).toBe(1);
  });

  it('signs the document when a signing key pair is provided', async () => {
    const kp = await generateKeyPair();
    const doc = await buildDiscoveryDocument({
      issuer: TEST_ISSUER,
      signingKeyPair: kp,
    });

    expect(doc.signature).toBeDefined();
    expect(typeof doc.signature).toBe('string');
    expect(doc.signing_key).toBe(kp.publicKeyHex);
  });

  it('produces a valid signature that can be verified', async () => {
    const kp = await generateKeyPair();
    const doc = await buildDiscoveryDocument({
      issuer: TEST_ISSUER,
      signingKeyPair: kp,
    });

    // Reconstruct canonical form the same way well-known.ts does
    const canonical = canonicalizeJson({
      ...doc,
      signature: undefined,
      signing_key: doc.signing_key,
    });
    const messageBytes = new TextEncoder().encode(canonical);
    const sigBytes = fromHex(doc.signature!);
    const pubKeyBytes = fromHex(doc.signing_key!);

    const isValid = await verify(messageBytes, sigBytes, pubKeyBytes);
    expect(isValid).toBe(true);
  });
});

// ─── Discovery Document Validation ──────────────────────────────────────────

describe('validateDiscoveryDocument', () => {
  it('passes validation for a valid unsigned document', async () => {
    const doc = makeMinimalDoc();
    const result = await validateDiscoveryDocument(doc);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('fails for a non-object input (null)', async () => {
    const result = await validateDiscoveryDocument(null);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Discovery document must be a JSON object');
  });

  it('fails for a non-object input (array)', async () => {
    const result = await validateDiscoveryDocument([1, 2, 3]);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Discovery document must be a JSON object');
  });

  it('fails when issuer is missing', async () => {
    const doc = makeMinimalDoc();
    delete (doc as unknown as Record<string, unknown>).issuer;
    const result = await validateDiscoveryDocument(doc);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('issuer must be a non-empty string URL');
  });

  it('fails when issuer is empty string', async () => {
    const doc = { ...makeMinimalDoc(), issuer: '' };
    const result = await validateDiscoveryDocument(doc);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('issuer must be a non-empty string URL');
  });

  it('fails when keys_endpoint is missing', async () => {
    const doc = makeMinimalDoc();
    delete (doc as unknown as Record<string, unknown>).keys_endpoint;
    const result = await validateDiscoveryDocument(doc);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('keys_endpoint must be a non-empty string URL');
  });

  it('fails when covenants_endpoint is missing', async () => {
    const doc = makeMinimalDoc();
    delete (doc as unknown as Record<string, unknown>).covenants_endpoint;
    const result = await validateDiscoveryDocument(doc);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('covenants_endpoint must be a non-empty string URL');
  });

  it('fails when protocol_versions_supported is empty', async () => {
    const doc = { ...makeMinimalDoc(), protocol_versions_supported: [] };
    const result = await validateDiscoveryDocument(doc);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('protocol_versions_supported must be a non-empty array');
  });

  it('fails when signature_schemes_supported is not an array', async () => {
    const doc = { ...makeMinimalDoc(), signature_schemes_supported: 'ed25519' };
    const result = await validateDiscoveryDocument(doc as unknown as DiscoveryDocument);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('signature_schemes_supported must be a non-empty array');
  });

  it('fails when hash_algorithms_supported is missing', async () => {
    const doc = makeMinimalDoc();
    delete (doc as unknown as Record<string, unknown>).hash_algorithms_supported;
    const result = await validateDiscoveryDocument(doc);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('hash_algorithms_supported must be a non-empty array');
  });

  it('fails when updated_at is not a string', async () => {
    const doc = { ...makeMinimalDoc(), updated_at: 12345 };
    const result = await validateDiscoveryDocument(doc as unknown as DiscoveryDocument);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('updated_at must be a string');
  });

  it('collects multiple errors at once', async () => {
    const result = await validateDiscoveryDocument({});
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(5);
  });

  it('verifies a valid signature when verifySignature is true', async () => {
    const kp = await generateKeyPair();
    const doc = await buildDiscoveryDocument({
      issuer: TEST_ISSUER,
      signingKeyPair: kp,
    });

    const result = await validateDiscoveryDocument(doc, { verifySignature: true });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('fails for a tampered signature when verifySignature is true', async () => {
    const kp = await generateKeyPair();
    const doc = await buildDiscoveryDocument({
      issuer: TEST_ISSUER,
      signingKeyPair: kp,
    });

    // Tamper with the document after signing
    doc.platform_name = 'TAMPERED';

    const result = await validateDiscoveryDocument(doc, { verifySignature: true });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Discovery document signature is invalid');
  });

  it('skips signature verification when verifySignature is false', async () => {
    const kp = await generateKeyPair();
    const doc = await buildDiscoveryDocument({
      issuer: TEST_ISSUER,
      signingKeyPair: kp,
    });

    // Tamper with the document
    doc.platform_name = 'TAMPERED';

    // With verifySignature false (or undefined), signature check is skipped
    const result = await validateDiscoveryDocument(doc, { verifySignature: false });
    expect(result.valid).toBe(true);
  });

  it('skips signature verification when no signature is present', async () => {
    const doc = makeMinimalDoc();
    const result = await validateDiscoveryDocument(doc, { verifySignature: true });
    expect(result.valid).toBe(true);
  });
});

// ─── Key Entry Building ─────────────────────────────────────────────────────

describe('buildKeyEntry', () => {
  it('creates a key entry with correct structure', () => {
    const publicKey = 'aabbccdd'.repeat(8); // 64 hex chars
    const entry = buildKeyEntry('agent-1', publicKey);

    expect(entry.kty).toBe('Ed25519');
    expect(entry.public_key).toBe(publicKey);
    expect(entry.agent_id).toBe('agent-1');
    expect(entry.status).toBe('active');
    expect(typeof entry.created_at).toBe('string');
    expect(typeof entry.kid).toBe('string');
    expect(entry.expires_at).toBeUndefined();
  });

  it('generates kid as SHA-256 of the public key', () => {
    const publicKey = 'deadbeef'.repeat(8);
    const entry = buildKeyEntry('agent-1', publicKey);
    const expectedKid = sha256String(publicKey);
    expect(entry.kid).toBe(expectedKid);
  });

  it('accepts custom status', () => {
    const entry = buildKeyEntry('agent-1', 'aa'.repeat(32), { status: 'rotated' });
    expect(entry.status).toBe('rotated');
  });

  it('accepts expiresAt option', () => {
    const expiresAt = '2030-01-01T00:00:00Z';
    const entry = buildKeyEntry('agent-1', 'aa'.repeat(32), { expiresAt });
    expect(entry.expires_at).toBe(expiresAt);
  });

  it('produces different kids for different public keys', () => {
    const entry1 = buildKeyEntry('agent-1', 'aa'.repeat(32));
    const entry2 = buildKeyEntry('agent-1', 'bb'.repeat(32));
    expect(entry1.kid).not.toBe(entry2.kid);
  });
});

describe('buildKeySet', () => {
  it('creates a key set from an array of entries', () => {
    const entry1 = buildKeyEntry('agent-1', 'aa'.repeat(32));
    const entry2 = buildKeyEntry('agent-2', 'bb'.repeat(32));
    const keySet = buildKeySet([entry1, entry2]);

    expect(keySet.keys).toHaveLength(2);
    expect(keySet.keys[0]).toBe(entry1);
    expect(keySet.keys[1]).toBe(entry2);
  });

  it('creates an empty key set', () => {
    const keySet = buildKeySet([]);
    expect(keySet.keys).toHaveLength(0);
  });
});

// ─── Discovery Server ───────────────────────────────────────────────────────

describe('DiscoveryServer', () => {
  let server: DiscoveryServer;
  let platformKp: KeyPair;

  beforeEach(async () => {
    platformKp = await generateKeyPair();
    server = new DiscoveryServer({
      issuer: TEST_ISSUER,
      platformName: 'Test Platform',
      signingKeyPair: platformKp,
    });
  });

  describe('construction', () => {
    it('creates a server instance', () => {
      expect(server).toBeInstanceOf(DiscoveryServer);
    });
  });

  describe('getDiscoveryDocument', () => {
    it('returns a signed discovery document', async () => {
      const doc = await server.getDiscoveryDocument();

      expect(doc.issuer).toBe(TEST_ISSUER);
      expect(doc.platform_name).toBe('Test Platform');
      expect(doc.signing_key).toBe(platformKp.publicKeyHex);
      expect(doc.signature).toBeDefined();
    });

    it('caches the discovery document', async () => {
      const doc1 = await server.getDiscoveryDocument();
      const doc2 = await server.getDiscoveryDocument();
      expect(doc1).toBe(doc2); // Same reference
    });

    it('rebuilds after invalidation', async () => {
      const doc1 = await server.getDiscoveryDocument();
      server.invalidateDiscoveryDocument();
      const doc2 = await server.getDiscoveryDocument();
      // Not the same reference after invalidation
      expect(doc1).not.toBe(doc2);
      expect(doc2.issuer).toBe(TEST_ISSUER);
    });
  });

  describe('registerAgentKey', () => {
    it('adds a key to the registry', async () => {
      const kp = await generateKeyPair();
      const entry = server.registerAgentKey('agent-1', kp.publicKeyHex);

      expect(entry.agent_id).toBe('agent-1');
      expect(entry.public_key).toBe(kp.publicKeyHex);
      expect(entry.status).toBe('active');
      expect(entry.kty).toBe('Ed25519');
    });

    it('can register multiple keys for the same agent', async () => {
      const kp1 = await generateKeyPair();
      const kp2 = await generateKeyPair();

      server.registerAgentKey('agent-1', kp1.publicKeyHex);
      server.registerAgentKey('agent-1', kp2.publicKeyHex);

      const keySet = server.getKeySet({ agentId: 'agent-1' });
      expect(keySet.keys).toHaveLength(2);
    });

    it('accepts expiresAt option', async () => {
      const kp = await generateKeyPair();
      const expiresAt = '2030-12-31T00:00:00Z';
      const entry = server.registerAgentKey('agent-1', kp.publicKeyHex, { expiresAt });
      expect(entry.expires_at).toBe(expiresAt);
    });
  });

  describe('rotateAgentKey', () => {
    it('marks old key as rotated and creates a new one', async () => {
      const kp1 = await generateKeyPair();
      const kp2 = await generateKeyPair();

      const oldEntry = server.registerAgentKey('agent-1', kp1.publicKeyHex);
      const newEntry = server.rotateAgentKey('agent-1', oldEntry.kid, kp2.publicKeyHex);

      // Verify old key is rotated
      const keySet = server.getKeySet({ kid: oldEntry.kid });
      expect(keySet.keys).toHaveLength(1);
      expect(keySet.keys[0]!.status).toBe('rotated');
      expect(keySet.keys[0]!.deactivated_at).toBeDefined();
      expect(keySet.keys[0]!.replaced_by).toBe(newEntry.kid);

      // Verify new key is active
      const newKeySet = server.getKeySet({ kid: newEntry.kid });
      expect(newKeySet.keys[0]!.status).toBe('active');
      expect(newKeySet.keys[0]!.public_key).toBe(kp2.publicKeyHex);
    });

    it('creates a new key when old kid does not exist', async () => {
      const kp = await generateKeyPair();
      const entry = server.rotateAgentKey('agent-1', 'nonexistent-kid', kp.publicKeyHex);

      expect(entry.status).toBe('active');
      expect(entry.public_key).toBe(kp.publicKeyHex);
    });
  });

  describe('revokeKey', () => {
    it('marks the key as revoked', async () => {
      const kp = await generateKeyPair();
      const entry = server.registerAgentKey('agent-1', kp.publicKeyHex);

      server.revokeKey(entry.kid);

      const keySet = server.getKeySet({ kid: entry.kid });
      expect(keySet.keys[0]!.status).toBe('revoked');
      expect(keySet.keys[0]!.deactivated_at).toBeDefined();
    });

    it('does nothing when kid does not exist', () => {
      // Should not throw
      expect(() => server.revokeKey('nonexistent-kid')).not.toThrow();
    });
  });

  describe('getKeySet', () => {
    it('returns all keys when no filters are provided', async () => {
      const kp1 = await generateKeyPair();
      const kp2 = await generateKeyPair();

      server.registerAgentKey('agent-1', kp1.publicKeyHex);
      server.registerAgentKey('agent-2', kp2.publicKeyHex);

      const keySet = server.getKeySet();
      expect(keySet.keys).toHaveLength(2);
    });

    it('filters by agentId', async () => {
      const kp1 = await generateKeyPair();
      const kp2 = await generateKeyPair();

      server.registerAgentKey('agent-1', kp1.publicKeyHex);
      server.registerAgentKey('agent-2', kp2.publicKeyHex);

      const keySet = server.getKeySet({ agentId: 'agent-1' });
      expect(keySet.keys).toHaveLength(1);
      expect(keySet.keys[0]!.agent_id).toBe('agent-1');
    });

    it('filters by kid', async () => {
      const kp1 = await generateKeyPair();
      const kp2 = await generateKeyPair();

      const entry1 = server.registerAgentKey('agent-1', kp1.publicKeyHex);
      server.registerAgentKey('agent-2', kp2.publicKeyHex);

      const keySet = server.getKeySet({ kid: entry1.kid });
      expect(keySet.keys).toHaveLength(1);
      expect(keySet.keys[0]!.kid).toBe(entry1.kid);
    });

    it('returns empty key set for unknown agentId', () => {
      const keySet = server.getKeySet({ agentId: 'nonexistent' });
      expect(keySet.keys).toHaveLength(0);
    });

    it('filters by both agentId and kid', async () => {
      const kp1 = await generateKeyPair();
      const kp2 = await generateKeyPair();

      const entry1 = server.registerAgentKey('agent-1', kp1.publicKeyHex);
      server.registerAgentKey('agent-1', kp2.publicKeyHex);

      const keySet = server.getKeySet({ agentId: 'agent-1', kid: entry1.kid });
      expect(keySet.keys).toHaveLength(1);
      expect(keySet.keys[0]!.kid).toBe(entry1.kid);
    });
  });

  describe('registerCovenant', () => {
    it('adds a covenant to the registry', async () => {
      const cov = await buildTestCovenant(platformKp);
      server.registerCovenant(cov);

      const result = server.queryCovenants();
      expect(result.covenants).toHaveLength(1);
      expect(result.covenants[0]!.id).toBe(cov.id);
      expect(result.covenants[0]!.issuer_id).toBe('issuer-1');
      expect(result.covenants[0]!.beneficiary_id).toBe('beneficiary-1');
      expect(result.covenants[0]!.status).toBe('active');
      expect(result.covenants[0]!.protocol_version).toBe(cov.version);
      expect(result.covenants[0]!.document_url).toContain(cov.id);
    });

    it('stores the full covenant document for retrieval', async () => {
      const cov = await buildTestCovenant(platformKp);
      server.registerCovenant(cov);

      const retrieved = server.getCovenantDocument(cov.id);
      expect(retrieved).toBe(cov);
    });
  });

  describe('queryCovenants', () => {
    it('returns all covenants when no filters are provided', async () => {
      const cov1 = await buildTestCovenant(platformKp);
      const cov2 = await buildTestCovenant(platformKp);

      server.registerCovenant(cov1);
      server.registerCovenant(cov2);

      const result = server.queryCovenants();
      expect(result.covenants).toHaveLength(2);
      expect(result.total).toBe(2);
    });

    it('filters by issuerId', async () => {
      const cov = await buildTestCovenant(platformKp);
      server.registerCovenant(cov);

      const result = server.queryCovenants({ issuerId: 'issuer-1' });
      expect(result.covenants).toHaveLength(1);

      const noResult = server.queryCovenants({ issuerId: 'nonexistent' });
      expect(noResult.covenants).toHaveLength(0);
    });

    it('filters by beneficiaryId', async () => {
      const cov = await buildTestCovenant(platformKp);
      server.registerCovenant(cov);

      const result = server.queryCovenants({ beneficiaryId: 'beneficiary-1' });
      expect(result.covenants).toHaveLength(1);

      const noResult = server.queryCovenants({ beneficiaryId: 'nonexistent' });
      expect(noResult.covenants).toHaveLength(0);
    });

    it('filters by status', async () => {
      const cov = await buildTestCovenant(platformKp);
      server.registerCovenant(cov);

      const activeResult = server.queryCovenants({ status: 'active' });
      expect(activeResult.covenants).toHaveLength(1);

      const revokedResult = server.queryCovenants({ status: 'revoked' });
      expect(revokedResult.covenants).toHaveLength(0);
    });

    it('supports pagination with limit', async () => {
      const cov1 = await buildTestCovenant(platformKp);
      const cov2 = await buildTestCovenant(platformKp);
      const cov3 = await buildTestCovenant(platformKp);

      server.registerCovenant(cov1);
      server.registerCovenant(cov2);
      server.registerCovenant(cov3);

      const page1 = server.queryCovenants({ limit: 2 });
      expect(page1.covenants).toHaveLength(2);
      expect(page1.total).toBe(3);
      expect(page1.next_cursor).toBeDefined();
    });

    it('supports cursor-based pagination', async () => {
      const cov1 = await buildTestCovenant(platformKp);
      const cov2 = await buildTestCovenant(platformKp);
      const cov3 = await buildTestCovenant(platformKp);

      server.registerCovenant(cov1);
      server.registerCovenant(cov2);
      server.registerCovenant(cov3);

      const page1 = server.queryCovenants({ limit: 1 });
      expect(page1.covenants).toHaveLength(1);
      expect(page1.next_cursor).toBeDefined();

      const page2 = server.queryCovenants({ limit: 1, cursor: page1.covenants[0]!.id });
      expect(page2.covenants).toHaveLength(1);
      expect(page2.covenants[0]!.id).not.toBe(page1.covenants[0]!.id);
    });

    it('returns no next_cursor when on the last page', async () => {
      const cov = await buildTestCovenant(platformKp);
      server.registerCovenant(cov);

      const result = server.queryCovenants({ limit: 10 });
      expect(result.next_cursor).toBeUndefined();
    });
  });

  describe('getCovenantDocument', () => {
    it('returns the stored covenant document', async () => {
      const cov = await buildTestCovenant(platformKp);
      server.registerCovenant(cov);

      const retrieved = server.getCovenantDocument(cov.id);
      expect(retrieved).toBeDefined();
      expect(retrieved!.id).toBe(cov.id);
    });

    it('returns undefined for unknown covenant', () => {
      const result = server.getCovenantDocument('nonexistent');
      expect(result).toBeUndefined();
    });
  });

  describe('handleVerificationRequest', () => {
    it('verifies an existing covenant', async () => {
      const cov = await buildTestCovenant(platformKp);
      server.registerCovenant(cov);

      const request: CrossPlatformVerificationRequest = {
        covenant_id: cov.id,
        requesting_platform: 'https://other-platform.example',
        timestamp: new Date().toISOString(),
        nonce: 'abc123',
      };

      const response = await server.handleVerificationRequest(request);
      expect(response.covenant_id).toBe(cov.id);
      expect(response.valid).toBe(true);
      expect(response.checks.length).toBeGreaterThan(0);
      expect(typeof response.timestamp).toBe('string');
    });

    it('returns invalid for missing covenant', async () => {
      const request: CrossPlatformVerificationRequest = {
        covenant_id: 'nonexistent-covenant-id',
        requesting_platform: 'https://other-platform.example',
        timestamp: new Date().toISOString(),
        nonce: 'abc123',
      };

      const response = await server.handleVerificationRequest(request);
      expect(response.covenant_id).toBe('nonexistent-covenant-id');
      expect(response.valid).toBe(false);
      expect(response.checks).toHaveLength(1);
      expect(response.checks[0]!.name).toBe('exists');
      expect(response.checks[0]!.passed).toBe(false);
      expect(response.checks[0]!.message).toBe('Covenant not found');
    });
  });

  describe('getRouteHandlers', () => {
    it('returns a map of route handlers', () => {
      const handlers = server.getRouteHandlers();

      expect(handlers).toBeInstanceOf(Map);
      expect(handlers.has('GET /.well-known/stele/configuration')).toBe(true);
      expect(handlers.has('GET /.well-known/stele/keys')).toBe(true);
      expect(handlers.has('GET /.well-known/stele/covenants')).toBe(true);
      expect(handlers.has('POST /.well-known/stele/verify')).toBe(true);
    });

    it('configuration handler returns the discovery document', async () => {
      const handlers = server.getRouteHandlers();
      const handler = handlers.get('GET /.well-known/stele/configuration')!;

      const result = await handler();
      expect(result.status).toBe(200);
      expect(result.headers['Content-Type']).toBe(STELE_MEDIA_TYPE);
      expect((result.body as DiscoveryDocument).issuer).toBe(TEST_ISSUER);
    });

    it('keys handler returns filtered key set', async () => {
      const kp = await generateKeyPair();
      server.registerAgentKey('agent-1', kp.publicKeyHex);

      const handlers = server.getRouteHandlers();
      const handler = handlers.get('GET /.well-known/stele/keys')!;

      const result = await handler({ agent_id: 'agent-1' });
      expect(result.status).toBe(200);
      const body = result.body as { keys: AgentKeyEntry[] };
      expect(body.keys).toHaveLength(1);
      expect(body.keys[0]!.agent_id).toBe('agent-1');
    });

    it('covenants handler returns the registry', async () => {
      const cov = await buildTestCovenant(platformKp);
      server.registerCovenant(cov);

      const handlers = server.getRouteHandlers();
      const handler = handlers.get('GET /.well-known/stele/covenants')!;

      const result = await handler();
      expect(result.status).toBe(200);
      const body = result.body as { covenants: unknown[]; total: number };
      expect(body.covenants).toHaveLength(1);
      expect(body.total).toBe(1);
    });

    it('verify handler processes verification requests', async () => {
      const cov = await buildTestCovenant(platformKp);
      server.registerCovenant(cov);

      const handlers = server.getRouteHandlers();
      const handler = handlers.get('POST /.well-known/stele/verify')!;

      const request: CrossPlatformVerificationRequest = {
        covenant_id: cov.id,
        requesting_platform: 'https://other.example',
        timestamp: new Date().toISOString(),
        nonce: 'nonce123',
      };

      const result = await handler(undefined, request);
      expect(result.status).toBe(200);
      expect((result.body as { valid: boolean }).valid).toBe(true);
    });
  });
});

// ─── Discovery Client ───────────────────────────────────────────────────────

describe('DiscoveryClient', () => {
  let mockFetch: ReturnType<typeof vi.fn>;
  let client: DiscoveryClient;
  let validDoc: DiscoveryDocument;

  beforeEach(async () => {
    validDoc = await buildDiscoveryDocument({ issuer: TEST_ISSUER });
    mockFetch = vi.fn();
    client = new DiscoveryClient({
      fetchFn: mockFetch as unknown as typeof fetch,
      fetchOptions: { verifySignature: false, timeout: 5000 },
    });
  });

  describe('construction', () => {
    it('creates a client instance', () => {
      expect(client).toBeInstanceOf(DiscoveryClient);
    });

    it('creates a client with default options', () => {
      // Should not throw even without fetchFn (falls back to globalThis.fetch)
      const c = new DiscoveryClient();
      expect(c).toBeInstanceOf(DiscoveryClient);
    });
  });

  describe('discover', () => {
    it('fetches and validates a discovery document', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(validDoc));

      const doc = await client.discover(TEST_ISSUER);
      expect(doc.issuer).toBe(TEST_ISSUER);
      expect(mockFetch).toHaveBeenCalledOnce();

      const calledUrl = mockFetch.mock.calls[0]![0];
      expect(calledUrl).toBe(`${TEST_ISSUER}${CONFIGURATION_PATH}`);
    });

    it('uses cached document on subsequent calls', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(validDoc));

      const doc1 = await client.discover(TEST_ISSUER);
      const doc2 = await client.discover(TEST_ISSUER);

      expect(doc1).toEqual(doc2);
      expect(mockFetch).toHaveBeenCalledOnce(); // Only fetched once
    });

    it('rejects invalid documents', async () => {
      const invalidDoc = { ...validDoc, issuer: '' };
      mockFetch.mockResolvedValueOnce(mockResponse(invalidDoc));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('throws on HTTP errors', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({}, false, 500));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Discovery fetch failed: 500/,
      );
    });

    it('strips trailing slashes from platform URL', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(validDoc));

      await client.discover('https://platform.example///');

      const calledUrl = mockFetch.mock.calls[0]![0];
      expect(calledUrl).toBe(`${TEST_ISSUER}${CONFIGURATION_PATH}`);
    });

    it('passes Accept header with stele media type', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(validDoc));

      await client.discover(TEST_ISSUER);

      const calledInit = mockFetch.mock.calls[0]![1];
      expect(calledInit.headers.Accept).toContain('application/stele+json');
    });

    it('verifies signature when configured to do so', async () => {
      const kp = await generateKeyPair();
      const signedDoc = await buildDiscoveryDocument({
        issuer: TEST_ISSUER,
        signingKeyPair: kp,
      });

      const verifyingClient = new DiscoveryClient({
        fetchFn: vi.fn().mockResolvedValueOnce(mockResponse(signedDoc)),
        fetchOptions: { verifySignature: true },
      });

      const doc = await verifyingClient.discover(TEST_ISSUER);
      expect(doc.signing_key).toBe(kp.publicKeyHex);
    });
  });

  describe('getAgentKeys', () => {
    it('fetches agent keys from the keys endpoint', async () => {
      const agentKeys = {
        keys: [
          {
            kid: 'kid-1',
            kty: 'Ed25519',
            public_key: 'aa'.repeat(32),
            agent_id: 'agent-1',
            status: 'active',
            created_at: new Date().toISOString(),
          },
        ],
      };

      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc)) // discover
        .mockResolvedValueOnce(mockResponse(agentKeys)); // getAgentKeys

      const keys = await client.getAgentKeys(TEST_ISSUER, 'agent-1');
      expect(keys).toHaveLength(1);
      expect(keys[0]!.agent_id).toBe('agent-1');
    });

    it('filters keys by agent_id', async () => {
      const agentKeys = {
        keys: [
          {
            kid: 'kid-1',
            kty: 'Ed25519',
            public_key: 'aa'.repeat(32),
            agent_id: 'agent-1',
            status: 'active',
            created_at: new Date().toISOString(),
          },
          {
            kid: 'kid-2',
            kty: 'Ed25519',
            public_key: 'bb'.repeat(32),
            agent_id: 'agent-2',
            status: 'active',
            created_at: new Date().toISOString(),
          },
        ],
      };

      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse(agentKeys));

      const keys = await client.getAgentKeys(TEST_ISSUER, 'agent-1');
      expect(keys).toHaveLength(1);
      expect(keys[0]!.agent_id).toBe('agent-1');
    });

    it('includes agent_id in the URL query parameter', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse({ keys: [] }));

      await client.getAgentKeys(TEST_ISSUER, 'agent-1');

      const keysUrl = mockFetch.mock.calls[1]![0] as string;
      expect(keysUrl).toContain('agent_id=agent-1');
    });
  });

  describe('queryCovenants', () => {
    it('queries covenants from the covenants endpoint', async () => {
      const covenantResponse = {
        covenants: [
          {
            id: 'cov-1',
            issuer_id: 'issuer-1',
            beneficiary_id: 'beneficiary-1',
            created_at: new Date().toISOString(),
            status: 'active',
            protocol_version: '1.0',
            document_url: `${TEST_ISSUER}/.well-known/stele/covenants/cov-1`,
          },
        ],
        total: 1,
      };

      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse(covenantResponse));

      const result = await client.queryCovenants(TEST_ISSUER);
      expect(result.covenants).toHaveLength(1);
      expect(result.total).toBe(1);
    });

    it('passes query filters as URL parameters', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse({ covenants: [], total: 0 }));

      await client.queryCovenants(TEST_ISSUER, {
        issuer_id: 'issuer-1',
        beneficiary_id: 'ben-1',
        status: 'active',
        cursor: 'cursor-abc',
        limit: 10,
      });

      const calledUrl = mockFetch.mock.calls[1]![0] as string;
      expect(calledUrl).toContain('issuer_id=issuer-1');
      expect(calledUrl).toContain('beneficiary_id=ben-1');
      expect(calledUrl).toContain('status=active');
      expect(calledUrl).toContain('cursor=cursor-abc');
      expect(calledUrl).toContain('limit=10');
    });

    it('omits empty query parameters', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse({ covenants: [], total: 0 }));

      await client.queryCovenants(TEST_ISSUER, {});

      const calledUrl = mockFetch.mock.calls[1]![0] as string;
      // No query string appended for empty filters
      expect(calledUrl).not.toContain('?');
    });
  });

  describe('verifyCovenant', () => {
    it('sends a verification request to the verification endpoint', async () => {
      const verificationResponse = {
        covenant_id: 'cov-123',
        valid: true,
        checks: [{ name: 'signature_valid', passed: true }],
        timestamp: new Date().toISOString(),
      };

      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse(verificationResponse));

      const result = await client.verifyCovenant(TEST_ISSUER, 'cov-123');
      expect(result.covenant_id).toBe('cov-123');
      expect(result.valid).toBe(true);
    });

    it('sends POST request with correct content type', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(
          mockResponse({
            covenant_id: 'cov-1',
            valid: true,
            checks: [],
            timestamp: new Date().toISOString(),
          }),
        );

      await client.verifyCovenant(TEST_ISSUER, 'cov-1');

      const postInit = mockFetch.mock.calls[1]![1];
      expect(postInit.method).toBe('POST');
      expect(postInit.headers['Content-Type']).toBe('application/stele+json');
    });

    it('throws when verification endpoint returns error', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse({}, false, 404));

      await expect(client.verifyCovenant(TEST_ISSUER, 'cov-1')).rejects.toThrow(
        /Cross-platform verification failed: 404/,
      );
    });

    it('throws when platform has no verification endpoint', async () => {
      const docWithoutVerify = { ...validDoc };
      delete docWithoutVerify.verification_endpoint;

      const noVerifyClient = new DiscoveryClient({
        fetchFn: vi.fn().mockResolvedValueOnce(mockResponse(docWithoutVerify)),
        fetchOptions: { verifySignature: false },
      });

      await expect(
        noVerifyClient.verifyCovenant(TEST_ISSUER, 'cov-1'),
      ).rejects.toThrow(/does not support cross-platform verification/);
    });

    it('includes nonce and timestamp in the request body', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(
          mockResponse({
            covenant_id: 'cov-1',
            valid: true,
            checks: [],
            timestamp: new Date().toISOString(),
          }),
        );

      await client.verifyCovenant(TEST_ISSUER, 'cov-1');

      const postBody = JSON.parse(mockFetch.mock.calls[1]![1].body);
      expect(postBody.nonce).toBeDefined();
      expect(typeof postBody.nonce).toBe('string');
      expect(postBody.timestamp).toBeDefined();
      expect(postBody.covenant_id).toBe('cov-1');
    });
  });

  describe('negotiate', () => {
    it('finds common capabilities and returns accepted response', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(validDoc));

      const result = await client.negotiate(TEST_ISSUER, {
        protocolVersions: [PROTOCOL_VERSION],
        signatureSchemes: ['ed25519'],
        hashAlgorithms: ['sha256'],
      });

      expect(result.accepted).toBe(true);
      expect(result.agreed_version).toBe(PROTOCOL_VERSION);
      expect(result.agreed_signature_scheme).toBe('ed25519');
      expect(result.agreed_hash_algorithm).toBe('sha256');
      expect(result.keys_endpoint).toBeDefined();
      expect(result.timestamp).toBeDefined();
      expect(result.nonce).toBeDefined();
    });

    it('rejects when no common protocol versions', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(validDoc));

      const result = await client.negotiate(TEST_ISSUER, {
        protocolVersions: ['99.0'],
        signatureSchemes: ['ed25519'],
        hashAlgorithms: ['sha256'],
      });

      expect(result.accepted).toBe(false);
      expect(result.rejection_reason).toContain('No common protocol capabilities');
    });

    it('rejects when no common signature schemes', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(validDoc));

      const result = await client.negotiate(TEST_ISSUER, {
        protocolVersions: [PROTOCOL_VERSION],
        signatureSchemes: ['rsa4096'],
        hashAlgorithms: ['sha256'],
      });

      expect(result.accepted).toBe(false);
      expect(result.rejection_reason).toContain('No common protocol capabilities');
    });

    it('rejects when no common hash algorithms', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(validDoc));

      const result = await client.negotiate(TEST_ISSUER, {
        protocolVersions: [PROTOCOL_VERSION],
        signatureSchemes: ['ed25519'],
        hashAlgorithms: ['sha512'],
      });

      expect(result.accepted).toBe(false);
      expect(result.rejection_reason).toContain('No common protocol capabilities');
    });

    it('picks the first common capability when multiple match', async () => {
      const multiVersionDoc = await buildDiscoveryDocument({
        issuer: TEST_ISSUER,
        additionalVersions: ['2.0'],
      });
      mockFetch.mockResolvedValueOnce(mockResponse(multiVersionDoc));

      const result = await client.negotiate(TEST_ISSUER, {
        protocolVersions: ['2.0', PROTOCOL_VERSION],
        signatureSchemes: ['ed25519'],
        hashAlgorithms: ['sha256'],
      });

      expect(result.accepted).toBe(true);
      // The first one in localCapabilities that is also in discovery
      expect(result.agreed_version).toBe('2.0');
    });
  });

  describe('clearCache', () => {
    it('clears entire cache when no platform specified', async () => {
      mockFetch.mockResolvedValue(mockResponse(validDoc));

      await client.discover(TEST_ISSUER);
      client.clearCache();

      // Next discover should fetch again
      await client.discover(TEST_ISSUER);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('clears only specific platform cache', async () => {
      const otherDoc = await buildDiscoveryDocument({ issuer: 'https://other.example' });

      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse(otherDoc));

      await client.discover(TEST_ISSUER);
      await client.discover('https://other.example');

      // Clear only the TEST_ISSUER cache
      client.clearCache(TEST_ISSUER);

      // Re-discover TEST_ISSUER should fetch again
      mockFetch.mockResolvedValueOnce(mockResponse(validDoc));
      await client.discover(TEST_ISSUER);
      expect(mockFetch).toHaveBeenCalledTimes(3);

      // Re-discover other should still be cached
      await client.discover('https://other.example');
      expect(mockFetch).toHaveBeenCalledTimes(3); // No additional fetch
    });
  });

  describe('getKeyById', () => {
    it('looks up a key by kid', async () => {
      const agentKeys = {
        keys: [
          {
            kid: 'kid-target',
            kty: 'Ed25519',
            public_key: 'aa'.repeat(32),
            agent_id: 'agent-1',
            status: 'active',
            created_at: new Date().toISOString(),
          },
          {
            kid: 'kid-other',
            kty: 'Ed25519',
            public_key: 'bb'.repeat(32),
            agent_id: 'agent-2',
            status: 'active',
            created_at: new Date().toISOString(),
          },
        ],
      };

      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse(agentKeys));

      const key = await client.getKeyById(TEST_ISSUER, 'kid-target');
      expect(key).toBeDefined();
      expect(key!.kid).toBe('kid-target');
    });

    it('returns undefined when kid not found', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse({ keys: [] }));

      const key = await client.getKeyById(TEST_ISSUER, 'nonexistent');
      expect(key).toBeUndefined();
    });
  });
});

// ─── Integration: Server + Client ────────────────────────────────────────────

describe('Server + Client integration', () => {
  it('client can discover a document served by the server', async () => {
    const kp = await generateKeyPair();
    const server = new DiscoveryServer({
      issuer: TEST_ISSUER,
      platformName: 'Integration Test Platform',
      signingKeyPair: kp,
    });

    const serverDoc = await server.getDiscoveryDocument();

    const client = new DiscoveryClient({
      fetchFn: vi.fn().mockResolvedValueOnce(mockResponse(serverDoc)),
      fetchOptions: { verifySignature: true },
    });

    const discovered = await client.discover(TEST_ISSUER);
    expect(discovered.issuer).toBe(TEST_ISSUER);
    expect(discovered.platform_name).toBe('Integration Test Platform');
    expect(discovered.signing_key).toBe(kp.publicKeyHex);
  });
});
