import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  generateKeyPair,
  sha256String,
  toHex,
  fromHex,
  verify,
  canonicalizeJson,
} from '@usekova/crypto';
import type { KeyPair } from '@usekova/crypto';
import { buildCovenant, PROTOCOL_VERSION } from '@usekova/core';
import type { CovenantDocument } from '@usekova/core';

import {
  buildDiscoveryDocument,
  validateDiscoveryDocument,
  buildKeyEntry,
  buildKeySet,
  WELL_KNOWN_PATH,
  CONFIGURATION_PATH,
  KOVA_MEDIA_TYPE,
  MAX_DOCUMENT_AGE_MS,
  DiscoveryClient,
  DiscoveryServer,
  // Federated discovery
  createFederationConfig,
  addResolver,
  removeResolver,
  resolveAgent,
  selectOptimalResolvers,
  // Trust-gated marketplace
  createMarketplace,
  listAgent,
  searchMarketplace,
  createTransaction,
  completeTransaction,
  disputeTransaction,
} from '../index.js';
import type {
  DiscoveryDocument,
  AgentKeyEntry,
  CrossPlatformVerificationRequest,
  FederatedResolver,
  FederationConfig,
  MarketplaceListing,
  MarketplaceConfig,
} from '../index.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const TEST_ISSUER = 'https://platform.example';

/** Build a minimal valid discovery document (unsigned). */
function makeMinimalDoc(): DiscoveryDocument {
  return {
    issuer: TEST_ISSUER,
    keys_endpoint: `${TEST_ISSUER}/.well-known/kova/keys`,
    covenants_endpoint: `${TEST_ISSUER}/.well-known/kova/covenants`,
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
  it('WELL_KNOWN_PATH is /.well-known/kova', () => {
    expect(WELL_KNOWN_PATH).toBe('/.well-known/kova');
  });

  it('CONFIGURATION_PATH is /.well-known/kova/configuration', () => {
    expect(CONFIGURATION_PATH).toBe('/.well-known/kova/configuration');
  });

  it('KOVA_MEDIA_TYPE is application/kova+json', () => {
    expect(KOVA_MEDIA_TYPE).toBe('application/kova+json');
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
    expect(doc.keys_endpoint).toBe(`${TEST_ISSUER}/.well-known/kova/keys`);
    expect(doc.covenants_endpoint).toBe(`${TEST_ISSUER}/.well-known/kova/covenants`);
    expect(doc.verification_endpoint).toBe(`${TEST_ISSUER}/.well-known/kova/verify`);
    expect(doc.reputation_endpoint).toBe(`${TEST_ISSUER}/.well-known/kova/reputation`);
    expect(doc.breach_endpoint).toBe(`${TEST_ISSUER}/.well-known/kova/breach`);
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
      expect(handlers.has('GET /.well-known/kova/configuration')).toBe(true);
      expect(handlers.has('GET /.well-known/kova/keys')).toBe(true);
      expect(handlers.has('GET /.well-known/kova/covenants')).toBe(true);
      expect(handlers.has('POST /.well-known/kova/verify')).toBe(true);
    });

    it('configuration handler returns the discovery document', async () => {
      const handlers = server.getRouteHandlers();
      const handler = handlers.get('GET /.well-known/kova/configuration')!;

      const result = await handler();
      expect(result.status).toBe(200);
      expect(result.headers['Content-Type']).toBe(KOVA_MEDIA_TYPE);
      expect((result.body as DiscoveryDocument).issuer).toBe(TEST_ISSUER);
    });

    it('keys handler returns filtered key set', async () => {
      const kp = await generateKeyPair();
      server.registerAgentKey('agent-1', kp.publicKeyHex);

      const handlers = server.getRouteHandlers();
      const handler = handlers.get('GET /.well-known/kova/keys')!;

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
      const handler = handlers.get('GET /.well-known/kova/covenants')!;

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
      const handler = handlers.get('POST /.well-known/kova/verify')!;

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

    it('passes Accept header with kova media type', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(validDoc));

      await client.discover(TEST_ISSUER);

      const calledInit = mockFetch.mock.calls[0]![1];
      expect(calledInit.headers.Accept).toContain('application/kova+json');
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
            document_url: `${TEST_ISSUER}/.well-known/kova/covenants/cov-1`,
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
      expect(postInit.headers['Content-Type']).toBe('application/kova+json');
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

// ─── Discovery Client Edge Cases ─────────────────────────────────────────────

describe('DiscoveryClient edge cases', () => {
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

  // ── HTTP Error Responses ──────────────────────────────────────────────

  describe('HTTP error responses', () => {
    it('throws on 404 Not Found during discover', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({}, false, 404));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Discovery fetch failed: 404/,
      );
    });

    it('throws on 500 Internal Server Error during discover', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({}, false, 500));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Discovery fetch failed: 500/,
      );
    });

    it('throws on 403 Forbidden during discover', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({}, false, 403));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Discovery fetch failed: 403/,
      );
    });

    it('throws on 502 Bad Gateway during discover', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({}, false, 502));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Discovery fetch failed: 502/,
      );
    });

    it('throws on HTTP error when fetching agent keys', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc)) // discover succeeds
        .mockResolvedValueOnce(mockResponse({}, false, 500)); // keys endpoint fails

      await expect(client.getAgentKeys(TEST_ISSUER, 'agent-1')).rejects.toThrow(
        /Discovery fetch failed: 500/,
      );
    });

    it('throws on HTTP error when querying covenants', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc)) // discover succeeds
        .mockResolvedValueOnce(mockResponse({}, false, 503)); // covenants endpoint fails

      await expect(client.queryCovenants(TEST_ISSUER)).rejects.toThrow(
        /Discovery fetch failed: 503/,
      );
    });

    it('throws on HTTP error when looking up key by ID', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc)) // discover succeeds
        .mockResolvedValueOnce(mockResponse({}, false, 404)); // keys endpoint 404

      await expect(client.getKeyById(TEST_ISSUER, 'kid-abc')).rejects.toThrow(
        /Discovery fetch failed: 404/,
      );
    });

    it('includes the URL in the HTTP error message', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({}, false, 500));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        new RegExp(`${TEST_ISSUER.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`),
      );
    });
  });

  // ── Network Timeouts & Failures ───────────────────────────────────────

  describe('network timeouts and failures', () => {
    it('throws when fetch rejects with a network error', async () => {
      mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow('Failed to fetch');
    });

    it('throws when fetch rejects with an abort error (timeout)', async () => {
      const abortError = new DOMException('The operation was aborted', 'AbortError');
      mockFetch.mockRejectedValueOnce(abortError);

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(/aborted/i);
    });

    it('throws when fetch rejects during getAgentKeys', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc)) // discover succeeds
        .mockRejectedValueOnce(new TypeError('Network request failed'));

      await expect(client.getAgentKeys(TEST_ISSUER, 'agent-1')).rejects.toThrow(
        'Network request failed',
      );
    });

    it('throws when fetch rejects during verifyCovenant POST', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc)) // discover succeeds
        .mockRejectedValueOnce(new TypeError('Connection refused'));

      await expect(client.verifyCovenant(TEST_ISSUER, 'cov-1')).rejects.toThrow(
        'Connection refused',
      );
    });

    it('throws when fetch rejects during queryCovenants', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc)) // discover succeeds
        .mockRejectedValueOnce(new Error('ECONNRESET'));

      await expect(client.queryCovenants(TEST_ISSUER)).rejects.toThrow('ECONNRESET');
    });
  });

  // ── Cache Expiration Logic ────────────────────────────────────────────

  describe('cache expiration logic', () => {
    it('re-fetches after cache TTL expires', async () => {
      vi.useFakeTimers();
      try {
        mockFetch.mockResolvedValue(mockResponse(validDoc));

        // First call fetches from network
        await client.discover(TEST_ISSUER);
        expect(mockFetch).toHaveBeenCalledTimes(1);

        // Second call uses cache
        await client.discover(TEST_ISSUER);
        expect(mockFetch).toHaveBeenCalledTimes(1);

        // Advance time past default cacheTtl (300_000ms = 5 minutes)
        vi.advanceTimersByTime(300_001);

        // Third call should re-fetch because cache expired
        await client.discover(TEST_ISSUER);
        expect(mockFetch).toHaveBeenCalledTimes(2);
      } finally {
        vi.useRealTimers();
      }
    });

    it('uses custom cacheTtl from fetch options', async () => {
      vi.useFakeTimers();
      try {
        const shortCacheClient = new DiscoveryClient({
          fetchFn: mockFetch as unknown as typeof fetch,
          fetchOptions: { verifySignature: false, cacheTtl: 1000 },
        });

        mockFetch.mockResolvedValue(mockResponse(validDoc));

        await shortCacheClient.discover(TEST_ISSUER);
        expect(mockFetch).toHaveBeenCalledTimes(1);

        // Advance time past the short TTL
        vi.advanceTimersByTime(1001);

        await shortCacheClient.discover(TEST_ISSUER);
        expect(mockFetch).toHaveBeenCalledTimes(2);
      } finally {
        vi.useRealTimers();
      }
    });

    it('serves from cache when TTL has not expired', async () => {
      vi.useFakeTimers();
      try {
        mockFetch.mockResolvedValue(mockResponse(validDoc));

        await client.discover(TEST_ISSUER);

        // Advance time but stay within the default 5 min TTL
        vi.advanceTimersByTime(299_999);

        await client.discover(TEST_ISSUER);
        expect(mockFetch).toHaveBeenCalledTimes(1); // Still using cache
      } finally {
        vi.useRealTimers();
      }
    });

    it('per-call cacheTtl overrides default TTL for that request', async () => {
      vi.useFakeTimers();
      try {
        mockFetch.mockResolvedValue(mockResponse(validDoc));

        // First discover with a custom short TTL
        await client.discover(TEST_ISSUER, { cacheTtl: 500 });
        expect(mockFetch).toHaveBeenCalledTimes(1);

        // Advance past the short TTL
        vi.advanceTimersByTime(501);

        // Should re-fetch because the cache entry used the 500ms TTL
        await client.discover(TEST_ISSUER);
        expect(mockFetch).toHaveBeenCalledTimes(2);
      } finally {
        vi.useRealTimers();
      }
    });

    it('clearCache for a specific platform does not affect others', async () => {
      const otherDoc = await buildDiscoveryDocument({ issuer: 'https://other.example' });

      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse(otherDoc));

      await client.discover(TEST_ISSUER);
      await client.discover('https://other.example');

      // Clear only the TEST_ISSUER cache
      client.clearCache(TEST_ISSUER);

      // other.example should still be cached
      await client.discover('https://other.example');
      expect(mockFetch).toHaveBeenCalledTimes(2); // No additional fetch for other.example

      // TEST_ISSUER requires a re-fetch
      mockFetch.mockResolvedValueOnce(mockResponse(validDoc));
      await client.discover(TEST_ISSUER);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('clearCache with trailing slash matches platform entries', async () => {
      mockFetch.mockResolvedValue(mockResponse(validDoc));

      await client.discover(TEST_ISSUER);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Clear using URL with trailing slash
      client.clearCache(TEST_ISSUER + '/');

      await client.discover(TEST_ISSUER);
      expect(mockFetch).toHaveBeenCalledTimes(2); // Re-fetched after clear
    });
  });

  // ── Invalid JSON Responses ────────────────────────────────────────────

  describe('invalid JSON responses', () => {
    it('throws when discover response returns invalid JSON', async () => {
      const badJsonResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => { throw new SyntaxError('Unexpected token < in JSON'); },
        headers: new Headers(),
        redirected: false,
        type: 'basic' as Response['type'],
        url: '',
        body: null,
        bodyUsed: false,
        clone: () => badJsonResponse,
        text: async () => '<html>Not JSON</html>',
        arrayBuffer: async () => new ArrayBuffer(0),
        blob: async () => new Blob(),
        formData: async () => new FormData(),
      } as unknown as Response;

      mockFetch.mockResolvedValueOnce(badJsonResponse);

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Unexpected token/,
      );
    });

    it('throws when getAgentKeys response returns invalid JSON', async () => {
      const badJsonResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => { throw new SyntaxError('Unexpected end of JSON input'); },
        headers: new Headers(),
        redirected: false,
        type: 'basic' as Response['type'],
        url: '',
        body: null,
        bodyUsed: false,
        clone: () => badJsonResponse,
        text: async () => '',
        arrayBuffer: async () => new ArrayBuffer(0),
        blob: async () => new Blob(),
        formData: async () => new FormData(),
      } as unknown as Response;

      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc)) // discover succeeds
        .mockResolvedValueOnce(badJsonResponse); // keys endpoint returns garbage

      await expect(client.getAgentKeys(TEST_ISSUER, 'agent-1')).rejects.toThrow(
        /Unexpected end of JSON/,
      );
    });

    it('throws when verifyCovenant response returns invalid JSON', async () => {
      const badJsonResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => { throw new SyntaxError('Bad JSON'); },
        headers: new Headers(),
        redirected: false,
        type: 'basic' as Response['type'],
        url: '',
        body: null,
        bodyUsed: false,
        clone: () => badJsonResponse,
        text: async () => 'not json',
        arrayBuffer: async () => new ArrayBuffer(0),
        blob: async () => new Blob(),
        formData: async () => new FormData(),
      } as unknown as Response;

      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc)) // discover succeeds
        .mockResolvedValueOnce(badJsonResponse); // verify endpoint returns garbage

      await expect(client.verifyCovenant(TEST_ISSUER, 'cov-1')).rejects.toThrow(
        /Bad JSON/,
      );
    });
  });

  // ── Discovery Document Validation Failures ────────────────────────────

  describe('discovery document validation failures', () => {
    it('rejects document with missing issuer', async () => {
      const badDoc = { ...validDoc };
      delete (badDoc as Record<string, unknown>).issuer;
      mockFetch.mockResolvedValueOnce(mockResponse(badDoc));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('rejects document with empty keys_endpoint', async () => {
      const badDoc = { ...validDoc, keys_endpoint: '' };
      mockFetch.mockResolvedValueOnce(mockResponse(badDoc));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('rejects document with missing covenants_endpoint', async () => {
      const badDoc = { ...validDoc };
      delete (badDoc as Record<string, unknown>).covenants_endpoint;
      mockFetch.mockResolvedValueOnce(mockResponse(badDoc));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('rejects document with empty protocol_versions_supported', async () => {
      const badDoc = { ...validDoc, protocol_versions_supported: [] };
      mockFetch.mockResolvedValueOnce(mockResponse(badDoc));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('rejects document with non-array signature_schemes_supported', async () => {
      const badDoc = { ...validDoc, signature_schemes_supported: 'ed25519' };
      mockFetch.mockResolvedValueOnce(mockResponse(badDoc));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('rejects document with missing hash_algorithms_supported', async () => {
      const badDoc = { ...validDoc };
      delete (badDoc as Record<string, unknown>).hash_algorithms_supported;
      mockFetch.mockResolvedValueOnce(mockResponse(badDoc));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('rejects document with non-string updated_at', async () => {
      const badDoc = { ...validDoc, updated_at: 12345 };
      mockFetch.mockResolvedValueOnce(mockResponse(badDoc));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('rejects document that is a plain array instead of object', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse([1, 2, 3]));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('rejects document that is null', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(null));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('rejects document with multiple validation errors', async () => {
      const badDoc = { updated_at: 999 }; // Missing most fields
      mockFetch.mockResolvedValueOnce(mockResponse(badDoc));

      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('rejects document with tampered signature when verifySignature is true', async () => {
      const kp = await generateKeyPair();
      const signedDoc = await buildDiscoveryDocument({
        issuer: TEST_ISSUER,
        signingKeyPair: kp,
      });

      // Tamper with the document
      signedDoc.platform_name = 'EVIL PLATFORM';

      const verifyingClient = new DiscoveryClient({
        fetchFn: vi.fn().mockResolvedValueOnce(mockResponse(signedDoc)),
        fetchOptions: { verifySignature: true },
      });

      await expect(verifyingClient.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );
    });

    it('does not cache a document that fails validation', async () => {
      const badDoc = { ...validDoc, issuer: '' };
      mockFetch
        .mockResolvedValueOnce(mockResponse(badDoc)) // first call: invalid
        .mockResolvedValueOnce(mockResponse(validDoc)); // second call: valid

      // First call fails
      await expect(client.discover(TEST_ISSUER)).rejects.toThrow(
        /Invalid discovery document/,
      );

      // Second call should re-fetch (not use cached invalid doc)
      const doc = await client.discover(TEST_ISSUER);
      expect(doc.issuer).toBe(TEST_ISSUER);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  // ── Fetch Not Available ───────────────────────────────────────────────

  describe('fetch not available', () => {
    it('throws descriptive error when no fetch implementation is available', async () => {
      // Save original fetch
      const originalFetch = globalThis.fetch;
      try {
        // Remove global fetch to simulate environments without it
        (globalThis as Record<string, unknown>).fetch = undefined;

        // Create a client without providing fetchFn
        const noFetchClient = new DiscoveryClient();

        await expect(noFetchClient.discover(TEST_ISSUER)).rejects.toThrow(
          /No fetch implementation available/,
        );
      } finally {
        // Restore
        globalThis.fetch = originalFetch;
      }
    });

    it('error message suggests providing fetchFn option', async () => {
      const originalFetch = globalThis.fetch;
      try {
        (globalThis as Record<string, unknown>).fetch = undefined;
        const noFetchClient = new DiscoveryClient();

        await expect(noFetchClient.discover(TEST_ISSUER)).rejects.toThrow(
          /Provide a fetchFn in options/,
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('works when custom fetchFn is provided even without global fetch', async () => {
      const originalFetch = globalThis.fetch;
      try {
        (globalThis as Record<string, unknown>).fetch = undefined;

        const customClient = new DiscoveryClient({
          fetchFn: vi.fn().mockResolvedValueOnce(mockResponse(validDoc)),
          fetchOptions: { verifySignature: false },
        });

        const doc = await customClient.discover(TEST_ISSUER);
        expect(doc.issuer).toBe(TEST_ISSUER);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  // ── Additional Edge Cases ─────────────────────────────────────────────

  describe('additional edge cases', () => {
    it('discover propagates errors from discover call in getAgentKeys', async () => {
      // No mocked responses, so discover will fail for getAgentKeys
      mockFetch.mockResolvedValueOnce(mockResponse({}, false, 500));

      await expect(client.getAgentKeys(TEST_ISSUER, 'agent-1')).rejects.toThrow(
        /Discovery fetch failed: 500/,
      );
    });

    it('discover propagates errors from discover call in queryCovenants', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({}, false, 404));

      await expect(client.queryCovenants(TEST_ISSUER)).rejects.toThrow(
        /Discovery fetch failed: 404/,
      );
    });

    it('discover propagates errors from discover call in verifyCovenant', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({}, false, 500));

      await expect(client.verifyCovenant(TEST_ISSUER, 'cov-1')).rejects.toThrow(
        /Discovery fetch failed: 500/,
      );
    });

    it('discover propagates errors from discover call in negotiate', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({}, false, 500));

      await expect(
        client.negotiate(TEST_ISSUER, {
          protocolVersions: ['1.0'],
          signatureSchemes: ['ed25519'],
          hashAlgorithms: ['sha256'],
        }),
      ).rejects.toThrow(/Discovery fetch failed: 500/);
    });

    it('handles empty keys array in getAgentKeys response', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse({ keys: [] }));

      const keys = await client.getAgentKeys(TEST_ISSUER, 'agent-1');
      expect(keys).toHaveLength(0);
    });

    it('verifyCovenant includes covenant_id in the POST body', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(
          mockResponse({
            covenant_id: 'my-cov-id',
            valid: true,
            checks: [],
            timestamp: new Date().toISOString(),
          }),
        );

      await client.verifyCovenant(TEST_ISSUER, 'my-cov-id');

      const postBody = JSON.parse(mockFetch.mock.calls[1]![1].body);
      expect(postBody.covenant_id).toBe('my-cov-id');
      expect(postBody.requesting_platform).toBe('local');
    });

    it('getAgentKeys URL-encodes special characters in agent ID', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse({ keys: [] }));

      await client.getAgentKeys(TEST_ISSUER, 'agent with spaces & symbols');

      const calledUrl = mockFetch.mock.calls[1]![0] as string;
      expect(calledUrl).toContain('agent_id=agent%20with%20spaces%20%26%20symbols');
    });

    it('getKeyById URL-encodes special characters in kid', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(validDoc))
        .mockResolvedValueOnce(mockResponse({ keys: [] }));

      await client.getKeyById(TEST_ISSUER, 'kid/with+special=chars');

      const calledUrl = mockFetch.mock.calls[1]![0] as string;
      expect(calledUrl).toContain('kid=kid%2Fwith%2Bspecial%3Dchars');
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

// ─── Federated Discovery Protocol ────────────────────────────────────────────

describe('createFederationConfig', () => {
  it('creates a config with default quorum and latency', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2' },
        { resolverId: 'r3', endpoint: 'https://r3.example', publicKey: 'pk3' },
      ],
    });

    expect(config.resolvers).toHaveLength(3);
    // Default quorum: ceil(3/2) + 1 = 3
    expect(config.quorum).toBe(3);
    expect(config.maxLatencyMs).toBe(5000);
    expect(config.trustSignatures).toBe(true);
  });

  it('uses custom quorum and latency when provided', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2' },
      ],
      quorum: 1,
      maxLatencyMs: 2000,
    });

    expect(config.quorum).toBe(1);
    expect(config.maxLatencyMs).toBe(2000);
  });

  it('initializes resolvers with default reliability of 1.0', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
      ],
    });

    expect(config.resolvers[0]!.reliability).toBe(1.0);
    expect(config.resolvers[0]!.lastSeen).toBeGreaterThan(0);
  });

  it('preserves region information', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1', region: 'us-east' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2', region: 'eu-west' },
      ],
    });

    expect(config.resolvers[0]!.region).toBe('us-east');
    expect(config.resolvers[1]!.region).toBe('eu-west');
  });

  it('handles empty resolver list', () => {
    const config = createFederationConfig({ resolvers: [] });
    expect(config.resolvers).toHaveLength(0);
    // quorum: ceil(0/2) + 1 = 1
    expect(config.quorum).toBe(1);
  });
});

describe('addResolver', () => {
  it('adds a new resolver to the config', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
      ],
    });

    const newResolver: FederatedResolver = {
      resolverId: 'r2',
      endpoint: 'https://r2.example',
      publicKey: 'pk2',
      lastSeen: Date.now(),
      reliability: 0.95,
    };

    const updated = addResolver(config, newResolver);
    expect(updated.resolvers).toHaveLength(2);
    expect(updated.resolvers[1]!.resolverId).toBe('r2');
  });

  it('replaces an existing resolver with the same ID', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
      ],
    });

    const updatedResolver: FederatedResolver = {
      resolverId: 'r1',
      endpoint: 'https://r1-new.example',
      publicKey: 'pk1-new',
      lastSeen: Date.now(),
      reliability: 0.8,
    };

    const updated = addResolver(config, updatedResolver);
    expect(updated.resolvers).toHaveLength(1);
    expect(updated.resolvers[0]!.endpoint).toBe('https://r1-new.example');
    expect(updated.resolvers[0]!.reliability).toBe(0.8);
  });

  it('returns a new config object (immutable)', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
      ],
    });

    const newResolver: FederatedResolver = {
      resolverId: 'r2',
      endpoint: 'https://r2.example',
      publicKey: 'pk2',
      lastSeen: Date.now(),
      reliability: 1.0,
    };

    const updated = addResolver(config, newResolver);
    expect(updated).not.toBe(config);
    expect(config.resolvers).toHaveLength(1); // original unchanged
  });
});

describe('removeResolver', () => {
  it('removes a resolver by ID', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2' },
      ],
    });

    const updated = removeResolver(config, 'r1');
    expect(updated.resolvers).toHaveLength(1);
    expect(updated.resolvers[0]!.resolverId).toBe('r2');
  });

  it('returns unchanged config when resolver ID does not exist', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
      ],
    });

    const updated = removeResolver(config, 'nonexistent');
    expect(updated.resolvers).toHaveLength(1);
  });

  it('returns a new config object (immutable)', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2' },
      ],
    });

    const updated = removeResolver(config, 'r1');
    expect(updated).not.toBe(config);
    expect(config.resolvers).toHaveLength(2); // original unchanged
  });
});

describe('resolveAgent', () => {
  let config: FederationConfig;

  beforeEach(() => {
    config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1', region: 'us-east' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2', region: 'eu-west' },
        { resolverId: 'r3', endpoint: 'https://r3.example', publicKey: 'pk3', region: 'ap-south' },
      ],
      quorum: 2,
    });
  });

  it('resolves when quorum is met (all resolvers agree)', () => {
    const result = resolveAgent(config, 'agent-1', [
      { resolverId: 'r1', found: true, signatureValid: true, latencyMs: 50, data: { name: 'Agent 1' } },
      { resolverId: 'r2', found: true, signatureValid: true, latencyMs: 100, data: { name: 'Agent 1' } },
      { resolverId: 'r3', found: true, signatureValid: true, latencyMs: 75, data: { name: 'Agent 1' } },
    ]);

    expect(result.resolved).toBe(true);
    expect(result.quorumMet).toBe(true);
    expect(result.agentId).toBe('agent-1');
    expect(result.consensusData).toEqual({ name: 'Agent 1' });
    expect(result.resolverResponses).toHaveLength(3);
  });

  it('resolves when quorum is met (minimum number agree)', () => {
    const result = resolveAgent(config, 'agent-1', [
      { resolverId: 'r1', found: true, signatureValid: true, latencyMs: 50, data: { name: 'Agent 1' } },
      { resolverId: 'r2', found: false, signatureValid: false, latencyMs: 100 },
      { resolverId: 'r3', found: true, signatureValid: true, latencyMs: 75, data: { name: 'Agent 1' } },
    ]);

    expect(result.resolved).toBe(true);
    expect(result.quorumMet).toBe(true);
  });

  it('fails to resolve when quorum is not met', () => {
    const result = resolveAgent(config, 'agent-1', [
      { resolverId: 'r1', found: true, signatureValid: true, latencyMs: 50 },
      { resolverId: 'r2', found: false, signatureValid: false, latencyMs: 100 },
      { resolverId: 'r3', found: false, signatureValid: false, latencyMs: 75 },
    ]);

    expect(result.resolved).toBe(false);
    expect(result.quorumMet).toBe(false);
    expect(result.consensusData).toBeNull();
  });

  it('rejects responses with invalid signatures when trustSignatures is true', () => {
    const result = resolveAgent(config, 'agent-1', [
      { resolverId: 'r1', found: true, signatureValid: false, latencyMs: 50, data: { fake: true } },
      { resolverId: 'r2', found: true, signatureValid: false, latencyMs: 100, data: { fake: true } },
      { resolverId: 'r3', found: true, signatureValid: true, latencyMs: 75, data: { real: true } },
    ]);

    // Only 1 valid response, quorum is 2
    expect(result.resolved).toBe(false);
    expect(result.quorumMet).toBe(false);
  });

  it('returns consensusData from the first valid resolver', () => {
    const result = resolveAgent(config, 'agent-1', [
      { resolverId: 'r1', found: true, signatureValid: false, latencyMs: 50, data: { source: 'r1' } },
      { resolverId: 'r2', found: true, signatureValid: true, latencyMs: 100, data: { source: 'r2' } },
      { resolverId: 'r3', found: true, signatureValid: true, latencyMs: 75, data: { source: 'r3' } },
    ]);

    expect(result.resolved).toBe(true);
    // First valid is r2 (r1 has invalid signature)
    expect(result.consensusData).toEqual({ source: 'r2' });
  });

  it('returns null consensusData when quorum met but no data provided', () => {
    const result = resolveAgent(config, 'agent-1', [
      { resolverId: 'r1', found: true, signatureValid: true, latencyMs: 50 },
      { resolverId: 'r2', found: true, signatureValid: true, latencyMs: 100 },
    ]);

    expect(result.resolved).toBe(true);
    expect(result.consensusData).toBeNull();
  });

  it('handles empty resolver results', () => {
    const result = resolveAgent(config, 'agent-1', []);

    expect(result.resolved).toBe(false);
    expect(result.quorumMet).toBe(false);
    expect(result.resolverResponses).toHaveLength(0);
  });
});

describe('selectOptimalResolvers', () => {
  it('selects resolvers by reliability', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2' },
        { resolverId: 'r3', endpoint: 'https://r3.example', publicKey: 'pk3' },
      ],
    });
    // Manually set reliabilities
    config.resolvers[0]!.reliability = 0.5;
    config.resolvers[1]!.reliability = 0.9;
    config.resolvers[2]!.reliability = 0.7;

    const selected = selectOptimalResolvers(config, 2);
    expect(selected).toHaveLength(2);
    expect(selected[0]!.resolverId).toBe('r2'); // highest reliability
  });

  it('prefers diverse regions', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1', region: 'us-east' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2', region: 'us-east' },
        { resolverId: 'r3', endpoint: 'https://r3.example', publicKey: 'pk3', region: 'eu-west' },
      ],
    });
    config.resolvers[0]!.reliability = 0.9;
    config.resolvers[1]!.reliability = 0.95;
    config.resolvers[2]!.reliability = 0.8;

    const selected = selectOptimalResolvers(config, 2);
    expect(selected).toHaveLength(2);
    // Should pick r1 (us-east, 0.9) and r3 (eu-west, 0.8) for diversity,
    // even though r2 (us-east, 0.95) has higher reliability than r3
    const regions = selected.map((r) => r.region);
    expect(regions).toContain('us-east');
    expect(regions).toContain('eu-west');
  });

  it('returns all resolvers when count >= total', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2' },
      ],
    });

    const selected = selectOptimalResolvers(config, 5);
    expect(selected).toHaveLength(2);
  });

  it('returns empty array when count is 0', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
      ],
    });

    const selected = selectOptimalResolvers(config, 0);
    expect(selected).toHaveLength(0);
  });

  it('handles resolvers without regions', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2' },
        { resolverId: 'r3', endpoint: 'https://r3.example', publicKey: 'pk3' },
      ],
    });
    config.resolvers[0]!.reliability = 0.9;
    config.resolvers[1]!.reliability = 0.8;
    config.resolvers[2]!.reliability = 0.7;

    const selected = selectOptimalResolvers(config, 2);
    expect(selected).toHaveLength(2);
    // All same "region" (undefined), so it picks by reliability
    expect(selected[0]!.resolverId).toBe('r1');
  });

  it('fills remaining slots after region diversity with highest reliability', () => {
    const config = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1', region: 'us' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2', region: 'eu' },
        { resolverId: 'r3', endpoint: 'https://r3.example', publicKey: 'pk3', region: 'us' },
        { resolverId: 'r4', endpoint: 'https://r4.example', publicKey: 'pk4', region: 'eu' },
      ],
    });
    config.resolvers[0]!.reliability = 0.9;
    config.resolvers[1]!.reliability = 0.8;
    config.resolvers[2]!.reliability = 0.95; // same region as r1 but higher
    config.resolvers[3]!.reliability = 0.7;

    const selected = selectOptimalResolvers(config, 3);
    expect(selected).toHaveLength(3);
    // First pass: r3 (us, 0.95) and r1 (eu... no, r1 is us)
    // Actually sorted by reliability: r3(0.95), r1(0.9), r2(0.8), r4(0.7)
    // First pass picks: r3 (us), r2 (eu) = 2 unique regions
    // Second pass fills: r1 (next highest)
    const selectedIds = selected.map((r) => r.resolverId);
    expect(selectedIds).toContain('r3'); // highest reliability
    expect(selectedIds).toContain('r2'); // different region
  });
});

// ─── Trust-Gated Marketplace ─────────────────────────────────────────────────

describe('createMarketplace', () => {
  it('creates a marketplace with default config', () => {
    const config = createMarketplace();

    expect(config.minimumTrustScore).toBe(0.3);
    expect(config.premiumThreshold).toBe(0.9);
    expect(config.verifiedThreshold).toBe(0.7);
    expect(config.escrowRequired).toBe(true);
    expect(config.transactionFeeRate).toBe(0.001);
  });

  it('overrides specific config values', () => {
    const config = createMarketplace({
      minimumTrustScore: 0.5,
      escrowRequired: false,
      transactionFeeRate: 0.01,
    });

    expect(config.minimumTrustScore).toBe(0.5);
    expect(config.escrowRequired).toBe(false);
    expect(config.transactionFeeRate).toBe(0.01);
    // Defaults preserved for unspecified
    expect(config.premiumThreshold).toBe(0.9);
    expect(config.verifiedThreshold).toBe(0.7);
  });
});

describe('listAgent', () => {
  let config: MarketplaceConfig;

  beforeEach(() => {
    config = createMarketplace();
  });

  it('lists an agent with standard tier when trust score is below verified threshold', () => {
    const result = listAgent(config, {
      agentId: 'agent-1',
      capabilities: ['search', 'translate'],
      trustScore: 0.5,
      pricing: { perQuery: 0.01, perTransaction: 0.1 },
    });

    expect('error' in result).toBe(false);
    const listing = result as MarketplaceListing;
    expect(listing.agentId).toBe('agent-1');
    expect(listing.tier).toBe('standard');
    expect(listing.listed).toBe(true);
    expect(listing.capabilities).toEqual(['search', 'translate']);
  });

  it('lists an agent with verified tier', () => {
    const result = listAgent(config, {
      agentId: 'agent-2',
      capabilities: ['analyze'],
      trustScore: 0.75,
      pricing: { perQuery: 0.02, perTransaction: 0.2 },
    });

    expect('error' in result).toBe(false);
    expect((result as MarketplaceListing).tier).toBe('verified');
  });

  it('lists an agent with premium tier', () => {
    const result = listAgent(config, {
      agentId: 'agent-3',
      capabilities: ['analyze', 'generate'],
      trustScore: 0.95,
      pricing: { perQuery: 0.05, perTransaction: 0.5 },
    });

    expect('error' in result).toBe(false);
    expect((result as MarketplaceListing).tier).toBe('premium');
  });

  it('rejects an agent with trust score below minimum', () => {
    const result = listAgent(config, {
      agentId: 'agent-untrusted',
      capabilities: ['search'],
      trustScore: 0.1,
      pricing: { perQuery: 0.01, perTransaction: 0.1 },
    });

    expect('error' in result).toBe(true);
    expect((result as { error: string }).error).toContain('below minimum threshold');
  });

  it('accepts an agent at exactly the minimum trust score', () => {
    const result = listAgent(config, {
      agentId: 'agent-exact',
      capabilities: ['search'],
      trustScore: 0.3,
      pricing: { perQuery: 0.01, perTransaction: 0.1 },
    });

    expect('error' in result).toBe(false);
    expect((result as MarketplaceListing).tier).toBe('standard');
  });

  it('assigns premium tier at exactly the premium threshold', () => {
    const result = listAgent(config, {
      agentId: 'agent-exact-premium',
      capabilities: ['search'],
      trustScore: 0.9,
      pricing: { perQuery: 0.01, perTransaction: 0.1 },
    });

    expect('error' in result).toBe(false);
    expect((result as MarketplaceListing).tier).toBe('premium');
  });

  it('sets listedAt to current time', () => {
    const before = Date.now();
    const result = listAgent(config, {
      agentId: 'agent-time',
      capabilities: ['search'],
      trustScore: 0.5,
      pricing: { perQuery: 0.01, perTransaction: 0.1 },
    });
    const after = Date.now();

    expect('error' in result).toBe(false);
    const listing = result as MarketplaceListing;
    expect(listing.listedAt).toBeGreaterThanOrEqual(before);
    expect(listing.listedAt).toBeLessThanOrEqual(after);
  });
});

describe('searchMarketplace', () => {
  let listings: MarketplaceListing[];

  beforeEach(() => {
    listings = [
      {
        agentId: 'agent-premium',
        capabilities: ['search', 'translate'],
        trustScore: 0.95,
        tier: 'premium',
        pricing: { perQuery: 0.05, perTransaction: 0.5 },
        listed: true,
        listedAt: 1000,
      },
      {
        agentId: 'agent-verified',
        capabilities: ['analyze', 'search'],
        trustScore: 0.8,
        tier: 'verified',
        pricing: { perQuery: 0.02, perTransaction: 0.2 },
        listed: true,
        listedAt: 2000,
      },
      {
        agentId: 'agent-standard',
        capabilities: ['search'],
        trustScore: 0.5,
        tier: 'standard',
        pricing: { perQuery: 0.01, perTransaction: 0.1 },
        listed: true,
        listedAt: 3000,
      },
      {
        agentId: 'agent-unlisted',
        capabilities: ['search'],
        trustScore: 0.6,
        tier: 'standard',
        pricing: { perQuery: 0.01, perTransaction: 0.1 },
        listed: false,
        listedAt: 4000,
      },
    ];
  });

  it('returns all listed agents when no filters are provided', () => {
    const results = searchMarketplace(listings, {});
    expect(results).toHaveLength(3); // excludes unlisted
  });

  it('filters out unlisted agents', () => {
    const results = searchMarketplace(listings, {});
    const ids = results.map((l) => l.agentId);
    expect(ids).not.toContain('agent-unlisted');
  });

  it('filters by capability', () => {
    const results = searchMarketplace(listings, { capabilities: ['translate'] });
    expect(results).toHaveLength(1);
    expect(results[0]!.agentId).toBe('agent-premium');
  });

  it('matches any capability (not all)', () => {
    const results = searchMarketplace(listings, { capabilities: ['analyze'] });
    expect(results).toHaveLength(1);
    expect(results[0]!.agentId).toBe('agent-verified');
  });

  it('filters by minimum trust score', () => {
    const results = searchMarketplace(listings, { minimumTrust: 0.7 });
    expect(results).toHaveLength(2);
    const ids = results.map((l) => l.agentId);
    expect(ids).toContain('agent-premium');
    expect(ids).toContain('agent-verified');
  });

  it('filters by tier', () => {
    const results = searchMarketplace(listings, { tier: 'verified' });
    expect(results).toHaveLength(1);
    expect(results[0]!.agentId).toBe('agent-verified');
  });

  it('sorts by tier priority (premium first) then trust score', () => {
    const results = searchMarketplace(listings, {});
    expect(results[0]!.tier).toBe('premium');
    expect(results[1]!.tier).toBe('verified');
    expect(results[2]!.tier).toBe('standard');
  });

  it('limits results by maxResults', () => {
    const results = searchMarketplace(listings, { maxResults: 1 });
    expect(results).toHaveLength(1);
  });

  it('defaults maxResults to 50', () => {
    // Create many listings
    const manyListings: MarketplaceListing[] = Array.from({ length: 60 }, (_, i) => ({
      agentId: `agent-${i}`,
      capabilities: ['search'],
      trustScore: 0.5,
      tier: 'standard' as const,
      pricing: { perQuery: 0.01, perTransaction: 0.1 },
      listed: true,
      listedAt: i,
    }));

    const results = searchMarketplace(manyListings, {});
    expect(results).toHaveLength(50);
  });

  it('returns empty array when no listings match', () => {
    const results = searchMarketplace(listings, { capabilities: ['nonexistent'] });
    expect(results).toHaveLength(0);
  });

  it('combines multiple filters', () => {
    const results = searchMarketplace(listings, {
      capabilities: ['search'],
      minimumTrust: 0.7,
      tier: 'premium',
    });
    expect(results).toHaveLength(1);
    expect(results[0]!.agentId).toBe('agent-premium');
  });
});

describe('createTransaction', () => {
  it('creates a pending transaction with correct fee', () => {
    const config = createMarketplace({ transactionFeeRate: 0.01 });
    const tx = createTransaction(config, {
      buyerAgentId: 'buyer-1',
      sellerAgentId: 'seller-1',
      amount: 100,
    });

    expect(tx.status).toBe('pending');
    expect(tx.amount).toBe(100);
    expect(tx.fee).toBeCloseTo(1.0); // 100 * 0.01
    expect(tx.buyerAgentId).toBe('buyer-1');
    expect(tx.sellerAgentId).toBe('seller-1');
    expect(tx.escrowHeld).toBe(true); // default
  });

  it('sets escrowHeld based on config', () => {
    const config = createMarketplace({ escrowRequired: false });
    const tx = createTransaction(config, {
      buyerAgentId: 'buyer-1',
      sellerAgentId: 'seller-1',
      amount: 50,
    });

    expect(tx.escrowHeld).toBe(false);
  });

  it('generates a unique transaction ID', () => {
    const config = createMarketplace();
    const tx1 = createTransaction(config, {
      buyerAgentId: 'buyer-1',
      sellerAgentId: 'seller-1',
      amount: 10,
    });
    const tx2 = createTransaction(config, {
      buyerAgentId: 'buyer-2',
      sellerAgentId: 'seller-2',
      amount: 20,
    });

    expect(tx1.id).toBeDefined();
    expect(tx2.id).toBeDefined();
    // IDs include buyer/seller so they're different
    expect(tx1.id).not.toBe(tx2.id);
  });

  it('computes fee with default rate', () => {
    const config = createMarketplace(); // 0.001 default
    const tx = createTransaction(config, {
      buyerAgentId: 'buyer-1',
      sellerAgentId: 'seller-1',
      amount: 1000,
    });

    expect(tx.fee).toBeCloseTo(1.0); // 1000 * 0.001
  });
});

describe('completeTransaction', () => {
  it('sets status to completed and releases escrow', () => {
    const config = createMarketplace();
    const tx = createTransaction(config, {
      buyerAgentId: 'buyer-1',
      sellerAgentId: 'seller-1',
      amount: 100,
    });

    expect(tx.status).toBe('pending');
    expect(tx.escrowHeld).toBe(true);

    const completed = completeTransaction(tx);
    expect(completed.status).toBe('completed');
    expect(completed.escrowHeld).toBe(false);
    expect(completed.amount).toBe(100); // preserved
  });

  it('returns a new object (immutable)', () => {
    const config = createMarketplace();
    const tx = createTransaction(config, {
      buyerAgentId: 'buyer-1',
      sellerAgentId: 'seller-1',
      amount: 100,
    });

    const completed = completeTransaction(tx);
    expect(completed).not.toBe(tx);
    expect(tx.status).toBe('pending'); // original unchanged
  });
});

describe('disputeTransaction', () => {
  it('sets status to disputed', () => {
    const config = createMarketplace();
    const tx = createTransaction(config, {
      buyerAgentId: 'buyer-1',
      sellerAgentId: 'seller-1',
      amount: 100,
    });

    const disputed = disputeTransaction(tx);
    expect(disputed.status).toBe('disputed');
    expect(disputed.escrowHeld).toBe(true); // escrow stays held during dispute
  });

  it('returns a new object (immutable)', () => {
    const config = createMarketplace();
    const tx = createTransaction(config, {
      buyerAgentId: 'buyer-1',
      sellerAgentId: 'seller-1',
      amount: 100,
    });

    const disputed = disputeTransaction(tx);
    expect(disputed).not.toBe(tx);
    expect(tx.status).toBe('pending'); // original unchanged
  });

  it('can dispute an already completed transaction', () => {
    const config = createMarketplace();
    const tx = createTransaction(config, {
      buyerAgentId: 'buyer-1',
      sellerAgentId: 'seller-1',
      amount: 100,
    });

    const completed = completeTransaction(tx);
    const disputed = disputeTransaction(completed);
    expect(disputed.status).toBe('disputed');
  });
});

// ─── Marketplace + Federation Integration ────────────────────────────────────

describe('Marketplace + Federation integration', () => {
  it('marketplace agents can be resolved through federation', () => {
    // Create marketplace
    const marketConfig = createMarketplace();
    const listing = listAgent(marketConfig, {
      agentId: 'agent-marketplace',
      capabilities: ['search'],
      trustScore: 0.8,
      pricing: { perQuery: 0.01, perTransaction: 0.1 },
    });
    expect('error' in listing).toBe(false);

    // Create federation
    const fedConfig = createFederationConfig({
      resolvers: [
        { resolverId: 'r1', endpoint: 'https://r1.example', publicKey: 'pk1' },
        { resolverId: 'r2', endpoint: 'https://r2.example', publicKey: 'pk2' },
      ],
      quorum: 2,
    });

    // Resolve the marketplace agent
    const result = resolveAgent(fedConfig, 'agent-marketplace', [
      { resolverId: 'r1', found: true, signatureValid: true, latencyMs: 50, data: { tier: 'verified' } },
      { resolverId: 'r2', found: true, signatureValid: true, latencyMs: 75, data: { tier: 'verified' } },
    ]);

    expect(result.resolved).toBe(true);
    expect(result.consensusData).toEqual({ tier: 'verified' });
  });
});
