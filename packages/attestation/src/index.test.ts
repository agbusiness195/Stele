import { describe, it, expect } from 'vitest';
import { generateKeyPair, toHex, sha256Object } from '@grith/crypto';
import {
  createAttestation,
  signAttestation,
  reconcile,
  getDiscrepancies,
  isSigned,
  verifyAttestation,
  attestationChainVerify,
  computeAttestationCoverage,
  createEntanglement,
  buildEntanglementNetwork,
  verifyEntangled,
  assessConditionalRisk,
} from './index';
import type {
  EntanglementLink,
  EntanglementNetwork,
} from './index';
import type {
  ExternalAttestation,
  ReceiptSummary,
  AttestationChainLink,
  AgentAction,
} from './types';

// ---------------------------------------------------------------------------
// createAttestation
// ---------------------------------------------------------------------------
describe('createAttestation', () => {
  it('produces a valid ExternalAttestation object', () => {
    const att = createAttestation('agent-1', 'counter-1', '/api/chat', 'inhash', 'outhash', 'ixhash', 1000);
    expect(att.agentId).toBe('agent-1');
    expect(att.counterpartyId).toBe('counter-1');
    expect(att.endpoint).toBe('/api/chat');
    expect(att.inputHash).toBe('inhash');
    expect(att.outputHash).toBe('outhash');
    expect(att.interactionHash).toBe('ixhash');
    expect(att.timestamp).toBe(1000);
  });

  it('produces a deterministic ID based on content', () => {
    const att1 = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 500);
    const att2 = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 500);
    expect(att1.id).toBe(att2.id);
  });

  it('produces different IDs for different content', () => {
    const att1 = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 500);
    const att2 = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 501);
    expect(att1.id).not.toBe(att2.id);
  });

  it('ID is a valid 64-character hex string (sha256)', () => {
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    expect(att.id.length).toBe(64);
    expect(/^[0-9a-f]{64}$/.test(att.id)).toBe(true);
  });

  it('counterpartySignature is initially empty string', () => {
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    expect(att.counterpartySignature).toBe('');
  });

  it('ID matches sha256Object of canonical content', () => {
    const att = createAttestation('agent', 'counter', '/e', 'ih', 'oh', 'xh', 999);
    const expectedId = sha256Object({
      agentId: 'agent',
      counterpartyId: 'counter',
      endpoint: '/e',
      inputHash: 'ih',
      outputHash: 'oh',
      interactionHash: 'xh',
      timestamp: 999,
    });
    expect(att.id).toBe(expectedId);
  });

  it('throws on empty agentId', () => {
    expect(() => createAttestation('', 'b', '/ep', 'in', 'out', 'ix', 0)).toThrow('agentId must be a non-empty string');
  });

  it('throws on empty counterpartyId', () => {
    expect(() => createAttestation('a', '', '/ep', 'in', 'out', 'ix', 0)).toThrow('counterpartyId must be a non-empty string');
  });

  it('throws on empty endpoint', () => {
    expect(() => createAttestation('a', 'b', '', 'in', 'out', 'ix', 0)).toThrow('endpoint must be a non-empty string');
  });

  it('throws on negative timestamp', () => {
    expect(() => createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', -1)).toThrow('timestamp must be a non-negative number');
  });
});

// ---------------------------------------------------------------------------
// isSigned
// ---------------------------------------------------------------------------
describe('isSigned', () => {
  it('returns false for unsigned attestation', () => {
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    expect(isSigned(att)).toBe(false);
  });

  it('returns true for signed attestation', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    const signed = await signAttestation(att, kp.privateKey);
    expect(isSigned(signed)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// signAttestation
// ---------------------------------------------------------------------------
describe('signAttestation', () => {
  it('adds a non-empty counterpartySignature', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    const signed = await signAttestation(att, kp.privateKey);
    expect(signed.counterpartySignature).not.toBe('');
    expect(signed.counterpartySignature.length).toBeGreaterThan(0);
  });

  it('returns a new object without mutating the original', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    const signed = await signAttestation(att, kp.privateKey);
    expect(att.counterpartySignature).toBe('');
    expect(signed.counterpartySignature).not.toBe('');
  });

  it('preserves all original fields', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('agent', 'counter', '/api', 'input', 'output', 'interact', 42);
    const signed = await signAttestation(att, kp.privateKey);
    expect(signed.id).toBe(att.id);
    expect(signed.agentId).toBe(att.agentId);
    expect(signed.counterpartyId).toBe(att.counterpartyId);
    expect(signed.endpoint).toBe(att.endpoint);
    expect(signed.inputHash).toBe(att.inputHash);
    expect(signed.outputHash).toBe(att.outputHash);
    expect(signed.interactionHash).toBe(att.interactionHash);
    expect(signed.timestamp).toBe(att.timestamp);
  });

  it('produces a hex-encoded signature (128 hex chars for Ed25519)', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    const signed = await signAttestation(att, kp.privateKey);
    expect(signed.counterpartySignature.length).toBe(128);
    expect(/^[0-9a-f]{128}$/.test(signed.counterpartySignature)).toBe(true);
  });

  it('produces deterministic signature for same key and attestation', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    const signed1 = await signAttestation(att, kp.privateKey);
    const signed2 = await signAttestation(att, kp.privateKey);
    expect(signed1.counterpartySignature).toBe(signed2.counterpartySignature);
  });
});

// ---------------------------------------------------------------------------
// verifyAttestation
// ---------------------------------------------------------------------------
describe('verifyAttestation', () => {
  it('returns true for correctly signed attestation', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    const signed = await signAttestation(att, kp.privateKey);
    const result = await verifyAttestation(signed, kp.publicKey);
    expect(result).toBe(true);
  });

  it('returns false for unsigned attestation', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    const result = await verifyAttestation(att, kp.publicKey);
    expect(result).toBe(false);
  });

  it('returns false for attestation signed with different key', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    const signed = await signAttestation(att, kp1.privateKey);
    const result = await verifyAttestation(signed, kp2.publicKey);
    expect(result).toBe(false);
  });

  it('returns false for tampered attestation', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    const signed = await signAttestation(att, kp.privateKey);
    const tampered = { ...signed, interactionHash: 'tampered' };
    const result = await verifyAttestation(tampered, kp.publicKey);
    expect(result).toBe(false);
  });

  it('returns false for invalid signature hex', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 0);
    const withBadSig = { ...att, counterpartySignature: 'not-valid-hex' };
    const result = await verifyAttestation(withBadSig, kp.publicKey);
    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// reconcile
// ---------------------------------------------------------------------------
describe('reconcile', () => {
  it('returns match=true when all hashes and fields match', () => {
    const receipt: ReceiptSummary = {
      id: 'receipt-1',
      interactionHash: 'ix',
      inputHash: 'in',
      outputHash: 'out',
      endpoint: '/ep',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 100);
    const result = reconcile(receipt, att);
    expect(result.match).toBe(true);
    expect(result.discrepancies).toHaveLength(0);
    expect(result.agentReceiptId).toBe('receipt-1');
    expect(result.attestationId).toBe(att.id);
  });

  it('returns match=false when interactionHash differs', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'ix-agent',
      inputHash: 'in',
      outputHash: 'out',
      endpoint: '/ep',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix-counter', 100);
    const result = reconcile(receipt, att);
    expect(result.match).toBe(false);
    expect(result.discrepancies).toHaveLength(1);
    expect(result.discrepancies[0]!.field).toBe('interactionHash');
    expect(result.discrepancies[0]!.severity).toBe('critical');
  });

  it('returns match=false with multiple discrepancies when all hashes differ', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'a-ix',
      inputHash: 'a-in',
      outputHash: 'a-out',
      endpoint: '/ep',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'c-in', 'c-out', 'c-ix', 100);
    const result = reconcile(receipt, att);
    expect(result.match).toBe(false);
    expect(result.discrepancies).toHaveLength(3);
  });

  it('detects endpoint mismatch as minor discrepancy', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'ix',
      inputHash: 'in',
      outputHash: 'out',
      endpoint: '/api/v1',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/api/v2', 'in', 'out', 'ix', 100);
    const result = reconcile(receipt, att);
    expect(result.match).toBe(false);
    const endpointDisc = result.discrepancies.find(d => d.field === 'endpoint');
    expect(endpointDisc).toBeDefined();
    expect(endpointDisc!.severity).toBe('minor');
  });

  it('detects large timestamp difference as minor discrepancy', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'ix',
      inputHash: 'in',
      outputHash: 'out',
      endpoint: '/ep',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 100000);
    const result = reconcile(receipt, att);
    expect(result.match).toBe(false);
    const tsDisc = result.discrepancies.find(d => d.field === 'timestamp');
    expect(tsDisc).toBeDefined();
    expect(tsDisc!.severity).toBe('minor');
  });

  it('does not flag small timestamp difference', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'ix',
      inputHash: 'in',
      outputHash: 'out',
      endpoint: '/ep',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 102);
    const result = reconcile(receipt, att);
    expect(result.match).toBe(true);
    expect(result.discrepancies).toHaveLength(0);
  });

  it('correctly populates agentClaimed and counterpartyClaimed', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'agent-ix',
      inputHash: 'in',
      outputHash: 'out',
      endpoint: '/ep',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'counter-ix', 100);
    const result = reconcile(receipt, att);
    expect(result.discrepancies[0]!.agentClaimed).toBe('agent-ix');
    expect(result.discrepancies[0]!.counterpartyClaimed).toBe('counter-ix');
  });
});

// ---------------------------------------------------------------------------
// getDiscrepancies
// ---------------------------------------------------------------------------
describe('getDiscrepancies', () => {
  it('returns empty array when all fields match', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'ix',
      inputHash: 'in',
      outputHash: 'out',
      endpoint: '/ep',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 100);
    const discs = getDiscrepancies(receipt, att);
    expect(discs).toHaveLength(0);
  });

  it('returns critical severity for interactionHash mismatch', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'DIFFERENT',
      inputHash: 'in',
      outputHash: 'out',
      endpoint: '/ep',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 100);
    const discs = getDiscrepancies(receipt, att);
    expect(discs).toHaveLength(1);
    expect(discs[0]!.field).toBe('interactionHash');
    expect(discs[0]!.severity).toBe('critical');
  });

  it('returns major severity for inputHash mismatch', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'ix',
      inputHash: 'DIFFERENT',
      outputHash: 'out',
      endpoint: '/ep',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 100);
    const discs = getDiscrepancies(receipt, att);
    expect(discs).toHaveLength(1);
    expect(discs[0]!.field).toBe('inputHash');
    expect(discs[0]!.severity).toBe('major');
  });

  it('returns major severity for outputHash mismatch', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'ix',
      inputHash: 'in',
      outputHash: 'DIFFERENT',
      endpoint: '/ep',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 100);
    const discs = getDiscrepancies(receipt, att);
    expect(discs).toHaveLength(1);
    expect(discs[0]!.field).toBe('outputHash');
    expect(discs[0]!.severity).toBe('major');
  });

  it('returns minor severity for endpoint mismatch', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'ix',
      inputHash: 'in',
      outputHash: 'out',
      endpoint: '/different',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'in', 'out', 'ix', 100);
    const discs = getDiscrepancies(receipt, att);
    const endpointDisc = discs.find(d => d.field === 'endpoint');
    expect(endpointDisc).toBeDefined();
    expect(endpointDisc!.severity).toBe('minor');
  });

  it('returns discrepancies in order: interactionHash, inputHash, outputHash', () => {
    const receipt: ReceiptSummary = {
      id: 'r1',
      interactionHash: 'x',
      inputHash: 'x',
      outputHash: 'x',
      endpoint: '/ep',
      timestamp: 100,
    };
    const att = createAttestation('a', 'b', '/ep', 'y', 'y', 'y', 100);
    const discs = getDiscrepancies(receipt, att);
    expect(discs.length).toBeGreaterThanOrEqual(3);
    expect(discs[0]!.field).toBe('interactionHash');
    expect(discs[1]!.field).toBe('inputHash');
    expect(discs[2]!.field).toBe('outputHash');
  });
});

// ---------------------------------------------------------------------------
// attestationChainVerify
// ---------------------------------------------------------------------------
describe('attestationChainVerify', () => {
  it('returns valid for empty chain', async () => {
    const result = await attestationChainVerify([]);
    expect(result.valid).toBe(true);
    expect(result.verifiedLinks).toBe(0);
    expect(result.totalLinks).toBe(0);
  });

  it('verifies a single valid link', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('agent-1', 'counter-1', '/ep', 'in', 'out', 'ix', 1000);
    const signed = await signAttestation(att, kp.privateKey);
    const chain: AttestationChainLink[] = [
      { attestation: signed, attesterPublicKey: kp.publicKey },
    ];
    const result = await attestationChainVerify(chain);
    expect(result.valid).toBe(true);
    expect(result.verifiedLinks).toBe(1);
  });

  it('fails on unsigned attestation in chain', async () => {
    const kp = await generateKeyPair();
    const att = createAttestation('agent-1', 'counter-1', '/ep', 'in', 'out', 'ix', 1000);
    const chain: AttestationChainLink[] = [
      { attestation: att, attesterPublicKey: kp.publicKey },
    ];
    const result = await attestationChainVerify(chain);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
    expect(result.reason).toContain('not signed');
  });

  it('fails when signature is invalid', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const att = createAttestation('agent-1', 'counter-1', '/ep', 'in', 'out', 'ix', 1000);
    const signed = await signAttestation(att, kp1.privateKey);
    // Use wrong public key for verification
    const chain: AttestationChainLink[] = [
      { attestation: signed, attesterPublicKey: kp2.publicKey },
    ];
    const result = await attestationChainVerify(chain);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
    expect(result.reason).toContain('signature verification failed');
  });

  it('verifies a multi-link chain with proper continuity', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();

    // Link 1: agent-1 -> counter-1
    const att1 = createAttestation('agent-1', 'counter-1', '/ep', 'in1', 'out1', 'ix1', 1000);
    const signed1 = await signAttestation(att1, kp1.privateKey);

    // Link 2: counter-1 -> agent-2 (continues from previous counterparty)
    const att2 = createAttestation('counter-1', 'agent-2', '/ep', 'in2', 'out2', 'ix2', 2000);
    const signed2 = await signAttestation(att2, kp2.privateKey);

    const chain: AttestationChainLink[] = [
      { attestation: signed1, attesterPublicKey: kp1.publicKey },
      { attestation: signed2, attesterPublicKey: kp2.publicKey },
    ];
    const result = await attestationChainVerify(chain);
    expect(result.valid).toBe(true);
    expect(result.verifiedLinks).toBe(2);
    expect(result.totalLinks).toBe(2);
  });

  it('fails when chain is temporally misordered', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();

    const att1 = createAttestation('agent-1', 'counter-1', '/ep', 'in1', 'out1', 'ix1', 5000);
    const signed1 = await signAttestation(att1, kp1.privateKey);

    const att2 = createAttestation('counter-1', 'agent-2', '/ep', 'in2', 'out2', 'ix2', 1000);
    const signed2 = await signAttestation(att2, kp2.privateKey);

    const chain: AttestationChainLink[] = [
      { attestation: signed1, attesterPublicKey: kp1.publicKey },
      { attestation: signed2, attesterPublicKey: kp2.publicKey },
    ];
    const result = await attestationChainVerify(chain);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
    expect(result.reason).toContain('timestamp');
  });

  it('fails when chain continuity is broken (agentId mismatch)', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();

    const att1 = createAttestation('agent-1', 'counter-1', '/ep', 'in1', 'out1', 'ix1', 1000);
    const signed1 = await signAttestation(att1, kp1.privateKey);

    // agent-2 instead of counter-1 breaks continuity
    const att2 = createAttestation('agent-2', 'counter-2', '/ep', 'in2', 'out2', 'ix2', 2000);
    const signed2 = await signAttestation(att2, kp2.privateKey);

    const chain: AttestationChainLink[] = [
      { attestation: signed1, attesterPublicKey: kp1.publicKey },
      { attestation: signed2, attesterPublicKey: kp2.publicKey },
    ];
    const result = await attestationChainVerify(chain);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
    expect(result.reason).toContain('agentId');
  });

  it('reports correct verifiedLinks before break', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();

    const att1 = createAttestation('agent-1', 'counter-1', '/ep', 'in1', 'out1', 'ix1', 1000);
    const signed1 = await signAttestation(att1, kp1.privateKey);

    // Second link is unsigned
    const att2 = createAttestation('counter-1', 'agent-2', '/ep', 'in2', 'out2', 'ix2', 2000);

    const chain: AttestationChainLink[] = [
      { attestation: signed1, attesterPublicKey: kp1.publicKey },
      { attestation: att2, attesterPublicKey: kp2.publicKey },
    ];
    const result = await attestationChainVerify(chain);
    expect(result.valid).toBe(false);
    expect(result.verifiedLinks).toBe(1);
    expect(result.brokenAt).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// computeAttestationCoverage
// ---------------------------------------------------------------------------
describe('computeAttestationCoverage', () => {
  it('returns 100% coverage for empty actions', () => {
    const result = computeAttestationCoverage([], []);
    expect(result.totalActions).toBe(0);
    expect(result.coveredActions).toBe(0);
    expect(result.coveragePercentage).toBe(100);
    expect(result.uncoveredActionIds).toEqual([]);
  });

  it('returns 0% coverage when no attestations exist', () => {
    const actions: AgentAction[] = [
      { id: 'a1', agentId: 'agent-1', timestamp: 1000, actionType: 'query' },
      { id: 'a2', agentId: 'agent-1', timestamp: 2000, actionType: 'write' },
    ];
    const result = computeAttestationCoverage(actions, []);
    expect(result.totalActions).toBe(2);
    expect(result.coveredActions).toBe(0);
    expect(result.coveragePercentage).toBe(0);
    expect(result.uncoveredActionIds).toEqual(['a1', 'a2']);
  });

  it('returns 100% coverage when all actions are attested', () => {
    const actions: AgentAction[] = [
      { id: 'a1', agentId: 'agent-1', timestamp: 1000, actionType: 'query' },
    ];
    const attestations: ExternalAttestation[] = [
      createAttestation('agent-1', 'counter-1', '/ep', 'in', 'out', 'ix', 1000),
    ];
    const result = computeAttestationCoverage(actions, attestations);
    expect(result.totalActions).toBe(1);
    expect(result.coveredActions).toBe(1);
    expect(result.coveragePercentage).toBe(100);
    expect(result.uncoveredActionIds).toEqual([]);
  });

  it('matches attestations within the time window', () => {
    const actions: AgentAction[] = [
      { id: 'a1', agentId: 'agent-1', timestamp: 1000, actionType: 'query' },
    ];
    const attestations: ExternalAttestation[] = [
      createAttestation('agent-1', 'counter-1', '/ep', 'in', 'out', 'ix', 4000),
    ];
    // Default window is 5000ms, so 4000 - 1000 = 3000 < 5000 => covered
    const result = computeAttestationCoverage(actions, attestations);
    expect(result.coveredActions).toBe(1);
  });

  it('does not match attestations outside the time window', () => {
    const actions: AgentAction[] = [
      { id: 'a1', agentId: 'agent-1', timestamp: 1000, actionType: 'query' },
    ];
    const attestations: ExternalAttestation[] = [
      createAttestation('agent-1', 'counter-1', '/ep', 'in', 'out', 'ix', 10000),
    ];
    // 10000 - 1000 = 9000 > 5000 => not covered
    const result = computeAttestationCoverage(actions, attestations);
    expect(result.coveredActions).toBe(0);
    expect(result.uncoveredActionIds).toEqual(['a1']);
  });

  it('does not match attestations for different agents', () => {
    const actions: AgentAction[] = [
      { id: 'a1', agentId: 'agent-1', timestamp: 1000, actionType: 'query' },
    ];
    const attestations: ExternalAttestation[] = [
      createAttestation('agent-2', 'counter-1', '/ep', 'in', 'out', 'ix', 1000),
    ];
    const result = computeAttestationCoverage(actions, attestations);
    expect(result.coveredActions).toBe(0);
  });

  it('handles partial coverage correctly', () => {
    const actions: AgentAction[] = [
      { id: 'a1', agentId: 'agent-1', timestamp: 1000, actionType: 'query' },
      { id: 'a2', agentId: 'agent-1', timestamp: 2000, actionType: 'write' },
      { id: 'a3', agentId: 'agent-1', timestamp: 50000, actionType: 'delete' },
    ];
    const attestations: ExternalAttestation[] = [
      createAttestation('agent-1', 'counter-1', '/ep', 'in', 'out', 'ix', 1500),
    ];
    // a1: |1500-1000| = 500 <= 5000 => covered
    // a2: |1500-2000| = 500 <= 5000 => covered
    // a3: |1500-50000| = 48500 > 5000 => not covered
    const result = computeAttestationCoverage(actions, attestations);
    expect(result.coveredActions).toBe(2);
    expect(result.coveragePercentage).toBeCloseTo(66.67, 1);
    expect(result.uncoveredActionIds).toEqual(['a3']);
  });

  it('respects custom time window', () => {
    const actions: AgentAction[] = [
      { id: 'a1', agentId: 'agent-1', timestamp: 1000, actionType: 'query' },
    ];
    const attestations: ExternalAttestation[] = [
      createAttestation('agent-1', 'counter-1', '/ep', 'in', 'out', 'ix', 1500),
    ];
    // With timeWindowMs=100, |1500-1000|=500 > 100 => not covered
    const result = computeAttestationCoverage(actions, attestations, 100);
    expect(result.coveredActions).toBe(0);
  });

  it('throws on negative timeWindowMs', () => {
    expect(() => computeAttestationCoverage([], [], -1)).toThrow('timeWindowMs must be non-negative');
  });

  it('handles multiple attestations covering the same action', () => {
    const actions: AgentAction[] = [
      { id: 'a1', agentId: 'agent-1', timestamp: 1000, actionType: 'query' },
    ];
    const attestations: ExternalAttestation[] = [
      createAttestation('agent-1', 'counter-1', '/ep', 'in1', 'out1', 'ix1', 1000),
      createAttestation('agent-1', 'counter-2', '/ep', 'in2', 'out2', 'ix2', 1001),
    ];
    const result = computeAttestationCoverage(actions, attestations);
    // Still counts as 1 covered action
    expect(result.coveredActions).toBe(1);
    expect(result.coveragePercentage).toBe(100);
  });

  it('handles zero time window (exact match only)', () => {
    const actions: AgentAction[] = [
      { id: 'a1', agentId: 'agent-1', timestamp: 1000, actionType: 'query' },
      { id: 'a2', agentId: 'agent-1', timestamp: 2000, actionType: 'write' },
    ];
    const attestations: ExternalAttestation[] = [
      createAttestation('agent-1', 'counter-1', '/ep', 'in', 'out', 'ix', 1000),
    ];
    const result = computeAttestationCoverage(actions, attestations, 0);
    expect(result.coveredActions).toBe(1);
    expect(result.uncoveredActionIds).toEqual(['a2']);
  });
});

// ---------------------------------------------------------------------------
// createEntanglement
// ---------------------------------------------------------------------------
describe('createEntanglement', () => {
  it('creates a valid EntanglementLink', () => {
    const link = createEntanglement({
      sourceAgentId: 'agent-a',
      targetAgentId: 'agent-b',
      strength: 0.8,
      mutualObligations: ['data-privacy'],
      conditionalDependencies: ['service-availability'],
    });

    expect(link.sourceAgentId).toBe('agent-a');
    expect(link.targetAgentId).toBe('agent-b');
    expect(link.entanglementStrength).toBe(0.8);
    expect(link.mutualObligations).toEqual(['data-privacy']);
    expect(link.conditionalDependencies).toEqual(['service-availability']);
    expect(typeof link.createdAt).toBe('number');
    expect(link.linkHash).toBeTruthy();
    expect(link.linkHash.length).toBe(64);
  });

  it('produces deterministic linkHash for same inputs (regardless of agent order)', () => {
    const link1 = createEntanglement({
      sourceAgentId: 'agent-a',
      targetAgentId: 'agent-b',
      strength: 0.5,
      mutualObligations: ['obligation-1'],
    });
    const link2 = createEntanglement({
      sourceAgentId: 'agent-b',
      targetAgentId: 'agent-a',
      strength: 0.5,
      mutualObligations: ['obligation-1'],
    });

    // linkHash is based on sorted agents, so it should be identical
    expect(link1.linkHash).toBe(link2.linkHash);
  });

  it('produces different linkHash for different strengths', () => {
    const link1 = createEntanglement({
      sourceAgentId: 'agent-a',
      targetAgentId: 'agent-b',
      strength: 0.5,
    });
    const link2 = createEntanglement({
      sourceAgentId: 'agent-a',
      targetAgentId: 'agent-b',
      strength: 0.9,
    });

    expect(link1.linkHash).not.toBe(link2.linkHash);
  });

  it('defaults mutualObligations and conditionalDependencies to empty arrays', () => {
    const link = createEntanglement({
      sourceAgentId: 'agent-a',
      targetAgentId: 'agent-b',
      strength: 0.5,
    });

    expect(link.mutualObligations).toEqual([]);
    expect(link.conditionalDependencies).toEqual([]);
  });

  it('throws on empty sourceAgentId', () => {
    expect(() => createEntanglement({
      sourceAgentId: '',
      targetAgentId: 'agent-b',
      strength: 0.5,
    })).toThrow('sourceAgentId must be a non-empty string');
  });

  it('throws on empty targetAgentId', () => {
    expect(() => createEntanglement({
      sourceAgentId: 'agent-a',
      targetAgentId: '',
      strength: 0.5,
    })).toThrow('targetAgentId must be a non-empty string');
  });

  it('throws on strength below 0', () => {
    expect(() => createEntanglement({
      sourceAgentId: 'agent-a',
      targetAgentId: 'agent-b',
      strength: -0.1,
    })).toThrow('strength must be a number between 0 and 1');
  });

  it('throws on strength above 1', () => {
    expect(() => createEntanglement({
      sourceAgentId: 'agent-a',
      targetAgentId: 'agent-b',
      strength: 1.1,
    })).toThrow('strength must be a number between 0 and 1');
  });

  it('accepts boundary strength values 0 and 1', () => {
    const link0 = createEntanglement({
      sourceAgentId: 'agent-a',
      targetAgentId: 'agent-b',
      strength: 0,
    });
    expect(link0.entanglementStrength).toBe(0);

    const link1 = createEntanglement({
      sourceAgentId: 'agent-a',
      targetAgentId: 'agent-b',
      strength: 1,
    });
    expect(link1.entanglementStrength).toBe(1);
  });

  it('linkHash is a valid 64-character hex string', () => {
    const link = createEntanglement({
      sourceAgentId: 'x',
      targetAgentId: 'y',
      strength: 0.5,
    });
    expect(/^[0-9a-f]{64}$/.test(link.linkHash)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// buildEntanglementNetwork
// ---------------------------------------------------------------------------
describe('buildEntanglementNetwork', () => {
  it('builds network from empty links array', () => {
    const network = buildEntanglementNetwork([]);
    expect(network.links).toHaveLength(0);
    expect(network.agents.size).toBe(0);
    expect(network.verificationCoverage).toBe(0);
    expect(network.sublinearCostRatio).toBe(1);
  });

  it('collects all unique agents from links', () => {
    const link1 = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.5 });
    const link2 = createEntanglement({ sourceAgentId: 'b', targetAgentId: 'c', strength: 0.5 });
    const link3 = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'c', strength: 0.5 });

    const network = buildEntanglementNetwork([link1, link2, link3]);
    expect(network.agents.size).toBe(3);
    expect(network.agents.has('a')).toBe(true);
    expect(network.agents.has('b')).toBe(true);
    expect(network.agents.has('c')).toBe(true);
  });

  it('computes verificationCoverage based on network effect formula', () => {
    const link = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.8 });
    const network = buildEntanglementNetwork([link]);

    // avgStrength = 0.8, agents = 2, avgLinksPerAgent = 2/2 = 1
    // coverage = 1 - (1 - 0.8)^1 = 0.8
    expect(network.verificationCoverage).toBeCloseTo(0.8, 5);
  });

  it('computes sublinearCostRatio as sqrt(n)/n', () => {
    const links = [
      createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.5 }),
      createEntanglement({ sourceAgentId: 'c', targetAgentId: 'd', strength: 0.5 }),
    ];
    const network = buildEntanglementNetwork(links);

    // 4 agents: sqrt(4)/4 = 2/4 = 0.5
    expect(network.sublinearCostRatio).toBeCloseTo(0.5, 5);
  });

  it('higher strength produces higher verificationCoverage', () => {
    const weakLink = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.2 });
    const strongLink = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.9 });

    const weakNet = buildEntanglementNetwork([weakLink]);
    const strongNet = buildEntanglementNetwork([strongLink]);

    expect(strongNet.verificationCoverage).toBeGreaterThan(weakNet.verificationCoverage);
  });

  it('more links produce higher verificationCoverage', () => {
    const singleLink = [
      createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.5 }),
    ];
    const multipleLinks = [
      createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.5 }),
      createEntanglement({ sourceAgentId: 'b', targetAgentId: 'a', strength: 0.5 }),
      createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.5 }),
    ];

    const singleNet = buildEntanglementNetwork(singleLink);
    const multiNet = buildEntanglementNetwork(multipleLinks);

    expect(multiNet.verificationCoverage).toBeGreaterThanOrEqual(singleNet.verificationCoverage);
  });

  it('preserves all links in the network', () => {
    const links = [
      createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.3 }),
      createEntanglement({ sourceAgentId: 'b', targetAgentId: 'c', strength: 0.7 }),
    ];
    const network = buildEntanglementNetwork(links);
    expect(network.links).toHaveLength(2);
    expect(network.links[0]!.entanglementStrength).toBe(0.3);
    expect(network.links[1]!.entanglementStrength).toBe(0.7);
  });

  it('network with single agent pair has sublinearCostRatio = 1/sqrt(2)', () => {
    const link = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.5 });
    const network = buildEntanglementNetwork([link]);
    // sqrt(2)/2 ≈ 0.7071
    expect(network.sublinearCostRatio).toBeCloseTo(Math.sqrt(2) / 2, 4);
  });
});

// ---------------------------------------------------------------------------
// verifyEntangled
// ---------------------------------------------------------------------------
describe('verifyEntangled', () => {
  it('returns the verified agent as directlyVerified', () => {
    const link = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.8 });
    const network = buildEntanglementNetwork([link]);

    const result = verifyEntangled(network, 'a');
    expect(result.directlyVerified).toBe('a');
  });

  it('finds transitively verified agents through direct links', () => {
    const link = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.8 });
    const network = buildEntanglementNetwork([link]);

    const result = verifyEntangled(network, 'a');
    expect(result.transitivelyVerified).toContain('b');
    expect(result.transitiveConfidence['b']).toBeCloseTo(0.8, 5);
  });

  it('follows multi-hop entanglement paths with decaying confidence', () => {
    const link1 = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.8 });
    const link2 = createEntanglement({ sourceAgentId: 'b', targetAgentId: 'c', strength: 0.5 });
    const network = buildEntanglementNetwork([link1, link2]);

    const result = verifyEntangled(network, 'a');
    expect(result.transitivelyVerified).toContain('b');
    expect(result.transitivelyVerified).toContain('c');
    // c's confidence = 0.8 * 0.5 = 0.4
    expect(result.transitiveConfidence['b']).toBeCloseTo(0.8, 5);
    expect(result.transitiveConfidence['c']).toBeCloseTo(0.4, 5);
  });

  it('excludes agents with confidence <= 0.1', () => {
    const link1 = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.3 });
    const link2 = createEntanglement({ sourceAgentId: 'b', targetAgentId: 'c', strength: 0.3 });
    const network = buildEntanglementNetwork([link1, link2]);

    const result = verifyEntangled(network, 'a');
    expect(result.transitivelyVerified).toContain('b');
    // c's confidence = 0.3 * 0.3 = 0.09 <= 0.1, so c is NOT transitively verified
    expect(result.transitivelyVerified).not.toContain('c');
  });

  it('computes costSavings correctly', () => {
    const links = [
      createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.8 }),
      createEntanglement({ sourceAgentId: 'b', targetAgentId: 'c', strength: 0.8 }),
      createEntanglement({ sourceAgentId: 'c', targetAgentId: 'd', strength: 0.8 }),
    ];
    const network = buildEntanglementNetwork(links);

    const result = verifyEntangled(network, 'a');
    // b, c, d are transitively verified; network has 4 agents
    // costSavings = 3 / 4 = 0.75
    expect(result.transitivelyVerified).toHaveLength(3);
    expect(result.costSavings).toBeCloseTo(0.75, 5);
  });

  it('handles agent not in network', () => {
    const link = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.8 });
    const network = buildEntanglementNetwork([link]);

    const result = verifyEntangled(network, 'unknown');
    expect(result.directlyVerified).toBe('unknown');
    expect(result.transitivelyVerified).toHaveLength(0);
    expect(result.costSavings).toBe(0);
  });

  it('handles empty network', () => {
    const network = buildEntanglementNetwork([]);
    const result = verifyEntangled(network, 'agent-a');

    expect(result.directlyVerified).toBe('agent-a');
    expect(result.transitivelyVerified).toHaveLength(0);
    expect(result.costSavings).toBe(0);
  });

  it('handles bidirectional links', () => {
    const link1 = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.9 });
    const link2 = createEntanglement({ sourceAgentId: 'b', targetAgentId: 'a', strength: 0.9 });
    const network = buildEntanglementNetwork([link1, link2]);

    const result = verifyEntangled(network, 'a');
    expect(result.transitivelyVerified).toContain('b');
  });

  it('does not revisit already visited agents (no infinite loops)', () => {
    // Create a cycle: a -> b -> c -> a
    const links = [
      createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0.9 }),
      createEntanglement({ sourceAgentId: 'b', targetAgentId: 'c', strength: 0.9 }),
      createEntanglement({ sourceAgentId: 'c', targetAgentId: 'a', strength: 0.9 }),
    ];
    const network = buildEntanglementNetwork(links);

    // Should not hang or throw
    const result = verifyEntangled(network, 'a');
    expect(result.transitivelyVerified).toContain('b');
    expect(result.transitivelyVerified).toContain('c');
  });

  it('confidence from a direct link with strength 0 excludes the neighbor', () => {
    const link = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 0 });
    const network = buildEntanglementNetwork([link]);

    const result = verifyEntangled(network, 'a');
    // strength 0 => confidence 0, which is <= 0.1
    expect(result.transitivelyVerified).not.toContain('b');
  });

  it('confidence from a direct link with strength 1 fully verifies the neighbor', () => {
    const link = createEntanglement({ sourceAgentId: 'a', targetAgentId: 'b', strength: 1 });
    const network = buildEntanglementNetwork([link]);

    const result = verifyEntangled(network, 'a');
    expect(result.transitivelyVerified).toContain('b');
    expect(result.transitiveConfidence['b']).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// assessConditionalRisk
// ---------------------------------------------------------------------------
describe('assessConditionalRisk', () => {
  it('returns empty affected agents when no conditional dependencies exist', () => {
    const link = createEntanglement({
      sourceAgentId: 'a',
      targetAgentId: 'b',
      strength: 0.8,
      mutualObligations: ['data-privacy'],
      // No conditional dependencies
    });
    const network = buildEntanglementNetwork([link]);

    const risk = assessConditionalRisk(network, 'a');
    expect(risk.affectedAgents).toHaveLength(0);
    expect(risk.cascadeRisk).toBe(0);
    expect(risk.recommendations).toHaveLength(1);
    expect(risk.recommendations[0]).toContain('minimal');
  });

  it('identifies affected agents with conditional dependencies', () => {
    const link = createEntanglement({
      sourceAgentId: 'a',
      targetAgentId: 'b',
      strength: 0.8,
      conditionalDependencies: ['service-availability'],
    });
    const network = buildEntanglementNetwork([link]);

    const risk = assessConditionalRisk(network, 'a');
    expect(risk.affectedAgents).toContain('b');
    expect(risk.cascadeRisk).toBeCloseTo(1.0, 5); // only link in network
  });

  it('computes cascadeRisk as affected strength / total strength', () => {
    const links = [
      createEntanglement({
        sourceAgentId: 'a',
        targetAgentId: 'b',
        strength: 0.4,
        conditionalDependencies: ['dep-1'],
      }),
      createEntanglement({
        sourceAgentId: 'c',
        targetAgentId: 'd',
        strength: 0.6,
      }),
    ];
    const network = buildEntanglementNetwork(links);

    const risk = assessConditionalRisk(network, 'a');
    // affected strength = 0.4, total = 0.4 + 0.6 = 1.0
    expect(risk.cascadeRisk).toBeCloseTo(0.4, 5);
    expect(risk.affectedAgents).toEqual(['b']);
  });

  it('recommends re-verification for each affected agent', () => {
    const links = [
      createEntanglement({
        sourceAgentId: 'a',
        targetAgentId: 'b',
        strength: 0.5,
        conditionalDependencies: ['service-availability'],
      }),
      createEntanglement({
        sourceAgentId: 'a',
        targetAgentId: 'c',
        strength: 0.5,
        conditionalDependencies: ['data-integrity'],
      }),
    ];
    const network = buildEntanglementNetwork(links);

    const risk = assessConditionalRisk(network, 'a');
    expect(risk.affectedAgents).toContain('b');
    expect(risk.affectedAgents).toContain('c');
    // Should have a recommendation per affected agent, plus high cascade risk warning
    const reVerifyRecs = risk.recommendations.filter(r => r.includes('Re-verify'));
    expect(reVerifyRecs).toHaveLength(2);
  });

  it('adds high cascade risk warning when cascadeRisk > 0.5', () => {
    const link = createEntanglement({
      sourceAgentId: 'a',
      targetAgentId: 'b',
      strength: 0.9,
      conditionalDependencies: ['critical-service'],
    });
    const network = buildEntanglementNetwork([link]);

    const risk = assessConditionalRisk(network, 'a');
    expect(risk.cascadeRisk).toBeGreaterThan(0.5);
    const highRiskRec = risk.recommendations.find(r => r.includes('High cascade risk'));
    expect(highRiskRec).toBeDefined();
  });

  it('does not add high cascade risk warning when cascadeRisk <= 0.5', () => {
    const links = [
      createEntanglement({
        sourceAgentId: 'a',
        targetAgentId: 'b',
        strength: 0.2,
        conditionalDependencies: ['dep'],
      }),
      createEntanglement({
        sourceAgentId: 'c',
        targetAgentId: 'd',
        strength: 0.8,
      }),
    ];
    const network = buildEntanglementNetwork(links);

    const risk = assessConditionalRisk(network, 'a');
    expect(risk.cascadeRisk).toBeLessThanOrEqual(0.5);
    const highRiskRec = risk.recommendations.find(r => r.includes('High cascade risk'));
    expect(highRiskRec).toBeUndefined();
  });

  it('handles failed agent not in network', () => {
    const link = createEntanglement({
      sourceAgentId: 'a',
      targetAgentId: 'b',
      strength: 0.5,
      conditionalDependencies: ['dep'],
    });
    const network = buildEntanglementNetwork([link]);

    const risk = assessConditionalRisk(network, 'unknown');
    expect(risk.affectedAgents).toHaveLength(0);
    expect(risk.cascadeRisk).toBe(0);
  });

  it('handles empty network', () => {
    const network = buildEntanglementNetwork([]);
    const risk = assessConditionalRisk(network, 'a');

    expect(risk.affectedAgents).toHaveLength(0);
    expect(risk.cascadeRisk).toBe(0);
    expect(risk.recommendations).toHaveLength(1);
  });

  it('does not double-count affected agents with multiple links', () => {
    const links = [
      createEntanglement({
        sourceAgentId: 'a',
        targetAgentId: 'b',
        strength: 0.3,
        conditionalDependencies: ['dep-1'],
      }),
      createEntanglement({
        sourceAgentId: 'a',
        targetAgentId: 'b',
        strength: 0.4,
        conditionalDependencies: ['dep-2'],
      }),
    ];
    const network = buildEntanglementNetwork(links);

    const risk = assessConditionalRisk(network, 'a');
    // b appears in both links but should only be listed once
    expect(risk.affectedAgents).toEqual(['b']);
  });

  it('considers target-side failure correctly', () => {
    const link = createEntanglement({
      sourceAgentId: 'a',
      targetAgentId: 'b',
      strength: 0.6,
      conditionalDependencies: ['bidirectional-dep'],
    });
    const network = buildEntanglementNetwork([link]);

    // Fail agent 'b' (target side)
    const risk = assessConditionalRisk(network, 'b');
    expect(risk.affectedAgents).toContain('a');
    expect(risk.cascadeRisk).toBeCloseTo(0.6 / 0.6, 5);
  });
});
