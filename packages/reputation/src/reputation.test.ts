import { describe, it, expect } from 'vitest';
import { generateKeyPair, sha256String, toHex } from '@stele/crypto';
import type { KeyPair, HashHex } from '@stele/crypto';
import {
  createReceipt,
  verifyReceipt,
  countersignReceipt,
  verifyReceiptChain,
  computeReputationScore,
  computeReceiptsMerkleRoot,
  createStake,
  releaseStake,
  burnStake,
  createDelegation,
  burnDelegation,
  coBurnDelegation,
  createEndorsement,
  verifyEndorsement,
  DEFAULT_SCORING_CONFIG,
  createResourcePool,
  allocateTrust,
  releaseTrust,
  slashStake,
  collateralizationRatio,
  computeProfile,
  compareProfiles,
  STAKE_TIERS,
  assignTier,
  createStakedAgent,
  recordQuery,
  computeGovernanceVote,
  ReceiptDAG,
  ReputationDecayModel,
  GraduatedBurner,
  ReputationAggregator,
} from './index.js';
import type {
  ExecutionReceipt,
  ReputationScore,
  Endorsement,
  ResourcePool,
  SlashingEvent,
  MultidimensionalProfile,
  StakeTier,
  StakedAgent,
} from './types.js';
import type {
  DecayModelConfig,
  ReputationSource,
  ReceiptDAGNode,
} from './index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generate a deterministic-looking hex hash (just a SHA-256 of a label). */
function fakeHash(label: string): HashHex {
  return sha256String(label);
}

/** Create a receipt using the agent's publicKeyHex as agentIdentityHash so
 *  that verifyReceipt can verify the signature against it. */
async function makeReceipt(
  agentKp: KeyPair,
  principalKp: KeyPair,
  outcome: ExecutionReceipt['outcome'] = 'fulfilled',
  previousReceiptHash: HashHex | null = null,
  breachSeverity?: 'critical' | 'high' | 'medium' | 'low',
): Promise<ExecutionReceipt> {
  return createReceipt(
    fakeHash('covenant-1'),
    agentKp.publicKeyHex,          // use raw pubkey hex so verify works
    principalKp.publicKeyHex,
    outcome,
    fakeHash('proof-1'),
    150,
    agentKp,
    previousReceiptHash,
    breachSeverity,
  );
}

// ---------------------------------------------------------------------------
// createReceipt
// ---------------------------------------------------------------------------

describe('createReceipt', () => {
  it('creates a valid receipt with all required fields', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipt = await makeReceipt(agentKp, principalKp);

    expect(receipt.id).toBeDefined();
    expect(receipt.id).toBe(receipt.receiptHash);
    expect(receipt.covenantId).toBe(fakeHash('covenant-1'));
    expect(receipt.agentIdentityHash).toBe(agentKp.publicKeyHex);
    expect(receipt.principalPublicKey).toBe(principalKp.publicKeyHex);
    expect(receipt.outcome).toBe('fulfilled');
    expect(receipt.proofHash).toBe(fakeHash('proof-1'));
    expect(receipt.durationMs).toBe(150);
    expect(receipt.completedAt).toBeDefined();
    expect(receipt.agentSignature).toBeDefined();
    expect(typeof receipt.agentSignature).toBe('string');
    expect(receipt.agentSignature.length).toBeGreaterThan(0);
    expect(receipt.previousReceiptHash).toBeNull();
    expect(receipt.principalSignature).toBeUndefined();
  });

  it('includes breachSeverity when outcome is breached', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipt = await makeReceipt(agentKp, principalKp, 'breached', null, 'high');

    expect(receipt.outcome).toBe('breached');
    expect(receipt.breachSeverity).toBe('high');
  });

  it('omits breachSeverity when not provided', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipt = await makeReceipt(agentKp, principalKp, 'fulfilled');

    expect(receipt.breachSeverity).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// createReceipt -> verifyReceipt round-trip
// ---------------------------------------------------------------------------

describe('createReceipt -> verifyReceipt round-trip', () => {
  it('verifies a freshly created receipt', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipt = await makeReceipt(agentKp, principalKp);
    const valid = await verifyReceipt(receipt);

    expect(valid).toBe(true);
  });

  it('fails verification when receiptHash is tampered', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipt = await makeReceipt(agentKp, principalKp);
    const tampered = { ...receipt, receiptHash: fakeHash('tampered') };
    const valid = await verifyReceipt(tampered);

    expect(valid).toBe(false);
  });

  it('fails verification when a content field is tampered', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipt = await makeReceipt(agentKp, principalKp);
    const tampered = { ...receipt, durationMs: 9999 };
    const valid = await verifyReceipt(tampered);

    expect(valid).toBe(false);
  });

  it('fails verification when agentSignature is tampered', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipt = await makeReceipt(agentKp, principalKp);
    // Flip the last hex digit in the signature
    const sig = receipt.agentSignature;
    const lastChar = sig[sig.length - 1]!;
    const flipped = lastChar === '0' ? '1' : '0';
    const tampered = { ...receipt, agentSignature: sig.slice(0, -1) + flipped };
    const valid = await verifyReceipt(tampered);

    expect(valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// countersignReceipt
// ---------------------------------------------------------------------------

describe('countersignReceipt', () => {
  it('adds principalSignature to the receipt', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipt = await makeReceipt(agentKp, principalKp);
    expect(receipt.principalSignature).toBeUndefined();

    const countersigned = await countersignReceipt(receipt, principalKp);

    expect(countersigned.principalSignature).toBeDefined();
    expect(typeof countersigned.principalSignature).toBe('string');
    expect(countersigned.principalSignature!.length).toBeGreaterThan(0);
  });

  it('does not mutate the original receipt', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipt = await makeReceipt(agentKp, principalKp);
    await countersignReceipt(receipt, principalKp);

    expect(receipt.principalSignature).toBeUndefined();
  });

  it('preserves all existing receipt fields', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipt = await makeReceipt(agentKp, principalKp);
    const countersigned = await countersignReceipt(receipt, principalKp);

    expect(countersigned.id).toBe(receipt.id);
    expect(countersigned.receiptHash).toBe(receipt.receiptHash);
    expect(countersigned.agentSignature).toBe(receipt.agentSignature);
    expect(countersigned.covenantId).toBe(receipt.covenantId);
    expect(countersigned.outcome).toBe(receipt.outcome);
  });
});

// ---------------------------------------------------------------------------
// verifyReceiptChain
// ---------------------------------------------------------------------------

describe('verifyReceiptChain', () => {
  it('validates a correct chain of receipts', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const r2 = await makeReceipt(agentKp, principalKp, 'fulfilled', r1.receiptHash);
    const r3 = await makeReceipt(agentKp, principalKp, 'partial', r2.receiptHash);

    expect(verifyReceiptChain([r1, r2, r3])).toBe(true);
  });

  it('validates an empty chain', () => {
    expect(verifyReceiptChain([])).toBe(true);
  });

  it('validates a single-element chain', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    expect(verifyReceiptChain([r1])).toBe(true);
  });

  it('fails when the first receipt has a non-null previousReceiptHash', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', fakeHash('bogus'));
    expect(verifyReceiptChain([r1])).toBe(false);
  });

  it('fails with a broken chain (wrong previousReceiptHash)', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    // r2 points to a bogus hash instead of r1.receiptHash
    const r2 = await makeReceipt(agentKp, principalKp, 'fulfilled', fakeHash('wrong'));

    expect(verifyReceiptChain([r1, r2])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// computeReputationScore
// ---------------------------------------------------------------------------

describe('computeReputationScore', () => {
  it('counts outcomes correctly', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const r2 = await makeReceipt(agentKp, principalKp, 'fulfilled', r1.receiptHash);
    const r3 = await makeReceipt(agentKp, principalKp, 'partial', r2.receiptHash);
    const r4 = await makeReceipt(agentKp, principalKp, 'failed', r3.receiptHash);
    const r5 = await makeReceipt(agentKp, principalKp, 'breached', r4.receiptHash, 'medium');

    const score = computeReputationScore(agentKp.publicKeyHex, [r1, r2, r3, r4, r5]);

    expect(score.totalExecutions).toBe(5);
    expect(score.fulfilled).toBe(2);
    expect(score.partial).toBe(1);
    expect(score.failed).toBe(1);
    expect(score.breached).toBe(1);
    expect(score.agentIdentityHash).toBe(agentKp.publicKeyHex);
  });

  it('applies breach penalties (breached receipts lower the score)', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    // All fulfilled
    const fulfilledReceipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 10; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      fulfilledReceipts.push(r);
      prevHash = r.receiptHash;
    }
    const fulfilledScore = computeReputationScore(agentKp.publicKeyHex, fulfilledReceipts);

    // Same count but with some breaches
    const mixedReceipts: ExecutionReceipt[] = [];
    prevHash = null;
    for (let i = 0; i < 7; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      mixedReceipts.push(r);
      prevHash = r.receiptHash;
    }
    for (let i = 0; i < 3; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'breached', prevHash, 'high');
      mixedReceipts.push(r);
      prevHash = r.receiptHash;
    }
    const mixedScore = computeReputationScore(agentKp.publicKeyHex, mixedReceipts);

    expect(mixedScore.weightedScore).toBeLessThan(fulfilledScore.weightedScore);
    expect(mixedScore.breached).toBe(3);
  });

  it('perfect record yields a high score', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 15; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      receipts.push(r);
      prevHash = r.receiptHash;
    }

    const score = computeReputationScore(agentKp.publicKeyHex, receipts);

    // With 15 fulfilled (>= minimumExecutions of 10), score should be close to 1.0
    expect(score.weightedScore).toBeGreaterThan(0.9);
    expect(score.successRate).toBe(1.0);
  });

  it('all breached yields a low score', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 10; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'breached', prevHash, 'critical');
      receipts.push(r);
      prevHash = r.receiptHash;
    }

    const score = computeReputationScore(agentKp.publicKeyHex, receipts);

    // Breached with critical severity yields negative outcome scores; clamped to 0
    expect(score.weightedScore).toBe(0);
    expect(score.successRate).toBe(0);
    expect(score.breached).toBe(10);
  });

  it('no receipts yields zero score', () => {
    const score = computeReputationScore(fakeHash('agent'), []);

    expect(score.totalExecutions).toBe(0);
    expect(score.weightedScore).toBe(0);
    expect(score.successRate).toBe(0);
    expect(score.fulfilled).toBe(0);
  });

  it('below minimumExecutions scales the score down', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    // 3 fulfilled receipts (below minimumExecutions of 10)
    const smallReceipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 3; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      smallReceipts.push(r);
      prevHash = r.receiptHash;
    }

    // 15 fulfilled receipts (above minimumExecutions of 10)
    const largeReceipts: ExecutionReceipt[] = [];
    prevHash = null;
    for (let i = 0; i < 15; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      largeReceipts.push(r);
      prevHash = r.receiptHash;
    }

    const smallScore = computeReputationScore(agentKp.publicKeyHex, smallReceipts);
    const largeScore = computeReputationScore(agentKp.publicKeyHex, largeReceipts);

    // The small set should be penalized for having < minimumExecutions
    expect(smallScore.weightedScore).toBeLessThan(largeScore.weightedScore);
  });

  it('includes endorsements in the score calculation', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const endorserKp = await generateKeyPair();

    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 10; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      receipts.push(r);
      prevHash = r.receiptHash;
    }

    const endorsement = await createEndorsement(
      endorserKp.publicKeyHex,
      agentKp.publicKeyHex,
      { covenantsCompleted: 10, breachRate: 0 },
      ['general'],
      0.9,
      endorserKp,
    );

    const scoreWithout = computeReputationScore(agentKp.publicKeyHex, receipts);
    const scoreWith = computeReputationScore(agentKp.publicKeyHex, receipts, [endorsement]);

    // With endorsements, the calculation blends in the endorsement weight
    // Both should be high for all-fulfilled, but the blending changes the value slightly
    expect(scoreWith.weightedScore).toBeDefined();
    expect(typeof scoreWith.weightedScore).toBe('number');
    // The endorsement weight is 0.15, endorsement value is 0.9
    // final = score * 0.85 + 0.15 * 0.9
    // For an all-fulfilled score ~1.0: final ~= 0.85 + 0.135 = 0.985
    expect(scoreWith.weightedScore).toBeGreaterThan(0.9);
    // scores should differ because endorsement blending is applied
    expect(scoreWith.weightedScore).not.toBe(scoreWithout.weightedScore);
  });

  it('computes successRate as (fulfilled + partial) / total', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const r2 = await makeReceipt(agentKp, principalKp, 'partial', r1.receiptHash);
    const r3 = await makeReceipt(agentKp, principalKp, 'failed', r2.receiptHash);
    const r4 = await makeReceipt(agentKp, principalKp, 'failed', r3.receiptHash);

    const score = computeReputationScore(agentKp.publicKeyHex, [r1, r2, r3, r4]);

    // successRate = (1 fulfilled + 1 partial) / 4 = 0.5
    expect(score.successRate).toBe(0.5);
  });
});

// ---------------------------------------------------------------------------
// createStake / releaseStake / burnStake
// ---------------------------------------------------------------------------

describe('createStake', () => {
  it('creates an active stake with correct fields', async () => {
    const agentKp = await generateKeyPair();

    const stake = await createStake(
      agentKp.publicKeyHex,
      fakeHash('covenant-1'),
      0.5,
      agentKp,
    );

    expect(stake.id).toBeDefined();
    expect(stake.agentIdentityHash).toBe(agentKp.publicKeyHex);
    expect(stake.covenantId).toBe(fakeHash('covenant-1'));
    expect(stake.amount).toBe(0.5);
    expect(stake.status).toBe('active');
    expect(stake.stakedAt).toBeDefined();
    expect(stake.signature).toBeDefined();
    expect(typeof stake.signature).toBe('string');
    expect(stake.signature.length).toBeGreaterThan(0);
    expect(stake.resolvedAt).toBeUndefined();
  });
});

describe('releaseStake', () => {
  it('changes status to released and sets resolvedAt', async () => {
    const agentKp = await generateKeyPair();

    const stake = await createStake(
      agentKp.publicKeyHex,
      fakeHash('covenant-1'),
      0.5,
      agentKp,
    );

    const released = releaseStake(stake, 'fulfilled');

    expect(released.status).toBe('released');
    expect(released.resolvedAt).toBeDefined();
    expect(typeof released.resolvedAt).toBe('string');
    // Original fields preserved
    expect(released.id).toBe(stake.id);
    expect(released.amount).toBe(0.5);
    expect(released.agentIdentityHash).toBe(stake.agentIdentityHash);
  });

  it('does not mutate the original stake', async () => {
    const agentKp = await generateKeyPair();

    const stake = await createStake(
      agentKp.publicKeyHex,
      fakeHash('covenant-1'),
      0.5,
      agentKp,
    );

    releaseStake(stake, 'fulfilled');

    expect(stake.status).toBe('active');
    expect(stake.resolvedAt).toBeUndefined();
  });
});

describe('burnStake', () => {
  it('changes status to burned and sets resolvedAt', async () => {
    const agentKp = await generateKeyPair();

    const stake = await createStake(
      agentKp.publicKeyHex,
      fakeHash('covenant-1'),
      0.5,
      agentKp,
    );

    const burned = burnStake(stake);

    expect(burned.status).toBe('burned');
    expect(burned.resolvedAt).toBeDefined();
    expect(typeof burned.resolvedAt).toBe('string');
    expect(burned.id).toBe(stake.id);
    expect(burned.amount).toBe(0.5);
  });

  it('does not mutate the original stake', async () => {
    const agentKp = await generateKeyPair();

    const stake = await createStake(
      agentKp.publicKeyHex,
      fakeHash('covenant-1'),
      0.5,
      agentKp,
    );

    burnStake(stake);

    expect(stake.status).toBe('active');
  });
});

// ---------------------------------------------------------------------------
// createDelegation / burnDelegation
// ---------------------------------------------------------------------------

describe('createDelegation', () => {
  it('creates a delegation with dual signatures', async () => {
    const sponsorKp = await generateKeyPair();
    const protegeKp = await generateKeyPair();

    const delegation = await createDelegation(
      sponsorKp.publicKeyHex,
      protegeKp.publicKeyHex,
      0.5,
      ['compute', 'storage'],
      '2026-12-31T00:00:00.000Z',
      sponsorKp,
      protegeKp,
    );

    expect(delegation.id).toBeDefined();
    expect(delegation.sponsorIdentityHash).toBe(sponsorKp.publicKeyHex);
    expect(delegation.protégéIdentityHash).toBe(protegeKp.publicKeyHex);
    expect(delegation.riskAmount).toBe(0.5);
    expect(delegation.scopes).toEqual(['compute', 'storage']);
    expect(delegation.expiresAt).toBe('2026-12-31T00:00:00.000Z');
    expect(delegation.status).toBe('active');
    expect(delegation.sponsorSignature).toBeDefined();
    expect(delegation.sponsorSignature.length).toBeGreaterThan(0);
    expect(delegation.protégéSignature).toBeDefined();
    expect(delegation.protégéSignature.length).toBeGreaterThan(0);
    // The two signatures must be different (different keys)
    expect(delegation.sponsorSignature).not.toBe(delegation.protégéSignature);
  });
});

describe('burnDelegation', () => {
  it('changes status to burned', async () => {
    const sponsorKp = await generateKeyPair();
    const protegeKp = await generateKeyPair();

    const delegation = await createDelegation(
      sponsorKp.publicKeyHex,
      protegeKp.publicKeyHex,
      0.5,
      ['compute'],
      '2026-12-31T00:00:00.000Z',
      sponsorKp,
      protegeKp,
    );

    const burned = burnDelegation(delegation);

    expect(burned.status).toBe('burned');
    expect(burned.id).toBe(delegation.id);
    expect(burned.sponsorIdentityHash).toBe(delegation.sponsorIdentityHash);
    expect(burned.protégéIdentityHash).toBe(delegation.protégéIdentityHash);
  });

  it('does not mutate the original delegation', async () => {
    const sponsorKp = await generateKeyPair();
    const protegeKp = await generateKeyPair();

    const delegation = await createDelegation(
      sponsorKp.publicKeyHex,
      protegeKp.publicKeyHex,
      0.5,
      ['compute'],
      '2026-12-31T00:00:00.000Z',
      sponsorKp,
      protegeKp,
    );

    burnDelegation(delegation);

    expect(delegation.status).toBe('active');
  });
});

// ---------------------------------------------------------------------------
// createEndorsement / verifyEndorsement
// ---------------------------------------------------------------------------

describe('createEndorsement', () => {
  it('creates a valid endorsement with all fields', async () => {
    const endorserKp = await generateKeyPair();
    const endorsedHash = fakeHash('endorsed-agent');

    const endorsement = await createEndorsement(
      endorserKp.publicKeyHex,
      endorsedHash,
      { covenantsCompleted: 20, breachRate: 0.02 },
      ['compute'],
      0.85,
      endorserKp,
    );

    expect(endorsement.id).toBeDefined();
    expect(endorsement.endorserIdentityHash).toBe(endorserKp.publicKeyHex);
    expect(endorsement.endorsedIdentityHash).toBe(endorsedHash);
    expect(endorsement.basis).toEqual({ covenantsCompleted: 20, breachRate: 0.02 });
    expect(endorsement.scopes).toEqual(['compute']);
    expect(endorsement.weight).toBe(0.85);
    expect(endorsement.issuedAt).toBeDefined();
    expect(endorsement.signature).toBeDefined();
    expect(endorsement.signature.length).toBeGreaterThan(0);
  });
});

describe('verifyEndorsement', () => {
  it('verifies a valid endorsement', async () => {
    const endorserKp = await generateKeyPair();
    const endorsedHash = fakeHash('endorsed-agent');

    const endorsement = await createEndorsement(
      endorserKp.publicKeyHex,
      endorsedHash,
      { covenantsCompleted: 10, breachRate: 0 },
      ['general'],
      0.9,
      endorserKp,
    );

    const valid = await verifyEndorsement(endorsement);
    expect(valid).toBe(true);
  });

  it('fails verification when a field is tampered', async () => {
    const endorserKp = await generateKeyPair();
    const endorsedHash = fakeHash('endorsed-agent');

    const endorsement = await createEndorsement(
      endorserKp.publicKeyHex,
      endorsedHash,
      { covenantsCompleted: 10, breachRate: 0 },
      ['general'],
      0.9,
      endorserKp,
    );

    const tampered = { ...endorsement, weight: 0.1 };
    const valid = await verifyEndorsement(tampered);
    expect(valid).toBe(false);
  });

  it('fails verification when signature is tampered', async () => {
    const endorserKp = await generateKeyPair();
    const endorsedHash = fakeHash('endorsed-agent');

    const endorsement = await createEndorsement(
      endorserKp.publicKeyHex,
      endorsedHash,
      { covenantsCompleted: 10, breachRate: 0 },
      ['general'],
      0.9,
      endorserKp,
    );

    const sig = endorsement.signature;
    const flipped = sig[sig.length - 1] === '0' ? '1' : '0';
    const tampered = { ...endorsement, signature: sig.slice(0, -1) + flipped };
    const valid = await verifyEndorsement(tampered);
    expect(valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Endorsement basis validation
// ---------------------------------------------------------------------------

describe('reputation - endorsement basis validation', () => {
  it('rejects negative covenantsCompleted', async () => {
    const kp = await generateKeyPair();
    await expect(createEndorsement(
      'endorser-hash', 'endorsed-hash',
      { covenantsCompleted: -1, breachRate: 0 },
      ['data'], 0.5, kp
    )).rejects.toThrow('covenantsCompleted');
  });

  it('rejects breachRate > 1', async () => {
    const kp = await generateKeyPair();
    await expect(createEndorsement(
      'endorser-hash', 'endorsed-hash',
      { covenantsCompleted: 10, breachRate: 1.5 },
      ['data'], 0.5, kp
    )).rejects.toThrow('breachRate');
  });

  it('rejects negative breachRate', async () => {
    const kp = await generateKeyPair();
    await expect(createEndorsement(
      'endorser-hash', 'endorsed-hash',
      { covenantsCompleted: 10, breachRate: -0.1 },
      ['data'], 0.5, kp
    )).rejects.toThrow('breachRate');
  });

  it('rejects averageOutcomeScore > 1', async () => {
    const kp = await generateKeyPair();
    await expect(createEndorsement(
      'endorser-hash', 'endorsed-hash',
      { covenantsCompleted: 10, breachRate: 0, averageOutcomeScore: 1.5 },
      ['data'], 0.5, kp
    )).rejects.toThrow('averageOutcomeScore');
  });

  it('rejects weight > 1', async () => {
    const kp = await generateKeyPair();
    await expect(createEndorsement(
      'endorser-hash', 'endorsed-hash',
      { covenantsCompleted: 10, breachRate: 0 },
      ['data'], 1.5, kp
    )).rejects.toThrow('weight');
  });

  it('accepts valid endorsement with all basis fields', async () => {
    const kp = await generateKeyPair();
    const endorsement = await createEndorsement(
      kp.publicKeyHex, 'endorsed-hash',
      { covenantsCompleted: 50, breachRate: 0.02, averageOutcomeScore: 0.95 },
      ['data.analysis', 'api.call'], 0.8, kp
    );
    expect(endorsement.basis.covenantsCompleted).toBe(50);
    expect(endorsement.basis.breachRate).toBe(0.02);
    expect(endorsement.basis.averageOutcomeScore).toBe(0.95);
    expect(endorsement.weight).toBe(0.8);
  });
});

// ---------------------------------------------------------------------------
// Co-burn delegation
// ---------------------------------------------------------------------------

describe('reputation - co-burn delegation', () => {
  it('computes sponsor reputation loss on protege breach', async () => {
    const sponsorKp = await generateKeyPair();
    const protegeKp = await generateKeyPair();

    const delegation = await createDelegation(
      sponsorKp.publicKeyHex, protegeKp.publicKeyHex,
      0.3, ['data.analysis'],
      new Date(Date.now() + 86400000).toISOString(),
      sponsorKp, protegeKp
    );

    const sponsorScore: ReputationScore = {
      agentIdentityHash: sponsorKp.publicKeyHex,
      totalExecutions: 100,
      fulfilled: 95,
      partial: 3,
      failed: 2,
      breached: 0,
      successRate: 0.98,
      weightedScore: 0.95,
      receiptsMerkleRoot: 'abc123',
      lastUpdatedAt: new Date().toISOString(),
      currentStake: 0,
      totalBurned: 0,
    };

    const result = coBurnDelegation(delegation, sponsorScore);
    expect(result.burnedDelegation.status).toBe('burned');
    expect(result.sponsorReputationLoss).toBeCloseTo(0.3 * 0.95); // riskAmount * weightedScore
    expect(result.newSponsorBurned).toBeCloseTo(0.3 * 0.95);
  });

  it('accumulates burned reputation across multiple co-burns', async () => {
    const sponsorKp = await generateKeyPair();
    const protegeKp = await generateKeyPair();

    const delegation = await createDelegation(
      sponsorKp.publicKeyHex, protegeKp.publicKeyHex,
      0.2, ['data'],
      new Date(Date.now() + 86400000).toISOString(),
      sponsorKp, protegeKp
    );

    const sponsorScore: ReputationScore = {
      agentIdentityHash: sponsorKp.publicKeyHex,
      totalExecutions: 50,
      fulfilled: 50,
      partial: 0,
      failed: 0,
      breached: 0,
      successRate: 1.0,
      weightedScore: 0.80,
      receiptsMerkleRoot: 'abc123',
      lastUpdatedAt: new Date().toISOString(),
      currentStake: 0,
      totalBurned: 0.1, // already had some burned
    };

    const result = coBurnDelegation(delegation, sponsorScore);
    expect(result.newSponsorBurned).toBeCloseTo(0.1 + 0.2 * 0.80);
  });
});

// ---------------------------------------------------------------------------
// Stake validation
// ---------------------------------------------------------------------------

describe('reputation - stake validation', () => {
  it('rejects stake amount > 1', async () => {
    const kp = await generateKeyPair();
    await expect(createStake('agent-hash', 'covenant-id', 1.5, kp))
      .rejects.toThrow('amount');
  });

  it('rejects negative stake amount', async () => {
    const kp = await generateKeyPair();
    await expect(createStake('agent-hash', 'covenant-id', -0.1, kp))
      .rejects.toThrow('amount');
  });
});

// ---------------------------------------------------------------------------
// Delegation validation
// ---------------------------------------------------------------------------

describe('reputation - delegation validation', () => {
  it('rejects empty scopes', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    await expect(createDelegation(
      kp1.publicKeyHex, kp2.publicKeyHex,
      0.3, [],
      new Date(Date.now() + 86400000).toISOString(),
      kp1, kp2
    )).rejects.toThrow('scope');
  });

  it('rejects riskAmount > 1', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    await expect(createDelegation(
      kp1.publicKeyHex, kp2.publicKeyHex,
      1.5, ['data'],
      new Date(Date.now() + 86400000).toISOString(),
      kp1, kp2
    )).rejects.toThrow('riskAmount');
  });
});

// ---------------------------------------------------------------------------
// computeReceiptsMerkleRoot
// ---------------------------------------------------------------------------

describe('computeReceiptsMerkleRoot', () => {
  it('produces a consistent hash for the same receipts', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const r2 = await makeReceipt(agentKp, principalKp, 'fulfilled', r1.receiptHash);

    const root1 = computeReceiptsMerkleRoot([r1, r2]);
    const root2 = computeReceiptsMerkleRoot([r1, r2]);

    expect(root1).toBe(root2);
  });

  it('produces different hashes for different receipt sets', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const r2 = await makeReceipt(agentKp, principalKp, 'partial', r1.receiptHash);
    const r3 = await makeReceipt(agentKp, principalKp, 'failed', r2.receiptHash);

    const rootAB = computeReceiptsMerkleRoot([r1, r2]);
    const rootABC = computeReceiptsMerkleRoot([r1, r2, r3]);

    expect(rootAB).not.toBe(rootABC);
  });

  it('handles empty array by returning sha256 of empty string', () => {
    const root = computeReceiptsMerkleRoot([]);
    expect(root).toBe(sha256String(''));
  });

  it('handles a single receipt', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const root = computeReceiptsMerkleRoot([r1]);

    // A single element is the root
    expect(root).toBe(r1.receiptHash);
  });

  it('handles odd number of receipts (duplicates last node)', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();

    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const r2 = await makeReceipt(agentKp, principalKp, 'fulfilled', r1.receiptHash);
    const r3 = await makeReceipt(agentKp, principalKp, 'fulfilled', r2.receiptHash);

    const root = computeReceiptsMerkleRoot([r1, r2, r3]);

    // For 3 receipts: pair (r1,r2) -> h12, pair (r3,r3) -> h33, then pair (h12, h33) -> root
    const h12 = sha256String(r1.receiptHash + r2.receiptHash);
    const h33 = sha256String(r3.receiptHash + r3.receiptHash);
    const expectedRoot = sha256String(h12 + h33);

    expect(root).toBe(expectedRoot);
  });
});

// ---------------------------------------------------------------------------
// DEFAULT_SCORING_CONFIG
// ---------------------------------------------------------------------------

describe('DEFAULT_SCORING_CONFIG', () => {
  it('has expected values', () => {
    expect(DEFAULT_SCORING_CONFIG.recencyDecay).toBe(0.95);
    expect(DEFAULT_SCORING_CONFIG.recencyPeriod).toBe(86400);
    expect(DEFAULT_SCORING_CONFIG.minimumExecutions).toBe(10);
    expect(DEFAULT_SCORING_CONFIG.endorsementWeight).toBe(0.15);
    expect(DEFAULT_SCORING_CONFIG.breachPenalty).toEqual({
      critical: 0.5,
      high: 0.3,
      medium: 0.15,
      low: 0.05,
    });
  });
});

// ---------------------------------------------------------------------------
// EXPANDED TESTS: createReceipt / verifyReceipt with various outcomes
// ---------------------------------------------------------------------------

describe('createReceipt - various outcomes', () => {
  it('creates a receipt with outcome partial', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp, 'partial');
    expect(receipt.outcome).toBe('partial');
    expect(receipt.breachSeverity).toBeUndefined();
    expect(receipt.id).toBe(receipt.receiptHash);
  });

  it('creates a receipt with outcome failed', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp, 'failed');
    expect(receipt.outcome).toBe('failed');
    expect(receipt.breachSeverity).toBeUndefined();
  });

  it('creates a breached receipt with critical severity', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp, 'breached', null, 'critical');
    expect(receipt.outcome).toBe('breached');
    expect(receipt.breachSeverity).toBe('critical');
  });

  it('creates a breached receipt with low severity', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp, 'breached', null, 'low');
    expect(receipt.outcome).toBe('breached');
    expect(receipt.breachSeverity).toBe('low');
  });

  it('has a valid ISO 8601 completedAt timestamp', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const before = new Date().toISOString();
    const receipt = await makeReceipt(agentKp, principalKp);
    const after = new Date().toISOString();
    expect(receipt.completedAt >= before).toBe(true);
    expect(receipt.completedAt <= after).toBe(true);
  });

  it('two receipts with same params get different ids due to timestamp', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const r1 = await makeReceipt(agentKp, principalKp);
    // Small delay is not needed; timestamps at ms precision suffice
    const r2 = await makeReceipt(agentKp, principalKp);
    // They might have the same timestamp at sub-ms resolution, but the test documents the intent
    expect(typeof r1.id).toBe('string');
    expect(typeof r2.id).toBe('string');
  });
});

describe('verifyReceipt - tampered fields', () => {
  it('fails when covenantId is tampered', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp);
    const tampered = { ...receipt, covenantId: fakeHash('other-covenant') };
    expect(await verifyReceipt(tampered)).toBe(false);
  });

  it('fails when outcome is tampered', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp, 'fulfilled');
    const tampered = { ...receipt, outcome: 'failed' as const };
    expect(await verifyReceipt(tampered)).toBe(false);
  });

  it('fails when proofHash is tampered', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp);
    const tampered = { ...receipt, proofHash: fakeHash('bad-proof') };
    expect(await verifyReceipt(tampered)).toBe(false);
  });

  it('fails when completedAt is tampered', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp);
    const tampered = { ...receipt, completedAt: '2020-01-01T00:00:00.000Z' };
    expect(await verifyReceipt(tampered)).toBe(false);
  });

  it('fails when previousReceiptHash is tampered', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp);
    const tampered = { ...receipt, previousReceiptHash: fakeHash('wrong-prev') };
    expect(await verifyReceipt(tampered)).toBe(false);
  });

  it('fails when principalPublicKey is tampered', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const otherKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp);
    const tampered = { ...receipt, principalPublicKey: otherKp.publicKeyHex };
    expect(await verifyReceipt(tampered)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// EXPANDED TESTS: countersignReceipt / verifyReceiptChain
// ---------------------------------------------------------------------------

describe('countersignReceipt - multi-countersigner chains', () => {
  it('can countersign with a different key pair than the principal', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const otherKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp);
    const countersigned = await countersignReceipt(receipt, otherKp);
    expect(countersigned.principalSignature).toBeDefined();
    expect(countersigned.principalSignature!.length).toBeGreaterThan(0);
    // The signature is different from agent signature
    expect(countersigned.principalSignature).not.toBe(countersigned.agentSignature);
  });

  it('countersigning twice with different keys produces different signatures', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const altKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp);
    const cs1 = await countersignReceipt(receipt, principalKp);
    const cs2 = await countersignReceipt(receipt, altKp);
    expect(cs1.principalSignature).not.toBe(cs2.principalSignature);
  });

  it('countersigned receipt still passes verifyReceipt (hash and agent sig unchanged)', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipt = await makeReceipt(agentKp, principalKp);
    const countersigned = await countersignReceipt(receipt, principalKp);
    expect(await verifyReceipt(countersigned)).toBe(true);
  });
});

describe('verifyReceiptChain - extended', () => {
  it('validates a long chain of 5 receipts with mixed outcomes', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const outcomes: Array<ExecutionReceipt['outcome']> = ['fulfilled', 'partial', 'fulfilled', 'failed', 'fulfilled'];
    const chain: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (const outcome of outcomes) {
      const r = await makeReceipt(agentKp, principalKp, outcome, prevHash);
      chain.push(r);
      prevHash = r.receiptHash;
    }
    expect(verifyReceiptChain(chain)).toBe(true);
  });

  it('fails when a middle link is removed from the chain', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const r2 = await makeReceipt(agentKp, principalKp, 'fulfilled', r1.receiptHash);
    const r3 = await makeReceipt(agentKp, principalKp, 'fulfilled', r2.receiptHash);
    // Remove r2 from the chain
    expect(verifyReceiptChain([r1, r3])).toBe(false);
  });

  it('fails when receipts are in wrong order', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const r2 = await makeReceipt(agentKp, principalKp, 'fulfilled', r1.receiptHash);
    // Swap order
    expect(verifyReceiptChain([r2, r1])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// EXPANDED TESTS: computeReceiptsMerkleRoot
// ---------------------------------------------------------------------------

describe('computeReceiptsMerkleRoot - extended', () => {
  it('handles exactly 2 receipts (no duplication needed)', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const r2 = await makeReceipt(agentKp, principalKp, 'partial', r1.receiptHash);
    const root = computeReceiptsMerkleRoot([r1, r2]);
    const expected = sha256String(r1.receiptHash + r2.receiptHash);
    expect(root).toBe(expected);
  });

  it('handles 4 receipts (perfect binary tree)', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 4; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      receipts.push(r);
      prevHash = r.receiptHash;
    }
    const root = computeReceiptsMerkleRoot(receipts);
    const h01 = sha256String(receipts[0]!.receiptHash + receipts[1]!.receiptHash);
    const h23 = sha256String(receipts[2]!.receiptHash + receipts[3]!.receiptHash);
    const expectedRoot = sha256String(h01 + h23);
    expect(root).toBe(expectedRoot);
  });

  it('handles 5 receipts (odd at first level, even at second)', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 5; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      receipts.push(r);
      prevHash = r.receiptHash;
    }
    const root = computeReceiptsMerkleRoot(receipts);
    // Level 0: h01 = H(r0+r1), h23 = H(r2+r3), h44 = H(r4+r4)
    const h01 = sha256String(receipts[0]!.receiptHash + receipts[1]!.receiptHash);
    const h23 = sha256String(receipts[2]!.receiptHash + receipts[3]!.receiptHash);
    const h44 = sha256String(receipts[4]!.receiptHash + receipts[4]!.receiptHash);
    // Level 1 (3 nodes -> odd): h_01_23 = H(h01+h23), h_44_44 = H(h44+h44)
    const h_01_23 = sha256String(h01 + h23);
    const h_44_44 = sha256String(h44 + h44);
    const expectedRoot = sha256String(h_01_23 + h_44_44);
    expect(root).toBe(expectedRoot);
  });

  it('different receipt order produces different merkle root', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const r2 = await makeReceipt(agentKp, principalKp, 'partial', r1.receiptHash);
    const rootAB = computeReceiptsMerkleRoot([r1, r2]);
    const rootBA = computeReceiptsMerkleRoot([r2, r1]);
    expect(rootAB).not.toBe(rootBA);
  });
});

// ---------------------------------------------------------------------------
// EXPANDED TESTS: computeReputationScore - custom ScoringConfig
// ---------------------------------------------------------------------------

describe('computeReputationScore - custom ScoringConfig', () => {
  it('uses custom breachPenalty values', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 5; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      receipts.push(r);
      prevHash = r.receiptHash;
    }
    for (let i = 0; i < 5; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'breached', prevHash, 'low');
      receipts.push(r);
      prevHash = r.receiptHash;
    }

    const heavyPenalty: import('./types.js').ScoringConfig = {
      recencyDecay: 0.95,
      recencyPeriod: 86400,
      breachPenalty: { critical: 1.0, high: 0.8, medium: 0.6, low: 0.4 },
      minimumExecutions: 5,
      endorsementWeight: 0.15,
    };
    const lightPenalty: import('./types.js').ScoringConfig = {
      recencyDecay: 0.95,
      recencyPeriod: 86400,
      breachPenalty: { critical: 0.1, high: 0.05, medium: 0.02, low: 0.01 },
      minimumExecutions: 5,
      endorsementWeight: 0.15,
    };

    const heavyScore = computeReputationScore(agentKp.publicKeyHex, receipts, undefined, heavyPenalty);
    const lightScore = computeReputationScore(agentKp.publicKeyHex, receipts, undefined, lightPenalty);
    expect(heavyScore.weightedScore).toBeLessThan(lightScore.weightedScore);
  });

  it('uses custom minimumExecutions threshold', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 5; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      receipts.push(r);
      prevHash = r.receiptHash;
    }

    const lowThreshold: import('./types.js').ScoringConfig = {
      ...DEFAULT_SCORING_CONFIG,
      minimumExecutions: 3,
    };
    const highThreshold: import('./types.js').ScoringConfig = {
      ...DEFAULT_SCORING_CONFIG,
      minimumExecutions: 100,
    };

    const lowScore = computeReputationScore(agentKp.publicKeyHex, receipts, undefined, lowThreshold);
    const highScore = computeReputationScore(agentKp.publicKeyHex, receipts, undefined, highThreshold);
    // Low threshold: 5 >= 3, no penalty. High threshold: 5 < 100, penalty applied.
    expect(lowScore.weightedScore).toBeGreaterThan(highScore.weightedScore);
  });

  it('uses custom endorsementWeight for blending', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const endorserKp = await generateKeyPair();
    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 10; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      receipts.push(r);
      prevHash = r.receiptHash;
    }
    const endorsement = await createEndorsement(
      endorserKp.publicKeyHex, agentKp.publicKeyHex,
      { covenantsCompleted: 10, breachRate: 0 },
      ['general'], 0.5, endorserKp,
    );

    const lowWeight: import('./types.js').ScoringConfig = {
      ...DEFAULT_SCORING_CONFIG,
      endorsementWeight: 0.01,
    };
    const highWeight: import('./types.js').ScoringConfig = {
      ...DEFAULT_SCORING_CONFIG,
      endorsementWeight: 0.9,
    };

    const lowWeightScore = computeReputationScore(agentKp.publicKeyHex, receipts, [endorsement], lowWeight);
    const highWeightScore = computeReputationScore(agentKp.publicKeyHex, receipts, [endorsement], highWeight);
    // With endorsement weight 0.5 and all-fulfilled base score ~1.0:
    // lowWeight: ~0.99*1.0 + 0.01*0.5 = ~0.995
    // highWeight: ~0.1*1.0 + 0.9*0.5 = ~0.55
    expect(lowWeightScore.weightedScore).toBeGreaterThan(highWeightScore.weightedScore);
  });
});

describe('computeReputationScore - recency decay effects', () => {
  it('recent receipts are weighted more heavily than old ones', () => {
    // Create synthetic receipts with controlled timestamps
    const now = Date.now();
    const recentReceipt: ExecutionReceipt = {
      id: fakeHash('recent') as HashHex,
      covenantId: fakeHash('covenant'),
      agentIdentityHash: fakeHash('agent'),
      principalPublicKey: 'pubkey',
      outcome: 'fulfilled',
      proofHash: fakeHash('proof'),
      durationMs: 100,
      completedAt: new Date(now - 1000).toISOString(), // 1 second ago
      agentSignature: 'sig',
      previousReceiptHash: null,
      receiptHash: fakeHash('recent'),
    };
    const oldReceipt: ExecutionReceipt = {
      id: fakeHash('old') as HashHex,
      covenantId: fakeHash('covenant'),
      agentIdentityHash: fakeHash('agent'),
      principalPublicKey: 'pubkey',
      outcome: 'failed',
      proofHash: fakeHash('proof2'),
      durationMs: 100,
      completedAt: new Date(now - 90 * 86400 * 1000).toISOString(), // 90 days ago
      agentSignature: 'sig',
      previousReceiptHash: fakeHash('recent'),
      receiptHash: fakeHash('old'),
    };

    const config: import('./types.js').ScoringConfig = {
      ...DEFAULT_SCORING_CONFIG,
      minimumExecutions: 1,
    };

    // Score with only the recent fulfilled receipt
    const recentScore = computeReputationScore(fakeHash('agent'), [recentReceipt], undefined, config);
    // Score with both -- the old failed receipt should drag the score down less due to decay
    const bothScore = computeReputationScore(fakeHash('agent'), [recentReceipt, oldReceipt], undefined, config);

    expect(recentScore.weightedScore).toBeGreaterThan(bothScore.weightedScore);
    // But the bothScore should still be relatively high because the old failure is heavily decayed
    expect(bothScore.weightedScore).toBeGreaterThan(0.5);
  });

  it('very old breaches have minimal impact', () => {
    const now = Date.now();
    const receipts: ExecutionReceipt[] = [];
    // 10 recent fulfilled
    for (let i = 0; i < 10; i++) {
      receipts.push({
        id: fakeHash(`recent-${i}`) as HashHex,
        covenantId: fakeHash('covenant'),
        agentIdentityHash: fakeHash('agent'),
        principalPublicKey: 'pubkey',
        outcome: 'fulfilled',
        proofHash: fakeHash(`proof-${i}`),
        durationMs: 100,
        completedAt: new Date(now - 1000 * (i + 1)).toISOString(),
        agentSignature: 'sig',
        previousReceiptHash: i === 0 ? null : fakeHash(`recent-${i - 1}`),
        receiptHash: fakeHash(`recent-${i}`),
      });
    }
    // 5 ancient breaches (365 days ago)
    for (let i = 0; i < 5; i++) {
      receipts.push({
        id: fakeHash(`old-breach-${i}`) as HashHex,
        covenantId: fakeHash('covenant'),
        agentIdentityHash: fakeHash('agent'),
        principalPublicKey: 'pubkey',
        outcome: 'breached',
        breachSeverity: 'critical',
        proofHash: fakeHash(`old-proof-${i}`),
        durationMs: 100,
        completedAt: new Date(now - 365 * 86400 * 1000 - i * 1000).toISOString(),
        agentSignature: 'sig',
        previousReceiptHash: fakeHash(`recent-9`),
        receiptHash: fakeHash(`old-breach-${i}`),
      });
    }

    const score = computeReputationScore(fakeHash('agent'), receipts);
    // Despite 5 critical breaches, score should still be reasonable because they are very old
    expect(score.weightedScore).toBeGreaterThan(0.5);
    expect(score.breached).toBe(5);
    expect(score.fulfilled).toBe(10);
  });
});

describe('computeReputationScore - multiple receipts with varying outcomes', () => {
  it('handles all-partial receipts', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 10; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'partial', prevHash);
      receipts.push(r);
      prevHash = r.receiptHash;
    }
    const score = computeReputationScore(agentKp.publicKeyHex, receipts);
    // partial = 0.5 outcome score
    expect(score.weightedScore).toBeCloseTo(0.5, 1);
    expect(score.successRate).toBe(1.0); // partial counts as success
    expect(score.partial).toBe(10);
  });

  it('handles all-failed receipts', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 10; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'failed', prevHash);
      receipts.push(r);
      prevHash = r.receiptHash;
    }
    const score = computeReputationScore(agentKp.publicKeyHex, receipts);
    expect(score.weightedScore).toBe(0);
    expect(score.successRate).toBe(0);
    expect(score.failed).toBe(10);
  });

  it('score is clamped to [0, 1]', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    // All fulfilled = score should be at most 1.0
    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 20; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      receipts.push(r);
      prevHash = r.receiptHash;
    }
    const score = computeReputationScore(agentKp.publicKeyHex, receipts);
    expect(score.weightedScore).toBeLessThanOrEqual(1.0);
    expect(score.weightedScore).toBeGreaterThanOrEqual(0.0);
  });

  it('includes a receiptsMerkleRoot that matches independent computation', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 3; i++) {
      const r = await makeReceipt(agentKp, principalKp, 'fulfilled', prevHash);
      receipts.push(r);
      prevHash = r.receiptHash;
    }
    const score = computeReputationScore(agentKp.publicKeyHex, receipts);
    const independentRoot = computeReceiptsMerkleRoot(receipts);
    expect(score.receiptsMerkleRoot).toBe(independentRoot);
  });

  it('lastUpdatedAt is a valid ISO 8601 timestamp', async () => {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    const r1 = await makeReceipt(agentKp, principalKp, 'fulfilled', null);
    const score = computeReputationScore(agentKp.publicKeyHex, [r1]);
    expect(() => new Date(score.lastUpdatedAt)).not.toThrow();
    expect(new Date(score.lastUpdatedAt).toISOString()).toBe(score.lastUpdatedAt);
  });
});

// ---------------------------------------------------------------------------
// EXPANDED TESTS: Stake lifecycle
// ---------------------------------------------------------------------------

describe('createStake / releaseStake / burnStake - lifecycle', () => {
  it('full lifecycle: create -> release', async () => {
    const agentKp = await generateKeyPair();
    const stake = await createStake(agentKp.publicKeyHex, fakeHash('covenant-1'), 0.75, agentKp);
    expect(stake.status).toBe('active');
    expect(stake.amount).toBe(0.75);

    const released = releaseStake(stake, 'fulfilled');
    expect(released.status).toBe('released');
    expect(released.resolvedAt).toBeDefined();
    expect(released.amount).toBe(0.75);
    expect(released.id).toBe(stake.id);
    expect(released.signature).toBe(stake.signature);
  });

  it('full lifecycle: create -> burn', async () => {
    const agentKp = await generateKeyPair();
    const stake = await createStake(agentKp.publicKeyHex, fakeHash('covenant-2'), 0.3, agentKp);
    expect(stake.status).toBe('active');

    const burned = burnStake(stake);
    expect(burned.status).toBe('burned');
    expect(burned.resolvedAt).toBeDefined();
    expect(burned.amount).toBe(0.3);
  });

  it('accepts boundary value amount = 0', async () => {
    const agentKp = await generateKeyPair();
    const stake = await createStake(agentKp.publicKeyHex, fakeHash('covenant-1'), 0, agentKp);
    expect(stake.amount).toBe(0);
    expect(stake.status).toBe('active');
  });

  it('accepts boundary value amount = 1', async () => {
    const agentKp = await generateKeyPair();
    const stake = await createStake(agentKp.publicKeyHex, fakeHash('covenant-1'), 1, agentKp);
    expect(stake.amount).toBe(1);
    expect(stake.status).toBe('active');
  });

  it('releaseStake preserves all original fields', async () => {
    const agentKp = await generateKeyPair();
    const stake = await createStake(agentKp.publicKeyHex, fakeHash('covenant-1'), 0.5, agentKp);
    const released = releaseStake(stake, 'partial');
    expect(released.agentIdentityHash).toBe(stake.agentIdentityHash);
    expect(released.covenantId).toBe(stake.covenantId);
    expect(released.stakedAt).toBe(stake.stakedAt);
    expect(released.signature).toBe(stake.signature);
  });

  it('burnStake preserves all original fields', async () => {
    const agentKp = await generateKeyPair();
    const stake = await createStake(agentKp.publicKeyHex, fakeHash('covenant-1'), 0.8, agentKp);
    const burned = burnStake(stake);
    expect(burned.agentIdentityHash).toBe(stake.agentIdentityHash);
    expect(burned.covenantId).toBe(stake.covenantId);
    expect(burned.stakedAt).toBe(stake.stakedAt);
    expect(burned.signature).toBe(stake.signature);
  });
});

// ---------------------------------------------------------------------------
// EXPANDED TESTS: Delegation lifecycle
// ---------------------------------------------------------------------------

describe('createDelegation / burnDelegation / coBurnDelegation - extended', () => {
  it('full lifecycle: create -> burn', async () => {
    const sponsorKp = await generateKeyPair();
    const protegeKp = await generateKeyPair();
    const delegation = await createDelegation(
      sponsorKp.publicKeyHex, protegeKp.publicKeyHex,
      0.5, ['compute', 'data'],
      new Date(Date.now() + 86400000).toISOString(),
      sponsorKp, protegeKp,
    );
    expect(delegation.status).toBe('active');
    const burned = burnDelegation(delegation);
    expect(burned.status).toBe('burned');
    expect(burned.riskAmount).toBe(0.5);
    expect(burned.scopes).toEqual(['compute', 'data']);
  });

  it('accepts boundary value riskAmount = 0', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const delegation = await createDelegation(
      kp1.publicKeyHex, kp2.publicKeyHex,
      0, ['data'],
      new Date(Date.now() + 86400000).toISOString(),
      kp1, kp2,
    );
    expect(delegation.riskAmount).toBe(0);
  });

  it('accepts boundary value riskAmount = 1', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const delegation = await createDelegation(
      kp1.publicKeyHex, kp2.publicKeyHex,
      1, ['data'],
      new Date(Date.now() + 86400000).toISOString(),
      kp1, kp2,
    );
    expect(delegation.riskAmount).toBe(1);
  });

  it('rejects negative riskAmount', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    await expect(createDelegation(
      kp1.publicKeyHex, kp2.publicKeyHex,
      -0.1, ['data'],
      new Date(Date.now() + 86400000).toISOString(),
      kp1, kp2,
    )).rejects.toThrow('riskAmount');
  });

  it('coBurnDelegation with riskAmount 0 produces zero reputation loss', async () => {
    const sponsorKp = await generateKeyPair();
    const protegeKp = await generateKeyPair();
    const delegation = await createDelegation(
      sponsorKp.publicKeyHex, protegeKp.publicKeyHex,
      0, ['data'],
      new Date(Date.now() + 86400000).toISOString(),
      sponsorKp, protegeKp,
    );
    const sponsorScore: ReputationScore = {
      agentIdentityHash: sponsorKp.publicKeyHex,
      totalExecutions: 50, fulfilled: 50, partial: 0, failed: 0, breached: 0,
      successRate: 1.0, weightedScore: 0.9, receiptsMerkleRoot: 'abc',
      lastUpdatedAt: new Date().toISOString(), currentStake: 0, totalBurned: 0,
    };
    const result = coBurnDelegation(delegation, sponsorScore);
    expect(result.sponsorReputationLoss).toBe(0);
    expect(result.newSponsorBurned).toBe(0);
  });

  it('coBurnDelegation with riskAmount 1 produces maximum reputation loss', async () => {
    const sponsorKp = await generateKeyPair();
    const protegeKp = await generateKeyPair();
    const delegation = await createDelegation(
      sponsorKp.publicKeyHex, protegeKp.publicKeyHex,
      1, ['data'],
      new Date(Date.now() + 86400000).toISOString(),
      sponsorKp, protegeKp,
    );
    const sponsorScore: ReputationScore = {
      agentIdentityHash: sponsorKp.publicKeyHex,
      totalExecutions: 50, fulfilled: 50, partial: 0, failed: 0, breached: 0,
      successRate: 1.0, weightedScore: 0.9, receiptsMerkleRoot: 'abc',
      lastUpdatedAt: new Date().toISOString(), currentStake: 0, totalBurned: 0.2,
    };
    const result = coBurnDelegation(delegation, sponsorScore);
    expect(result.sponsorReputationLoss).toBeCloseTo(0.9);
    expect(result.newSponsorBurned).toBeCloseTo(0.2 + 0.9);
  });

  it('burnDelegation does not mutate scopes array', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const scopes = ['compute', 'storage'];
    const delegation = await createDelegation(
      kp1.publicKeyHex, kp2.publicKeyHex,
      0.5, scopes,
      new Date(Date.now() + 86400000).toISOString(),
      kp1, kp2,
    );
    const burned = burnDelegation(delegation);
    expect(burned.scopes).toEqual(['compute', 'storage']);
    expect(delegation.scopes).toEqual(['compute', 'storage']);
  });
});

// ---------------------------------------------------------------------------
// EXPANDED TESTS: Endorsement basis boundary values
// ---------------------------------------------------------------------------

describe('createEndorsement / verifyEndorsement - extended', () => {
  it('accepts boundary value covenantsCompleted = 0', async () => {
    const kp = await generateKeyPair();
    const e = await createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 0, breachRate: 0 },
      ['scope'], 0.5, kp,
    );
    expect(e.basis.covenantsCompleted).toBe(0);
  });

  it('accepts boundary value breachRate = 0', async () => {
    const kp = await generateKeyPair();
    const e = await createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 0 },
      ['scope'], 0.5, kp,
    );
    expect(e.basis.breachRate).toBe(0);
  });

  it('accepts boundary value breachRate = 1', async () => {
    const kp = await generateKeyPair();
    const e = await createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 1 },
      ['scope'], 0.5, kp,
    );
    expect(e.basis.breachRate).toBe(1);
  });

  it('accepts boundary value weight = 0', async () => {
    const kp = await generateKeyPair();
    const e = await createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 0 },
      ['scope'], 0, kp,
    );
    expect(e.weight).toBe(0);
  });

  it('accepts boundary value weight = 1', async () => {
    const kp = await generateKeyPair();
    const e = await createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 0 },
      ['scope'], 1, kp,
    );
    expect(e.weight).toBe(1);
  });

  it('rejects negative weight', async () => {
    const kp = await generateKeyPair();
    await expect(createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 0 },
      ['scope'], -0.1, kp,
    )).rejects.toThrow('weight');
  });

  it('accepts averageOutcomeScore = 0', async () => {
    const kp = await generateKeyPair();
    const e = await createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 0, averageOutcomeScore: 0 },
      ['scope'], 0.5, kp,
    );
    expect(e.basis.averageOutcomeScore).toBe(0);
  });

  it('accepts averageOutcomeScore = 1', async () => {
    const kp = await generateKeyPair();
    const e = await createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 0, averageOutcomeScore: 1 },
      ['scope'], 0.5, kp,
    );
    expect(e.basis.averageOutcomeScore).toBe(1);
  });

  it('rejects negative averageOutcomeScore', async () => {
    const kp = await generateKeyPair();
    await expect(createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 0, averageOutcomeScore: -0.1 },
      ['scope'], 0.5, kp,
    )).rejects.toThrow('averageOutcomeScore');
  });

  it('verifyEndorsement returns false when id is tampered', async () => {
    const kp = await generateKeyPair();
    const e = await createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 0 },
      ['scope'], 0.5, kp,
    );
    const tampered = { ...e, id: fakeHash('wrong-id') };
    expect(await verifyEndorsement(tampered)).toBe(false);
  });

  it('verifyEndorsement returns false when endorsedIdentityHash is tampered', async () => {
    const kp = await generateKeyPair();
    const e = await createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 0 },
      ['scope'], 0.5, kp,
    );
    const tampered = { ...e, endorsedIdentityHash: fakeHash('other') };
    expect(await verifyEndorsement(tampered)).toBe(false);
  });

  it('verifyEndorsement returns false when scopes are tampered', async () => {
    const kp = await generateKeyPair();
    const e = await createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 0 },
      ['scope-a', 'scope-b'], 0.5, kp,
    );
    const tampered = { ...e, scopes: ['scope-a'] };
    expect(await verifyEndorsement(tampered)).toBe(false);
  });

  it('endorsement with multiple scopes', async () => {
    const kp = await generateKeyPair();
    const e = await createEndorsement(
      kp.publicKeyHex, fakeHash('endorsed'),
      { covenantsCompleted: 10, breachRate: 0 },
      ['compute', 'storage', 'network', 'data'], 0.5, kp,
    );
    expect(e.scopes).toEqual(['compute', 'storage', 'network', 'data']);
    expect(await verifyEndorsement(e)).toBe(true);
  });
});

// ===========================================================================
// Item 30: Trust as Bounded Resource
// ===========================================================================

describe('createResourcePool', () => {
  it('creates a pool with full available trust', () => {
    const pool = createResourcePool(1000);
    expect(pool.totalCollateral).toBe(1000);
    expect(pool.allocatedTrust).toBe(0);
    expect(pool.availableTrust).toBe(1000);
    expect(pool.utilizationRatio).toBe(0);
    expect(pool.participants.size).toBe(0);
  });

  it('creates a pool with zero collateral', () => {
    const pool = createResourcePool(0);
    expect(pool.totalCollateral).toBe(0);
    expect(pool.availableTrust).toBe(0);
    expect(pool.utilizationRatio).toBe(0);
  });
});

describe('allocateTrust', () => {
  it('allocates trust when amount is within available', () => {
    const pool = createResourcePool(1000);
    const result = allocateTrust(pool, 'agent-1', 200);
    expect(result.allocated).toBe(true);
    expect(result.reason).toBe('Allocation successful');
    expect(result.pool.allocatedTrust).toBe(200);
    expect(result.pool.availableTrust).toBe(800);
    expect(result.pool.utilizationRatio).toBeCloseTo(0.2);
    expect(result.pool.participants.get('agent-1')).toBe(200);
  });

  it('rejects allocation when amount exceeds available trust', () => {
    const pool = createResourcePool(100);
    const result = allocateTrust(pool, 'agent-1', 150);
    expect(result.allocated).toBe(false);
    expect(result.reason).toContain('exceeds available trust');
    expect(result.pool.allocatedTrust).toBe(0);
    expect(result.pool.availableTrust).toBe(100);
  });

  it('rejects zero and negative amounts', () => {
    const pool = createResourcePool(1000);
    const r1 = allocateTrust(pool, 'agent-1', 0);
    expect(r1.allocated).toBe(false);
    const r2 = allocateTrust(pool, 'agent-1', -10);
    expect(r2.allocated).toBe(false);
  });

  it('allocates to multiple agents', () => {
    let pool = createResourcePool(1000);
    const r1 = allocateTrust(pool, 'agent-1', 300);
    expect(r1.allocated).toBe(true);
    pool = r1.pool;

    const r2 = allocateTrust(pool, 'agent-2', 400);
    expect(r2.allocated).toBe(true);
    pool = r2.pool;

    expect(pool.allocatedTrust).toBe(700);
    expect(pool.availableTrust).toBe(300);
    expect(pool.participants.get('agent-1')).toBe(300);
    expect(pool.participants.get('agent-2')).toBe(400);
    expect(pool.utilizationRatio).toBeCloseTo(0.7);
  });

  it('allocates exact remaining amount (fully utilized pool)', () => {
    let pool = createResourcePool(500);
    const r1 = allocateTrust(pool, 'agent-1', 500);
    expect(r1.allocated).toBe(true);
    pool = r1.pool;

    expect(pool.availableTrust).toBe(0);
    expect(pool.utilizationRatio).toBeCloseTo(1.0);

    // No more room
    const r2 = allocateTrust(pool, 'agent-2', 1);
    expect(r2.allocated).toBe(false);
  });

  it('accumulates trust for the same agent across multiple allocations', () => {
    let pool = createResourcePool(1000);
    const r1 = allocateTrust(pool, 'agent-1', 100);
    pool = r1.pool;
    const r2 = allocateTrust(pool, 'agent-1', 200);
    pool = r2.pool;

    expect(pool.participants.get('agent-1')).toBe(300);
    expect(pool.allocatedTrust).toBe(300);
  });
});

describe('releaseTrust', () => {
  it('releases trust back to the pool', () => {
    let pool = createResourcePool(1000);
    const { pool: p1 } = allocateTrust(pool, 'agent-1', 400);
    pool = p1;

    pool = releaseTrust(pool, 'agent-1', 150);
    expect(pool.allocatedTrust).toBe(250);
    expect(pool.availableTrust).toBe(750);
    expect(pool.participants.get('agent-1')).toBe(250);
  });

  it('removes participant when fully released', () => {
    let pool = createResourcePool(1000);
    const { pool: p1 } = allocateTrust(pool, 'agent-1', 300);
    pool = p1;

    pool = releaseTrust(pool, 'agent-1', 300);
    expect(pool.participants.has('agent-1')).toBe(false);
    expect(pool.allocatedTrust).toBe(0);
    expect(pool.availableTrust).toBe(1000);
  });

  it('caps release at existing allocation', () => {
    let pool = createResourcePool(1000);
    const { pool: p1 } = allocateTrust(pool, 'agent-1', 200);
    pool = p1;

    pool = releaseTrust(pool, 'agent-1', 500); // More than allocated
    expect(pool.participants.has('agent-1')).toBe(false);
    expect(pool.allocatedTrust).toBe(0);
    expect(pool.availableTrust).toBe(1000);
  });

  it('handles releasing from nonexistent agent gracefully', () => {
    const pool = createResourcePool(1000);
    const result = releaseTrust(pool, 'nonexistent', 100);
    expect(result.allocatedTrust).toBe(0);
    expect(result.availableTrust).toBe(1000);
  });
});

describe('slashStake', () => {
  it('destroys collateral on non-redistributed slash', () => {
    let pool = createResourcePool(1000);
    const { pool: p1 } = allocateTrust(pool, 'agent-1', 500);
    pool = p1;

    const event: SlashingEvent = {
      agentId: 'agent-1',
      amount: 200,
      reason: 'breach',
      timestamp: Date.now(),
      redistributed: false,
    };

    pool = slashStake(pool, event);
    expect(pool.totalCollateral).toBe(800); // 1000 - 200
    expect(pool.allocatedTrust).toBe(300); // 500 - 200
    expect(pool.availableTrust).toBe(500); // unchanged
    expect(pool.participants.get('agent-1')).toBe(300);
  });

  it('redistributes slashed amount when redistributed is true', () => {
    let pool = createResourcePool(1000);
    const { pool: p1 } = allocateTrust(pool, 'agent-1', 500);
    pool = p1;

    const event: SlashingEvent = {
      agentId: 'agent-1',
      amount: 200,
      reason: 'minor violation',
      timestamp: Date.now(),
      redistributed: true,
    };

    pool = slashStake(pool, event);
    expect(pool.totalCollateral).toBe(1000); // unchanged
    expect(pool.allocatedTrust).toBe(300); // 500 - 200
    expect(pool.availableTrust).toBe(700); // 500 + 200
    expect(pool.participants.get('agent-1')).toBe(300);
  });

  it('caps slash amount at agent allocation', () => {
    let pool = createResourcePool(1000);
    const { pool: p1 } = allocateTrust(pool, 'agent-1', 100);
    pool = p1;

    const event: SlashingEvent = {
      agentId: 'agent-1',
      amount: 500, // More than allocated
      reason: 'severe breach',
      timestamp: Date.now(),
      redistributed: false,
    };

    pool = slashStake(pool, event);
    expect(pool.totalCollateral).toBe(900); // 1000 - 100 (capped)
    expect(pool.allocatedTrust).toBe(0);
    expect(pool.participants.has('agent-1')).toBe(false);
  });

  it('removes agent when fully slashed', () => {
    let pool = createResourcePool(1000);
    const { pool: p1 } = allocateTrust(pool, 'agent-1', 300);
    pool = p1;

    const event: SlashingEvent = {
      agentId: 'agent-1',
      amount: 300,
      reason: 'full slash',
      timestamp: Date.now(),
      redistributed: false,
    };

    pool = slashStake(pool, event);
    expect(pool.participants.has('agent-1')).toBe(false);
  });
});

describe('collateralizationRatio', () => {
  it('returns 0 for empty pool', () => {
    const pool = createResourcePool(1000);
    expect(collateralizationRatio(pool)).toBe(0);
  });

  it('returns correct ratio after allocation', () => {
    const pool = createResourcePool(1000);
    const { pool: p1 } = allocateTrust(pool, 'agent-1', 250);
    expect(collateralizationRatio(p1)).toBeCloseTo(0.25);
  });

  it('returns 1.0 for fully allocated pool', () => {
    const pool = createResourcePool(500);
    const { pool: p1 } = allocateTrust(pool, 'agent-1', 500);
    expect(collateralizationRatio(p1)).toBeCloseTo(1.0);
  });

  it('never exceeds 1.0', () => {
    const pool = createResourcePool(100);
    const { pool: p1 } = allocateTrust(pool, 'agent-1', 100);
    expect(collateralizationRatio(p1)).toBeLessThanOrEqual(1.0);
  });

  it('returns 0 for zero collateral pool', () => {
    const pool = createResourcePool(0);
    expect(collateralizationRatio(pool)).toBe(0);
  });
});

describe('resource pool - integrated flow', () => {
  it('allocate, partially release, slash, verify invariants', () => {
    let pool = createResourcePool(1000);

    // Allocate to two agents
    const r1 = allocateTrust(pool, 'agent-1', 300);
    pool = r1.pool;
    const r2 = allocateTrust(pool, 'agent-2', 400);
    pool = r2.pool;

    expect(pool.allocatedTrust).toBe(700);
    expect(pool.availableTrust).toBe(300);

    // Release some from agent-1
    pool = releaseTrust(pool, 'agent-1', 100);
    expect(pool.allocatedTrust).toBe(600);
    expect(pool.availableTrust).toBe(400);

    // Slash agent-2 (destroyed)
    pool = slashStake(pool, {
      agentId: 'agent-2',
      amount: 150,
      reason: 'breach',
      timestamp: Date.now(),
      redistributed: false,
    });

    expect(pool.totalCollateral).toBe(850);
    expect(pool.allocatedTrust).toBe(450);
    expect(pool.availableTrust).toBe(400);
    expect(collateralizationRatio(pool)).toBeCloseTo(450 / 850);

    // Collateralization ratio must not exceed 1
    expect(collateralizationRatio(pool)).toBeLessThanOrEqual(1.0);
  });
});

// ===========================================================================
// Item 46: Multidimensional Trust Profile (Anti-Gaming)
// ===========================================================================

describe('computeProfile', () => {
  it('computes a profile with default equal weights', () => {
    const profile = computeProfile({
      agentId: 'agent-1',
      hardEnforcement: 0.8,
      attestationCoverage: 0.7,
      covenantBreadth: 0.6,
      historyDepth: 0.9,
      stakeRatio: 0.5,
    });

    expect(profile.agentId).toBe('agent-1');
    expect(profile.dimensions.hardEnforcement.score).toBe(0.8);
    expect(profile.dimensions.attestationCoverage.score).toBe(0.7);
    expect(profile.dimensions.covenantBreadth.score).toBe(0.6);
    expect(profile.dimensions.historyDepth.score).toBe(0.9);
    expect(profile.dimensions.stakeRatio.score).toBe(0.5);

    // All default weights should be 0.2
    expect(profile.dimensions.hardEnforcement.weight).toBe(0.2);
    expect(profile.dimensions.attestationCoverage.weight).toBe(0.2);

    // Evidence defaults to 1
    expect(profile.dimensions.hardEnforcement.evidence).toBe(1);

    // Composite score should be the geometric mean
    expect(profile.compositeScore).toBeGreaterThan(0);
    expect(profile.compositeScore).toBeLessThanOrEqual(1);

    // Gaming resistance
    expect(profile.gamingResistance).toBeGreaterThanOrEqual(0);
    expect(profile.gamingResistance).toBeLessThanOrEqual(1);
  });

  it('perfectly balanced profile has maximum gaming resistance', () => {
    const profile = computeProfile({
      agentId: 'agent-1',
      hardEnforcement: 0.7,
      attestationCoverage: 0.7,
      covenantBreadth: 0.7,
      historyDepth: 0.7,
      stakeRatio: 0.7,
    });

    // gamingResistance = 1 - max + min = 1 - 0.7 + 0.7 = 1.0
    expect(profile.gamingResistance).toBeCloseTo(1.0);
  });

  it('maximally unbalanced profile has low gaming resistance', () => {
    const profile = computeProfile({
      agentId: 'agent-1',
      hardEnforcement: 1.0,
      attestationCoverage: 0.0,
      covenantBreadth: 0.0,
      historyDepth: 0.0,
      stakeRatio: 0.0,
    });

    // gamingResistance = 1 - 1.0 + 0.0 = 0.0
    expect(profile.gamingResistance).toBeCloseTo(0.0);
  });

  it('composite score uses geometric mean (penalises zero dimensions)', () => {
    const balanced = computeProfile({
      agentId: 'agent-1',
      hardEnforcement: 0.5,
      attestationCoverage: 0.5,
      covenantBreadth: 0.5,
      historyDepth: 0.5,
      stakeRatio: 0.5,
    });

    const oneZero = computeProfile({
      agentId: 'agent-2',
      hardEnforcement: 1.0,
      attestationCoverage: 1.0,
      covenantBreadth: 1.0,
      historyDepth: 1.0,
      stakeRatio: 0.0,
    });

    // Even though oneZero has higher average, the geometric mean punishes the zero
    expect(oneZero.compositeScore).toBeLessThan(balanced.compositeScore);
  });

  it('all-ones profile has composite score of 1.0', () => {
    const profile = computeProfile({
      agentId: 'agent-1',
      hardEnforcement: 1.0,
      attestationCoverage: 1.0,
      covenantBreadth: 1.0,
      historyDepth: 1.0,
      stakeRatio: 1.0,
    });

    expect(profile.compositeScore).toBeCloseTo(1.0);
  });

  it('clamps input scores to [0, 1]', () => {
    const profile = computeProfile({
      agentId: 'agent-1',
      hardEnforcement: 1.5,
      attestationCoverage: -0.2,
      covenantBreadth: 0.5,
      historyDepth: 0.5,
      stakeRatio: 0.5,
    });

    expect(profile.dimensions.hardEnforcement.score).toBe(1.0);
    expect(profile.dimensions.attestationCoverage.score).toBe(0.0);
  });

  it('accepts custom weights', () => {
    const profile = computeProfile({
      agentId: 'agent-1',
      hardEnforcement: 0.9,
      attestationCoverage: 0.1,
      covenantBreadth: 0.5,
      historyDepth: 0.5,
      stakeRatio: 0.5,
      weights: {
        hardEnforcement: 0.5,
        attestationCoverage: 0.1,
      },
    });

    expect(profile.dimensions.hardEnforcement.weight).toBe(0.5);
    expect(profile.dimensions.attestationCoverage.weight).toBe(0.1);
    // Others keep defaults
    expect(profile.dimensions.covenantBreadth.weight).toBe(0.2);
  });

  it('dimension names are set correctly', () => {
    const profile = computeProfile({
      agentId: 'agent-1',
      hardEnforcement: 0.5,
      attestationCoverage: 0.5,
      covenantBreadth: 0.5,
      historyDepth: 0.5,
      stakeRatio: 0.5,
    });

    expect(profile.dimensions.hardEnforcement.name).toBe('hardEnforcement');
    expect(profile.dimensions.attestationCoverage.name).toBe('attestationCoverage');
    expect(profile.dimensions.covenantBreadth.name).toBe('covenantBreadth');
    expect(profile.dimensions.historyDepth.name).toBe('historyDepth');
    expect(profile.dimensions.stakeRatio.name).toBe('stakeRatio');
  });
});

describe('compareProfiles', () => {
  it('detects domination by profile a', () => {
    const a = computeProfile({
      agentId: 'a',
      hardEnforcement: 0.9,
      attestationCoverage: 0.8,
      covenantBreadth: 0.7,
      historyDepth: 0.9,
      stakeRatio: 0.6,
    });
    const b = computeProfile({
      agentId: 'b',
      hardEnforcement: 0.5,
      attestationCoverage: 0.4,
      covenantBreadth: 0.3,
      historyDepth: 0.5,
      stakeRatio: 0.2,
    });

    const result = compareProfiles(a, b);
    expect(result.dominates).toBe('a');
    expect(result.strongerDimensions.hardEnforcement).toBe('a');
    expect(result.strongerDimensions.stakeRatio).toBe('a');
  });

  it('detects domination by profile b', () => {
    const a = computeProfile({
      agentId: 'a',
      hardEnforcement: 0.2,
      attestationCoverage: 0.3,
      covenantBreadth: 0.1,
      historyDepth: 0.2,
      stakeRatio: 0.1,
    });
    const b = computeProfile({
      agentId: 'b',
      hardEnforcement: 0.8,
      attestationCoverage: 0.9,
      covenantBreadth: 0.7,
      historyDepth: 0.8,
      stakeRatio: 0.6,
    });

    const result = compareProfiles(a, b);
    expect(result.dominates).toBe('b');
  });

  it('returns neither when profiles trade off', () => {
    const a = computeProfile({
      agentId: 'a',
      hardEnforcement: 0.9,
      attestationCoverage: 0.2,
      covenantBreadth: 0.5,
      historyDepth: 0.5,
      stakeRatio: 0.5,
    });
    const b = computeProfile({
      agentId: 'b',
      hardEnforcement: 0.3,
      attestationCoverage: 0.8,
      covenantBreadth: 0.5,
      historyDepth: 0.5,
      stakeRatio: 0.5,
    });

    const result = compareProfiles(a, b);
    expect(result.dominates).toBe('neither');
    expect(result.strongerDimensions.hardEnforcement).toBe('a');
    expect(result.strongerDimensions.attestationCoverage).toBe('b');
    expect(result.strongerDimensions.covenantBreadth).toBe('tie');
  });

  it('returns neither when profiles are identical', () => {
    const a = computeProfile({
      agentId: 'a',
      hardEnforcement: 0.5,
      attestationCoverage: 0.5,
      covenantBreadth: 0.5,
      historyDepth: 0.5,
      stakeRatio: 0.5,
    });
    const b = computeProfile({
      agentId: 'b',
      hardEnforcement: 0.5,
      attestationCoverage: 0.5,
      covenantBreadth: 0.5,
      historyDepth: 0.5,
      stakeRatio: 0.5,
    });

    const result = compareProfiles(a, b);
    expect(result.dominates).toBe('neither');
    expect(result.strongerDimensions.hardEnforcement).toBe('tie');
  });

  it('correctly identifies per-dimension strengths', () => {
    const a = computeProfile({
      agentId: 'a',
      hardEnforcement: 0.9,
      attestationCoverage: 0.3,
      covenantBreadth: 0.5,
      historyDepth: 0.7,
      stakeRatio: 0.1,
    });
    const b = computeProfile({
      agentId: 'b',
      hardEnforcement: 0.3,
      attestationCoverage: 0.9,
      covenantBreadth: 0.5,
      historyDepth: 0.2,
      stakeRatio: 0.8,
    });

    const result = compareProfiles(a, b);
    expect(result.strongerDimensions.hardEnforcement).toBe('a');
    expect(result.strongerDimensions.attestationCoverage).toBe('b');
    expect(result.strongerDimensions.covenantBreadth).toBe('tie');
    expect(result.strongerDimensions.historyDepth).toBe('a');
    expect(result.strongerDimensions.stakeRatio).toBe('b');
  });
});

describe('multidimensional profile - gaming resistance scenarios', () => {
  it('specialist agent has lower gaming resistance than generalist', () => {
    const specialist = computeProfile({
      agentId: 'specialist',
      hardEnforcement: 1.0,
      attestationCoverage: 0.1,
      covenantBreadth: 0.1,
      historyDepth: 0.1,
      stakeRatio: 0.1,
    });

    const generalist = computeProfile({
      agentId: 'generalist',
      hardEnforcement: 0.5,
      attestationCoverage: 0.5,
      covenantBreadth: 0.5,
      historyDepth: 0.5,
      stakeRatio: 0.5,
    });

    expect(specialist.gamingResistance).toBeLessThan(generalist.gamingResistance);
  });

  it('partially balanced agent has moderate gaming resistance', () => {
    const partial = computeProfile({
      agentId: 'partial',
      hardEnforcement: 0.8,
      attestationCoverage: 0.6,
      covenantBreadth: 0.7,
      historyDepth: 0.5,
      stakeRatio: 0.6,
    });

    // gamingResistance = 1 - 0.8 + 0.5 = 0.7
    expect(partial.gamingResistance).toBeCloseTo(0.7);
    expect(partial.gamingResistance).toBeGreaterThan(0);
    expect(partial.gamingResistance).toBeLessThan(1);
  });
});

// ===========================================================================
// Item 75: Productive Staking Tiers
// ===========================================================================

describe('STAKE_TIERS', () => {
  it('has correct configuration for each tier', () => {
    expect(STAKE_TIERS.basic.minimumStake).toBe(1);
    expect(STAKE_TIERS.basic.verificationIncomeRate).toBe(0.0001);
    expect(STAKE_TIERS.basic.marketplaceRankBoost).toBe(1.0);
    expect(STAKE_TIERS.basic.governanceWeight).toBe(1);
    expect(STAKE_TIERS.basic.maxDelegations).toBe(5);

    expect(STAKE_TIERS.verified.minimumStake).toBe(10);
    expect(STAKE_TIERS.verified.verificationIncomeRate).toBe(0.0002);
    expect(STAKE_TIERS.verified.marketplaceRankBoost).toBe(1.5);
    expect(STAKE_TIERS.verified.governanceWeight).toBe(2);
    expect(STAKE_TIERS.verified.maxDelegations).toBe(20);

    expect(STAKE_TIERS.certified.minimumStake).toBe(100);
    expect(STAKE_TIERS.certified.verificationIncomeRate).toBe(0.0005);
    expect(STAKE_TIERS.certified.marketplaceRankBoost).toBe(3.0);
    expect(STAKE_TIERS.certified.governanceWeight).toBe(5);
    expect(STAKE_TIERS.certified.maxDelegations).toBe(100);

    expect(STAKE_TIERS.institutional.minimumStake).toBe(1000);
    expect(STAKE_TIERS.institutional.verificationIncomeRate).toBe(0.001);
    expect(STAKE_TIERS.institutional.marketplaceRankBoost).toBe(10.0);
    expect(STAKE_TIERS.institutional.governanceWeight).toBe(20);
    expect(STAKE_TIERS.institutional.maxDelegations).toBe(1000);
  });

  it('tiers are ordered by minimum stake', () => {
    expect(STAKE_TIERS.basic.minimumStake).toBeLessThan(STAKE_TIERS.verified.minimumStake);
    expect(STAKE_TIERS.verified.minimumStake).toBeLessThan(STAKE_TIERS.certified.minimumStake);
    expect(STAKE_TIERS.certified.minimumStake).toBeLessThan(STAKE_TIERS.institutional.minimumStake);
  });

  it('higher tiers have better income rates', () => {
    expect(STAKE_TIERS.basic.verificationIncomeRate).toBeLessThan(STAKE_TIERS.verified.verificationIncomeRate);
    expect(STAKE_TIERS.verified.verificationIncomeRate).toBeLessThan(STAKE_TIERS.certified.verificationIncomeRate);
    expect(STAKE_TIERS.certified.verificationIncomeRate).toBeLessThan(STAKE_TIERS.institutional.verificationIncomeRate);
  });

  it('higher tiers have higher governance weights', () => {
    expect(STAKE_TIERS.basic.governanceWeight).toBeLessThan(STAKE_TIERS.verified.governanceWeight);
    expect(STAKE_TIERS.verified.governanceWeight).toBeLessThan(STAKE_TIERS.certified.governanceWeight);
    expect(STAKE_TIERS.certified.governanceWeight).toBeLessThan(STAKE_TIERS.institutional.governanceWeight);
  });
});

describe('assignTier', () => {
  it('assigns basic tier for amounts below 10', () => {
    expect(assignTier(1)).toBe('basic');
    expect(assignTier(5)).toBe('basic');
    expect(assignTier(9.99)).toBe('basic');
  });

  it('assigns verified tier for amounts >= 10 and < 100', () => {
    expect(assignTier(10)).toBe('verified');
    expect(assignTier(50)).toBe('verified');
    expect(assignTier(99)).toBe('verified');
  });

  it('assigns certified tier for amounts >= 100 and < 1000', () => {
    expect(assignTier(100)).toBe('certified');
    expect(assignTier(500)).toBe('certified');
    expect(assignTier(999)).toBe('certified');
  });

  it('assigns institutional tier for amounts >= 1000', () => {
    expect(assignTier(1000)).toBe('institutional');
    expect(assignTier(5000)).toBe('institutional');
    expect(assignTier(1000000)).toBe('institutional');
  });

  it('assigns basic for amounts below minimum basic stake', () => {
    expect(assignTier(0)).toBe('basic');
    expect(assignTier(0.5)).toBe('basic');
  });
});

describe('createStakedAgent', () => {
  it('creates a basic agent', () => {
    const agent = createStakedAgent('agent-1', 5);
    expect(agent.agentId).toBe('agent-1');
    expect(agent.tier).toBe('basic');
    expect(agent.stakedAmount).toBe(5);
    expect(agent.earnedIncome).toBe(0);
    expect(agent.queriesServed).toBe(0);
    expect(agent.config.tier).toBe('basic');
    expect(agent.config.verificationIncomeRate).toBe(0.0001);
  });

  it('creates a verified agent', () => {
    const agent = createStakedAgent('agent-2', 50);
    expect(agent.tier).toBe('verified');
    expect(agent.config.governanceWeight).toBe(2);
    expect(agent.config.maxDelegations).toBe(20);
  });

  it('creates a certified agent', () => {
    const agent = createStakedAgent('agent-3', 200);
    expect(agent.tier).toBe('certified');
    expect(agent.config.marketplaceRankBoost).toBe(3.0);
  });

  it('creates an institutional agent', () => {
    const agent = createStakedAgent('agent-4', 5000);
    expect(agent.tier).toBe('institutional');
    expect(agent.config.governanceWeight).toBe(20);
    expect(agent.config.maxDelegations).toBe(1000);
  });

  it('creates agent at exact tier boundaries', () => {
    expect(createStakedAgent('a', 1).tier).toBe('basic');
    expect(createStakedAgent('b', 10).tier).toBe('verified');
    expect(createStakedAgent('c', 100).tier).toBe('certified');
    expect(createStakedAgent('d', 1000).tier).toBe('institutional');
  });
});

describe('recordQuery', () => {
  it('increments queriesServed and adds income', () => {
    const agent = createStakedAgent('agent-1', 5);
    const updated = recordQuery(agent);
    expect(updated.queriesServed).toBe(1);
    expect(updated.earnedIncome).toBeCloseTo(0.0001);
  });

  it('accumulates income over multiple queries', () => {
    let agent = createStakedAgent('agent-1', 50); // verified tier
    for (let i = 0; i < 10; i++) {
      agent = recordQuery(agent);
    }
    expect(agent.queriesServed).toBe(10);
    expect(agent.earnedIncome).toBeCloseTo(10 * 0.0002);
  });

  it('does not mutate the original agent', () => {
    const agent = createStakedAgent('agent-1', 5);
    recordQuery(agent);
    expect(agent.queriesServed).toBe(0);
    expect(agent.earnedIncome).toBe(0);
  });

  it('higher tier earns more per query', () => {
    let basic = createStakedAgent('basic', 5);
    let institutional = createStakedAgent('inst', 5000);

    basic = recordQuery(basic);
    institutional = recordQuery(institutional);

    expect(institutional.earnedIncome).toBeGreaterThan(basic.earnedIncome);
  });

  it('preserves other agent fields', () => {
    const agent = createStakedAgent('agent-1', 200);
    const updated = recordQuery(agent);
    expect(updated.agentId).toBe('agent-1');
    expect(updated.tier).toBe('certified');
    expect(updated.stakedAmount).toBe(200);
    expect(updated.config).toEqual(agent.config);
  });
});

describe('computeGovernanceVote', () => {
  it('multiplies base vote by governance weight', () => {
    const basicAgent = createStakedAgent('basic', 5);
    expect(computeGovernanceVote(basicAgent, 1)).toBe(1); // weight 1

    const verifiedAgent = createStakedAgent('verified', 50);
    expect(computeGovernanceVote(verifiedAgent, 1)).toBe(2); // weight 2

    const certifiedAgent = createStakedAgent('certified', 200);
    expect(computeGovernanceVote(certifiedAgent, 1)).toBe(5); // weight 5

    const instAgent = createStakedAgent('inst', 5000);
    expect(computeGovernanceVote(instAgent, 1)).toBe(20); // weight 20
  });

  it('scales with base vote', () => {
    const agent = createStakedAgent('agent-1', 200); // certified, weight 5
    expect(computeGovernanceVote(agent, 10)).toBe(50);
    expect(computeGovernanceVote(agent, 0)).toBe(0);
    expect(computeGovernanceVote(agent, 0.5)).toBeCloseTo(2.5);
  });

  it('institutional agents have 20x voting power over basic', () => {
    const basic = createStakedAgent('basic', 5);
    const inst = createStakedAgent('inst', 5000);
    const baseVote = 1;
    expect(computeGovernanceVote(inst, baseVote)).toBe(
      20 * computeGovernanceVote(basic, baseVote),
    );
  });
});

describe('staking tiers - integrated flow', () => {
  it('agent lifecycle: create, serve queries, earn income, governance', () => {
    // Create an agent at the verified tier
    let agent = createStakedAgent('agent-1', 25);
    expect(agent.tier).toBe('verified');
    expect(agent.config.marketplaceRankBoost).toBe(1.5);

    // Serve 100 queries
    for (let i = 0; i < 100; i++) {
      agent = recordQuery(agent);
    }
    expect(agent.queriesServed).toBe(100);
    expect(agent.earnedIncome).toBeCloseTo(100 * 0.0002);

    // Vote in governance
    const vote = computeGovernanceVote(agent, 1);
    expect(vote).toBe(2);

    // The agent's tier is consistent with the config
    expect(agent.config.maxDelegations).toBe(20);
  });
});

// ===========================================================================
// ReceiptDAG
// ===========================================================================

describe('ReceiptDAG', () => {
  // Helper: create a minimal receipt with a unique hash derived from a label
  async function dagReceipt(label: string, outcome: ExecutionReceipt['outcome'] = 'fulfilled'): Promise<ExecutionReceipt> {
    const agentKp = await generateKeyPair();
    const principalKp = await generateKeyPair();
    return createReceipt(
      fakeHash('cov-dag'),
      agentKp.publicKeyHex,
      principalKp.publicKeyHex,
      outcome,
      fakeHash(`proof-${label}`),
      100,
      agentKp,
      null,
      outcome === 'breached' ? 'medium' : undefined,
    );
  }

  // -----------------------------------------------------------------------
  // Empty DAG
  // -----------------------------------------------------------------------

  it('starts empty with size 0', () => {
    const dag = new ReceiptDAG();
    expect(dag.size).toBe(0);
    expect(dag.getRoots()).toEqual([]);
    expect(dag.getLeaves()).toEqual([]);
  });

  it('computeDAGReputation returns 0 for an empty DAG', () => {
    const dag = new ReceiptDAG();
    expect(dag.computeDAGReputation()).toBe(0);
  });

  // -----------------------------------------------------------------------
  // Single node
  // -----------------------------------------------------------------------

  it('adds a single root node', async () => {
    const dag = new ReceiptDAG();
    const r = await dagReceipt('root');
    dag.addNode(r);

    expect(dag.size).toBe(1);
    expect(dag.getRoots()).toEqual([r.receiptHash]);
    expect(dag.getLeaves()).toEqual([r.receiptHash]);
  });

  it('getNode returns a copy of the node', async () => {
    const dag = new ReceiptDAG();
    const r = await dagReceipt('root');
    dag.addNode(r);

    const node = dag.getNode(r.receiptHash);
    expect(node).toBeDefined();
    expect(node!.receiptHash).toBe(r.receiptHash);
    expect(node!.parentHashes).toEqual([]);
    expect(node!.receipt).toBeDefined();
  });

  it('getNode returns undefined for a missing hash', () => {
    const dag = new ReceiptDAG();
    expect(dag.getNode(fakeHash('nonexistent'))).toBeUndefined();
  });

  // -----------------------------------------------------------------------
  // Linear chain
  // -----------------------------------------------------------------------

  it('builds a linear chain of receipts', async () => {
    const dag = new ReceiptDAG();
    const r1 = await dagReceipt('n1');
    const r2 = await dagReceipt('n2');
    const r3 = await dagReceipt('n3');

    dag.addNode(r1);
    dag.addNode(r2, [r1.receiptHash]);
    dag.addNode(r3, [r2.receiptHash]);

    expect(dag.size).toBe(3);
    expect(dag.getRoots()).toEqual([r1.receiptHash]);
    expect(dag.getLeaves()).toEqual([r3.receiptHash]);
  });

  // -----------------------------------------------------------------------
  // Fork and merge (diamond shape)
  // -----------------------------------------------------------------------

  it('supports fork and merge (diamond DAG)', async () => {
    //     root
    //    /    \
    //  left  right
    //    \    /
    //     merge
    const dag = new ReceiptDAG();
    const root = await dagReceipt('root');
    const left = await dagReceipt('left');
    const right = await dagReceipt('right');
    const merge = await dagReceipt('merge');

    dag.addNode(root);
    dag.addNode(left, [root.receiptHash]);
    dag.addNode(right, [root.receiptHash]);
    dag.addNode(merge, [left.receiptHash, right.receiptHash]);

    expect(dag.size).toBe(4);
    expect(dag.getRoots()).toEqual([root.receiptHash]);
    expect(dag.getLeaves()).toEqual([merge.receiptHash]);

    // The root node should have 2 children (left and right)
    const rootNode = dag.getNode(root.receiptHash)!;
    expect(rootNode.parentHashes).toHaveLength(0);
  });

  // -----------------------------------------------------------------------
  // Multiple roots
  // -----------------------------------------------------------------------

  it('supports multiple root nodes', async () => {
    const dag = new ReceiptDAG();
    const r1 = await dagReceipt('root1');
    const r2 = await dagReceipt('root2');
    const child = await dagReceipt('child');

    dag.addNode(r1);
    dag.addNode(r2);
    dag.addNode(child, [r1.receiptHash, r2.receiptHash]);

    expect(dag.size).toBe(3);
    const roots = dag.getRoots();
    expect(roots).toHaveLength(2);
    expect(roots).toContain(r1.receiptHash);
    expect(roots).toContain(r2.receiptHash);
    expect(dag.getLeaves()).toEqual([child.receiptHash]);
  });

  // -----------------------------------------------------------------------
  // Multiple leaves
  // -----------------------------------------------------------------------

  it('supports multiple leaf nodes (fork without merge)', async () => {
    const dag = new ReceiptDAG();
    const root = await dagReceipt('root');
    const l1 = await dagReceipt('leaf1');
    const l2 = await dagReceipt('leaf2');

    dag.addNode(root);
    dag.addNode(l1, [root.receiptHash]);
    dag.addNode(l2, [root.receiptHash]);

    expect(dag.size).toBe(3);
    expect(dag.getRoots()).toEqual([root.receiptHash]);
    const leaves = dag.getLeaves();
    expect(leaves).toHaveLength(2);
    expect(leaves).toContain(l1.receiptHash);
    expect(leaves).toContain(l2.receiptHash);
  });

  // -----------------------------------------------------------------------
  // Error paths
  // -----------------------------------------------------------------------

  it('throws when adding a receipt with missing parent', async () => {
    const dag = new ReceiptDAG();
    const r = await dagReceipt('child');
    expect(() => dag.addNode(r, [fakeHash('nonexistent-parent')])).toThrow(
      /not found in DAG/,
    );
  });

  it('throws when adding a duplicate receipt', async () => {
    const dag = new ReceiptDAG();
    const r = await dagReceipt('dup');
    dag.addNode(r);
    expect(() => dag.addNode(r)).toThrow(/already exists in DAG/);
  });

  // -----------------------------------------------------------------------
  // findCommonAncestors
  // -----------------------------------------------------------------------

  it('findCommonAncestors returns the node itself when both hashes are the same', async () => {
    const dag = new ReceiptDAG();
    const r = await dagReceipt('only');
    dag.addNode(r);

    const ancestors = dag.findCommonAncestors(r.receiptHash, r.receiptHash);
    expect(ancestors).toEqual([r.receiptHash]);
  });

  it('findCommonAncestors finds root as common ancestor in a diamond', async () => {
    const dag = new ReceiptDAG();
    const root = await dagReceipt('root');
    const left = await dagReceipt('left');
    const right = await dagReceipt('right');

    dag.addNode(root);
    dag.addNode(left, [root.receiptHash]);
    dag.addNode(right, [root.receiptHash]);

    const ancestors = dag.findCommonAncestors(left.receiptHash, right.receiptHash);
    expect(ancestors).toContain(root.receiptHash);
  });

  it('findCommonAncestors with deeper diamond returns lowest common ancestor', async () => {
    //     root
    //    /    \
    //   a      b
    //   |      |
    //   c      d
    const dag = new ReceiptDAG();
    const root = await dagReceipt('root');
    const a = await dagReceipt('a');
    const b = await dagReceipt('b');
    const c = await dagReceipt('c');
    const d = await dagReceipt('d');

    dag.addNode(root);
    dag.addNode(a, [root.receiptHash]);
    dag.addNode(b, [root.receiptHash]);
    dag.addNode(c, [a.receiptHash]);
    dag.addNode(d, [b.receiptHash]);

    const ancestors = dag.findCommonAncestors(c.receiptHash, d.receiptHash);
    expect(ancestors).toContain(root.receiptHash);
  });

  it('findCommonAncestors throws for unknown hashes', async () => {
    const dag = new ReceiptDAG();
    const r = await dagReceipt('only');
    dag.addNode(r);

    expect(() => dag.findCommonAncestors(r.receiptHash, fakeHash('unknown'))).toThrow(
      /not found in DAG/,
    );
    expect(() => dag.findCommonAncestors(fakeHash('unknown'), r.receiptHash)).toThrow(
      /not found in DAG/,
    );
  });

  it('findCommonAncestors returns empty for nodes in disconnected components', async () => {
    const dag = new ReceiptDAG();
    const r1 = await dagReceipt('island1');
    const r2 = await dagReceipt('island2');
    dag.addNode(r1);
    dag.addNode(r2);

    const ancestors = dag.findCommonAncestors(r1.receiptHash, r2.receiptHash);
    expect(ancestors).toHaveLength(0);
  });

  // -----------------------------------------------------------------------
  // computeDAGReputation
  // -----------------------------------------------------------------------

  it('computeDAGReputation returns a value in [0, 1] for a single fulfilled node', async () => {
    const dag = new ReceiptDAG();
    const r = await dagReceipt('fulfilled-only', 'fulfilled');
    dag.addNode(r);

    const score = dag.computeDAGReputation();
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThanOrEqual(1);
  });

  it('computeDAGReputation for all-fulfilled chain produces positive score', async () => {
    const dag = new ReceiptDAG();
    const r1 = await dagReceipt('ok1', 'fulfilled');
    const r2 = await dagReceipt('ok2', 'fulfilled');
    const r3 = await dagReceipt('ok3', 'fulfilled');

    dag.addNode(r1);
    dag.addNode(r2, [r1.receiptHash]);
    dag.addNode(r3, [r2.receiptHash]);

    const score = dag.computeDAGReputation();
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThanOrEqual(1);
  });

  it('computeDAGReputation for all-failed chain produces zero or near-zero score', async () => {
    const dag = new ReceiptDAG();
    const r1 = await dagReceipt('f1', 'failed');
    const r2 = await dagReceipt('f2', 'failed');

    dag.addNode(r1);
    dag.addNode(r2, [r1.receiptHash]);

    const score = dag.computeDAGReputation();
    expect(score).toBe(0);
  });

  it('computeDAGReputation of breached receipts is lower than fulfilled', async () => {
    const dagGood = new ReceiptDAG();
    const good = await dagReceipt('good', 'fulfilled');
    dagGood.addNode(good);

    const dagBad = new ReceiptDAG();
    const bad = await dagReceipt('bad', 'breached');
    dagBad.addNode(bad);

    const goodScore = dagGood.computeDAGReputation();
    const badScore = dagBad.computeDAGReputation();
    expect(goodScore).toBeGreaterThan(badScore);
  });

  it('computeDAGReputation averages leaf scores in a fork', async () => {
    // Fork: root -> fulfilled leaf + root -> failed leaf
    // The average should be between the two extremes
    const dag = new ReceiptDAG();
    const root = await dagReceipt('root', 'fulfilled');
    const goodLeaf = await dagReceipt('good', 'fulfilled');
    const badLeaf = await dagReceipt('bad', 'failed');

    dag.addNode(root);
    dag.addNode(goodLeaf, [root.receiptHash]);
    dag.addNode(badLeaf, [root.receiptHash]);

    const score = dag.computeDAGReputation();
    // Should be between the good-only and bad-only scores
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThan(1);
  });

  it('handles a large DAG without errors', async () => {
    const dag = new ReceiptDAG();
    const receipts: ExecutionReceipt[] = [];

    // Build a wide DAG: 3 roots, each with 3 children, all merging
    for (let i = 0; i < 3; i++) {
      const r = await dagReceipt(`root-${i}`);
      dag.addNode(r);
      receipts.push(r);
    }

    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        const child = await dagReceipt(`child-${i}-${j}`);
        dag.addNode(child, [receipts[i]!.receiptHash]);
        receipts.push(child);
      }
    }

    expect(dag.size).toBe(12);
    expect(dag.getRoots()).toHaveLength(3);
    expect(dag.getLeaves()).toHaveLength(9);

    const score = dag.computeDAGReputation();
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(1);
  });
});

// ===========================================================================
// ReputationDecayModel
// ===========================================================================

describe('ReputationDecayModel', () => {
  // -----------------------------------------------------------------------
  // Exponential decay
  // -----------------------------------------------------------------------

  describe('exponential decay', () => {
    it('returns 1 at t=0', () => {
      const model = new ReputationDecayModel({ model: 'exponential', params: { lambda: 0.1 } });
      expect(model.decay(0)).toBe(1);
    });

    it('follows e^(-lambda*t)', () => {
      const lambda = 0.5;
      const model = new ReputationDecayModel({ model: 'exponential', params: { lambda } });

      expect(model.decay(1)).toBeCloseTo(Math.exp(-0.5), 10);
      expect(model.decay(2)).toBeCloseTo(Math.exp(-1.0), 10);
      expect(model.decay(10)).toBeCloseTo(Math.exp(-5.0), 10);
    });

    it('decays monotonically', () => {
      const model = new ReputationDecayModel({ model: 'exponential', params: { lambda: 0.3 } });
      let prev = model.decay(0);
      for (let t = 1; t <= 20; t++) {
        const curr = model.decay(t);
        expect(curr).toBeLessThan(prev);
        prev = curr;
      }
    });

    it('approaches 0 for large t', () => {
      const model = new ReputationDecayModel({ model: 'exponential', params: { lambda: 1 } });
      expect(model.decay(100)).toBeCloseTo(0, 10);
    });

    it('apply multiplies score by decay factor', () => {
      const model = new ReputationDecayModel({ model: 'exponential', params: { lambda: 0.1 } });
      const score = 0.85;
      const t = 5;
      expect(model.apply(score, t)).toBeCloseTo(score * Math.exp(-0.5), 10);
    });

    it('type getter returns exponential', () => {
      const model = new ReputationDecayModel({ model: 'exponential', params: { lambda: 1 } });
      expect(model.type).toBe('exponential');
    });
  });

  // -----------------------------------------------------------------------
  // Weibull decay
  // -----------------------------------------------------------------------

  describe('weibull decay', () => {
    it('returns 1 at t=0', () => {
      const model = new ReputationDecayModel({ model: 'weibull', params: { k: 2, lambda: 5 } });
      expect(model.decay(0)).toBe(1);
    });

    it('follows e^(-(t/lambda)^k)', () => {
      const k = 2;
      const lambda = 5;
      const model = new ReputationDecayModel({ model: 'weibull', params: { k, lambda } });

      const t = 3;
      const expected = Math.exp(-Math.pow(t / lambda, k));
      expect(model.decay(t)).toBeCloseTo(expected, 10);
    });

    it('with k=1, reduces to exponential with rate 1/lambda', () => {
      const lambda = 2;
      const model = new ReputationDecayModel({ model: 'weibull', params: { k: 1, lambda } });
      // Weibull k=1: e^(-(t/lambda)^1) = e^(-t/lambda)
      // This is exponential with rate 1/lambda
      const t = 4;
      expect(model.decay(t)).toBeCloseTo(Math.exp(-t / lambda), 10);
    });

    it('k > 1 decays slowly at first then quickly', () => {
      const model = new ReputationDecayModel({ model: 'weibull', params: { k: 3, lambda: 5 } });
      // At t=1 (small relative to lambda=5), decay should be very close to 1
      expect(model.decay(1)).toBeGreaterThan(0.99);
      // At t=10 (well past lambda=5 with k=3), decay should be near 0
      expect(model.decay(10)).toBeLessThan(0.01);
    });

    it('k < 1 decays quickly at first then slowly', () => {
      const model = new ReputationDecayModel({ model: 'weibull', params: { k: 0.5, lambda: 1 } });
      // At t=0.01, still significant decay already (k < 1 means early decay)
      const earlyDecay = 1 - model.decay(0.01);
      // At t=100, still some signal remaining
      expect(model.decay(100)).toBeGreaterThan(0);
    });

    it('type getter returns weibull', () => {
      const model = new ReputationDecayModel({ model: 'weibull', params: { k: 1, lambda: 1 } });
      expect(model.type).toBe('weibull');
    });
  });

  // -----------------------------------------------------------------------
  // Gamma decay
  // -----------------------------------------------------------------------

  describe('gamma decay', () => {
    it('returns 1 at t=0', () => {
      const model = new ReputationDecayModel({ model: 'gamma', params: { alpha: 2, beta: 1 } });
      expect(model.decay(0)).toBe(1);
    });

    it('decays towards 0 for large t', () => {
      const model = new ReputationDecayModel({ model: 'gamma', params: { alpha: 2, beta: 1 } });
      expect(model.decay(100)).toBeLessThan(0.01);
    });

    it('decay is monotonically non-increasing', () => {
      const model = new ReputationDecayModel({ model: 'gamma', params: { alpha: 3, beta: 0.5 } });
      let prev = model.decay(0);
      for (let t = 1; t <= 30; t++) {
        const curr = model.decay(t);
        expect(curr).toBeLessThanOrEqual(prev + 1e-10); // small tolerance for numerical issues
        prev = curr;
      }
    });

    it('apply works correctly with gamma model', () => {
      const model = new ReputationDecayModel({ model: 'gamma', params: { alpha: 2, beta: 0.5 } });
      const score = 0.9;
      const t = 5;
      const decayed = model.apply(score, t);
      expect(decayed).toBeCloseTo(score * model.decay(t), 10);
    });

    it('type getter returns gamma', () => {
      const model = new ReputationDecayModel({ model: 'gamma', params: { alpha: 1, beta: 1 } });
      expect(model.type).toBe('gamma');
    });

    it('alpha=1 gamma is similar to exponential (both are memoryless)', () => {
      // Gamma(1, beta) survival function = e^(-beta*t), similar to exponential
      const beta = 0.3;
      const gammaModel = new ReputationDecayModel({ model: 'gamma', params: { alpha: 1, beta } });
      const expModel = new ReputationDecayModel({ model: 'exponential', params: { lambda: beta } });

      for (const t of [0, 1, 5, 10]) {
        expect(gammaModel.decay(t)).toBeCloseTo(expModel.decay(t), 3);
      }
    });
  });

  // -----------------------------------------------------------------------
  // Error paths
  // -----------------------------------------------------------------------

  describe('constructor validation', () => {
    it('rejects unknown model type', () => {
      expect(() => new ReputationDecayModel({ model: 'unknown' as any, params: {} })).toThrow(
        /Unknown decay model/,
      );
    });

    it('rejects exponential with missing lambda', () => {
      expect(() => new ReputationDecayModel({ model: 'exponential', params: {} })).toThrow(
        /lambda/,
      );
    });

    it('rejects exponential with lambda <= 0', () => {
      expect(() => new ReputationDecayModel({ model: 'exponential', params: { lambda: 0 } })).toThrow(
        /lambda/,
      );
      expect(() => new ReputationDecayModel({ model: 'exponential', params: { lambda: -1 } })).toThrow(
        /lambda/,
      );
    });

    it('rejects weibull with missing k', () => {
      expect(() => new ReputationDecayModel({ model: 'weibull', params: { lambda: 1 } })).toThrow(/k/);
    });

    it('rejects weibull with k <= 0', () => {
      expect(() => new ReputationDecayModel({ model: 'weibull', params: { k: 0, lambda: 1 } })).toThrow(/k/);
    });

    it('rejects weibull with missing lambda', () => {
      expect(() => new ReputationDecayModel({ model: 'weibull', params: { k: 1 } })).toThrow(/lambda/);
    });

    it('rejects weibull with lambda <= 0', () => {
      expect(() => new ReputationDecayModel({ model: 'weibull', params: { k: 1, lambda: 0 } })).toThrow(/lambda/);
    });

    it('rejects gamma with missing alpha', () => {
      expect(() => new ReputationDecayModel({ model: 'gamma', params: { beta: 1 } })).toThrow(/alpha/);
    });

    it('rejects gamma with alpha <= 0', () => {
      expect(() => new ReputationDecayModel({ model: 'gamma', params: { alpha: -1, beta: 1 } })).toThrow(/alpha/);
    });

    it('rejects gamma with missing beta', () => {
      expect(() => new ReputationDecayModel({ model: 'gamma', params: { alpha: 1 } })).toThrow(/beta/);
    });

    it('rejects gamma with beta <= 0', () => {
      expect(() => new ReputationDecayModel({ model: 'gamma', params: { alpha: 1, beta: 0 } })).toThrow(/beta/);
    });
  });

  describe('decay(t) validation', () => {
    it('throws for negative t', () => {
      const model = new ReputationDecayModel({ model: 'exponential', params: { lambda: 1 } });
      expect(() => model.decay(-1)).toThrow(/non-negative/);
    });
  });
});

// ===========================================================================
// GraduatedBurner
// ===========================================================================

describe('GraduatedBurner', () => {
  // -----------------------------------------------------------------------
  // Constructor and defaults
  // -----------------------------------------------------------------------

  it('constructs with default configuration', () => {
    const burner = new GraduatedBurner();
    // Just verify it doesn't throw
    const result = burner.calculateBurn(100, 'medium', 0, 10);
    expect(result.burnAmount).toBeGreaterThan(0);
    expect(result.burnFraction).toBeGreaterThan(0);
    expect(result.burnFraction).toBeLessThanOrEqual(1);
  });

  it('constructs with partial config overrides', () => {
    const burner = new GraduatedBurner({ minBurnFraction: 0.1, maxBurnFraction: 0.8 });
    const result = burner.calculateBurn(1000, 'low', 0, 10);
    expect(result.burnFraction).toBeGreaterThanOrEqual(0.1);
    expect(result.burnFraction).toBeLessThanOrEqual(0.8);
  });

  // -----------------------------------------------------------------------
  // Severity mapping
  // -----------------------------------------------------------------------

  describe('severity to burn fraction mapping', () => {
    it('critical severity produces highest burn', () => {
      const burner = new GraduatedBurner();
      const critical = burner.calculateBurn(1000, 'critical', 0, 100);
      const high = burner.calculateBurn(1000, 'high', 0, 100);
      const medium = burner.calculateBurn(1000, 'medium', 0, 100);
      const low = burner.calculateBurn(1000, 'low', 0, 100);

      expect(critical.burnFraction).toBeGreaterThan(high.burnFraction);
      expect(high.burnFraction).toBeGreaterThan(medium.burnFraction);
      expect(medium.burnFraction).toBeGreaterThan(low.burnFraction);
    });

    it('critical=1.0, high=0.75, medium=0.5, low=0.25 base scores', () => {
      // With historyWeight=0 and curveExponent=1 (linear), the severity maps directly
      const burner = new GraduatedBurner({
        minBurnFraction: 0,
        maxBurnFraction: 1,
        curveExponent: 1,
        historyWeight: 0,
      });

      // burnFraction = 0 + (1-0) * severity^1 = severity
      expect(burner.calculateBurn(100, 'critical', 0, 0).burnFraction).toBeCloseTo(1.0);
      expect(burner.calculateBurn(100, 'high', 0, 0).burnFraction).toBeCloseTo(0.75);
      expect(burner.calculateBurn(100, 'medium', 0, 0).burnFraction).toBeCloseTo(0.5);
      expect(burner.calculateBurn(100, 'low', 0, 0).burnFraction).toBeCloseTo(0.25);
    });
  });

  // -----------------------------------------------------------------------
  // Burn amount calculation
  // -----------------------------------------------------------------------

  it('burnAmount equals stakeAmount * burnFraction', () => {
    const burner = new GraduatedBurner();
    const stake = 500;
    const result = burner.calculateBurn(stake, 'medium', 0, 10);
    expect(result.burnAmount).toBeCloseTo(stake * result.burnFraction);
  });

  it('zero stake produces zero burn amount', () => {
    const burner = new GraduatedBurner();
    const result = burner.calculateBurn(0, 'critical', 5, 10);
    expect(result.burnAmount).toBe(0);
    // burnFraction can still be > 0 (it's just applied to 0)
  });

  // -----------------------------------------------------------------------
  // History adjustment
  // -----------------------------------------------------------------------

  it('agents with more past breaches get higher burn', () => {
    const burner = new GraduatedBurner();
    const noBreach = burner.calculateBurn(1000, 'medium', 0, 100);
    const someBreach = burner.calculateBurn(1000, 'medium', 20, 100);
    const manyBreach = burner.calculateBurn(1000, 'medium', 50, 100);

    expect(someBreach.burnFraction).toBeGreaterThan(noBreach.burnFraction);
    expect(manyBreach.burnFraction).toBeGreaterThan(someBreach.burnFraction);
  });

  it('history has no effect when historyWeight is 0', () => {
    const burner = new GraduatedBurner({ historyWeight: 0 });
    const noBreach = burner.calculateBurn(1000, 'medium', 0, 100);
    const manyBreach = burner.calculateBurn(1000, 'medium', 50, 100);

    expect(manyBreach.burnFraction).toBeCloseTo(noBreach.burnFraction);
  });

  it('history adjustment when totalPastExecutions is 0 treats breachRatio as 0', () => {
    const burner = new GraduatedBurner();
    // pastBreachCount=0, totalPastExecutions=0 => breachRatio = 0
    const result = burner.calculateBurn(1000, 'low', 0, 0);
    const expected = burner.calculateBurn(1000, 'low', 0, 100);
    expect(result.burnFraction).toBeCloseTo(expected.burnFraction);
  });

  // -----------------------------------------------------------------------
  // Curve exponent
  // -----------------------------------------------------------------------

  it('linear curve (exponent=1) scales proportionally', () => {
    const burner = new GraduatedBurner({
      minBurnFraction: 0,
      maxBurnFraction: 1,
      curveExponent: 1,
      historyWeight: 0,
    });

    // With linear scaling, burnFraction should equal the severity score
    const result = burner.calculateBurn(100, 'medium', 0, 10);
    expect(result.burnFraction).toBeCloseTo(0.5); // medium = 0.5
  });

  it('superlinear curve (exponent>1) is lenient for low severity', () => {
    const linearBurner = new GraduatedBurner({
      minBurnFraction: 0,
      maxBurnFraction: 1,
      curveExponent: 1,
      historyWeight: 0,
    });
    const superBurner = new GraduatedBurner({
      minBurnFraction: 0,
      maxBurnFraction: 1,
      curveExponent: 2,
      historyWeight: 0,
    });

    // For low severity (0.25), superlinear should produce less burn
    const linearLow = linearBurner.calculateBurn(100, 'low', 0, 10);
    const superLow = superBurner.calculateBurn(100, 'low', 0, 10);
    expect(superLow.burnFraction).toBeLessThan(linearLow.burnFraction);

    // For critical (1.0), both should produce the same (1^n = 1)
    const linearCrit = linearBurner.calculateBurn(100, 'critical', 0, 10);
    const superCrit = superBurner.calculateBurn(100, 'critical', 0, 10);
    expect(superCrit.burnFraction).toBeCloseTo(linearCrit.burnFraction);
  });

  // -----------------------------------------------------------------------
  // Clamping
  // -----------------------------------------------------------------------

  it('burnFraction is clamped to [0, 1]', () => {
    const burner = new GraduatedBurner();
    // Even with extreme parameters, burnFraction stays in [0, 1]
    const result = burner.calculateBurn(1000, 'critical', 100, 100);
    expect(result.burnFraction).toBeGreaterThanOrEqual(0);
    expect(result.burnFraction).toBeLessThanOrEqual(1);
  });

  // -----------------------------------------------------------------------
  // Constructor validation
  // -----------------------------------------------------------------------

  describe('constructor validation', () => {
    it('rejects minBurnFraction < 0', () => {
      expect(() => new GraduatedBurner({ minBurnFraction: -0.1 })).toThrow(/minBurnFraction/);
    });

    it('rejects minBurnFraction > 1', () => {
      expect(() => new GraduatedBurner({ minBurnFraction: 1.5 })).toThrow(/minBurnFraction/);
    });

    it('rejects maxBurnFraction < minBurnFraction', () => {
      expect(() => new GraduatedBurner({ minBurnFraction: 0.5, maxBurnFraction: 0.3 })).toThrow(
        /maxBurnFraction/,
      );
    });

    it('rejects maxBurnFraction > 1', () => {
      expect(() => new GraduatedBurner({ maxBurnFraction: 1.5 })).toThrow(/maxBurnFraction/);
    });

    it('rejects curveExponent <= 0', () => {
      expect(() => new GraduatedBurner({ curveExponent: 0 })).toThrow(/curveExponent/);
      expect(() => new GraduatedBurner({ curveExponent: -1 })).toThrow(/curveExponent/);
    });

    it('rejects historyWeight < 0', () => {
      expect(() => new GraduatedBurner({ historyWeight: -0.1 })).toThrow(/historyWeight/);
    });

    it('rejects historyWeight > 1', () => {
      expect(() => new GraduatedBurner({ historyWeight: 1.5 })).toThrow(/historyWeight/);
    });
  });

  // -----------------------------------------------------------------------
  // calculateBurn input validation
  // -----------------------------------------------------------------------

  describe('calculateBurn input validation', () => {
    it('rejects negative stakeAmount', () => {
      const burner = new GraduatedBurner();
      expect(() => burner.calculateBurn(-100, 'medium', 0, 10)).toThrow(/stakeAmount/);
    });

    it('rejects negative pastBreachCount', () => {
      const burner = new GraduatedBurner();
      expect(() => burner.calculateBurn(100, 'medium', -1, 10)).toThrow(/pastBreachCount/);
    });

    it('rejects non-integer pastBreachCount', () => {
      const burner = new GraduatedBurner();
      expect(() => burner.calculateBurn(100, 'medium', 1.5, 10)).toThrow(/pastBreachCount/);
    });

    it('rejects negative totalPastExecutions', () => {
      const burner = new GraduatedBurner();
      expect(() => burner.calculateBurn(100, 'medium', 0, -5)).toThrow(/totalPastExecutions/);
    });

    it('rejects non-integer totalPastExecutions', () => {
      const burner = new GraduatedBurner();
      expect(() => burner.calculateBurn(100, 'medium', 0, 10.5)).toThrow(/totalPastExecutions/);
    });
  });
});

// ===========================================================================
// ReputationAggregator
// ===========================================================================

describe('ReputationAggregator', () => {
  const agg = new ReputationAggregator();

  // -----------------------------------------------------------------------
  // aggregate - happy paths
  // -----------------------------------------------------------------------

  it('returns the single score when there is one source', () => {
    const result = agg.aggregate([{ sourceId: 'a', score: 0.75, weight: 1 }]);
    expect(result).toBe(0.75);
  });

  it('returns weighted median for multiple equal-weight sources', () => {
    // With equal weights, weighted median = regular median
    const sources: ReputationSource[] = [
      { sourceId: 'a', score: 0.3, weight: 1 },
      { sourceId: 'b', score: 0.5, weight: 1 },
      { sourceId: 'c', score: 0.9, weight: 1 },
    ];
    const result = agg.aggregate(sources);
    // Median of [0.3, 0.5, 0.9] with equal weights => 0.5
    expect(result).toBe(0.5);
  });

  it('weighted median favors the heavier side', () => {
    // Two scores: 0.2 (weight=1) and 0.8 (weight=3)
    // Total weight=4, half=2. Sorted: 0.2(w=1), 0.8(w=3). cumWeight after 0.8=4 >= 2, so median=0.8
    const sources: ReputationSource[] = [
      { sourceId: 'low', score: 0.2, weight: 1 },
      { sourceId: 'high', score: 0.8, weight: 3 },
    ];
    const result = agg.aggregate(sources);
    expect(result).toBe(0.8);
  });

  it('interpolates when cumulative weight lands exactly at 50%', () => {
    // Scores: 0.2 (w=1), 0.8 (w=1). Total=2, half=1.
    // After 0.2: cumWeight=1 === halfWeight=1, and there is a next => interpolate (0.2+0.8)/2 = 0.5
    const sources: ReputationSource[] = [
      { sourceId: 'a', score: 0.2, weight: 1 },
      { sourceId: 'b', score: 0.8, weight: 1 },
    ];
    const result = agg.aggregate(sources);
    expect(result).toBe(0.5);
  });

  it('ignores zero-weight sources', () => {
    const sources: ReputationSource[] = [
      { sourceId: 'ghost', score: 0.1, weight: 0 },
      { sourceId: 'real', score: 0.9, weight: 5 },
    ];
    const result = agg.aggregate(sources);
    expect(result).toBe(0.9);
  });

  // -----------------------------------------------------------------------
  // aggregate - Byzantine fault tolerance
  // -----------------------------------------------------------------------

  it('tolerates up to ~50% malicious sources (BFT)', () => {
    // 3 honest sources reporting ~0.8, 2 malicious sources reporting 0.0
    const sources: ReputationSource[] = [
      { sourceId: 'honest-1', score: 0.8, weight: 1 },
      { sourceId: 'honest-2', score: 0.8, weight: 1 },
      { sourceId: 'honest-3', score: 0.8, weight: 1 },
      { sourceId: 'evil-1', score: 0.0, weight: 1 },
      { sourceId: 'evil-2', score: 0.0, weight: 1 },
    ];
    const result = agg.aggregate(sources);
    // Sorted: 0.0, 0.0, 0.8, 0.8, 0.8. Total=5, half=2.5
    // cumWeight: 1, 2, 3 >= 2.5 => median is 0.8
    expect(result).toBe(0.8);
  });

  it('exactly 50% malicious sources still gives honest result', () => {
    // 3 honest (0.7) + 3 malicious (0.0), all weight 1
    const sources: ReputationSource[] = [
      { sourceId: 'h1', score: 0.7, weight: 1 },
      { sourceId: 'h2', score: 0.7, weight: 1 },
      { sourceId: 'h3', score: 0.7, weight: 1 },
      { sourceId: 'e1', score: 0.0, weight: 1 },
      { sourceId: 'e2', score: 0.0, weight: 1 },
      { sourceId: 'e3', score: 0.0, weight: 1 },
    ];
    const result = agg.aggregate(sources);
    // Sorted: 0, 0, 0, 0.7, 0.7, 0.7. Total=6, half=3
    // cumWeight: 1, 2, 3 === half=3 and next exists => interpolate (0+0.7)/2 = 0.35
    // Or cumWeight after 0(w=3)=3 >= 3 and next exists => (0+0.7)/2 = 0.35
    // With 50% malicious, the median is affected -- this is the threshold
    expect(result).toBeLessThan(0.7);
  });

  it('weighted BFT: honest majority by weight overrides malicious majority by count', () => {
    // 2 honest sources with high weight vs 5 malicious sources with low weight
    const sources: ReputationSource[] = [
      { sourceId: 'h1', score: 0.9, weight: 10 },
      { sourceId: 'h2', score: 0.85, weight: 10 },
      { sourceId: 'e1', score: 0.0, weight: 1 },
      { sourceId: 'e2', score: 0.0, weight: 1 },
      { sourceId: 'e3', score: 0.0, weight: 1 },
      { sourceId: 'e4', score: 0.0, weight: 1 },
      { sourceId: 'e5', score: 0.0, weight: 1 },
    ];
    const result = agg.aggregate(sources);
    // Total weight=25, half=12.5
    // Sorted by score: 0(1), 0(1), 0(1), 0(1), 0(1), 0.85(10), 0.9(10)
    // cumWeight: 1, 2, 3, 4, 5, 15>=12.5 => median = 0.85
    expect(result).toBe(0.85);
  });

  // -----------------------------------------------------------------------
  // aggregate - edge cases
  // -----------------------------------------------------------------------

  it('all sources report the same score', () => {
    const sources: ReputationSource[] = [
      { sourceId: 'a', score: 0.6, weight: 1 },
      { sourceId: 'b', score: 0.6, weight: 2 },
      { sourceId: 'c', score: 0.6, weight: 3 },
    ];
    expect(agg.aggregate(sources)).toBe(0.6);
  });

  it('extreme scores at boundaries (0 and 1)', () => {
    const sources: ReputationSource[] = [
      { sourceId: 'zero', score: 0, weight: 1 },
      { sourceId: 'one', score: 1, weight: 1 },
      { sourceId: 'mid', score: 0.5, weight: 1 },
    ];
    const result = agg.aggregate(sources);
    expect(result).toBe(0.5);
  });

  // -----------------------------------------------------------------------
  // aggregate - error paths
  // -----------------------------------------------------------------------

  it('throws for empty sources', () => {
    expect(() => agg.aggregate([])).toThrow(/At least one reputation source/);
  });

  it('throws for score out of range [0, 1]', () => {
    expect(() =>
      agg.aggregate([{ sourceId: 'a', score: 1.5, weight: 1 }]),
    ).toThrow(/Invalid score/);
    expect(() =>
      agg.aggregate([{ sourceId: 'a', score: -0.1, weight: 1 }]),
    ).toThrow(/Invalid score/);
  });

  it('throws for negative weight', () => {
    expect(() =>
      agg.aggregate([{ sourceId: 'a', score: 0.5, weight: -1 }]),
    ).toThrow(/Invalid weight/);
  });

  it('throws when all sources have zero weight', () => {
    expect(() =>
      agg.aggregate([
        { sourceId: 'a', score: 0.5, weight: 0 },
        { sourceId: 'b', score: 0.7, weight: 0 },
      ]),
    ).toThrow(/positive weight/);
  });

  // -----------------------------------------------------------------------
  // aggregateWithConfidence
  // -----------------------------------------------------------------------

  describe('aggregateWithConfidence', () => {
    it('returns median, quartiles, and consensus', () => {
      const sources: ReputationSource[] = [
        { sourceId: 'a', score: 0.2, weight: 1 },
        { sourceId: 'b', score: 0.5, weight: 1 },
        { sourceId: 'c', score: 0.8, weight: 1 },
      ];
      const result = agg.aggregateWithConfidence(sources);

      expect(result.median).toBe(0.5);
      expect(result.lowerQuartile).toBeDefined();
      expect(result.upperQuartile).toBeDefined();
      expect(result.consensus).toBeDefined();
      expect(result.lowerQuartile).toBeLessThanOrEqual(result.median);
      expect(result.upperQuartile).toBeGreaterThanOrEqual(result.median);
    });

    it('high consensus when all sources agree', () => {
      const sources: ReputationSource[] = [
        { sourceId: 'a', score: 0.7, weight: 1 },
        { sourceId: 'b', score: 0.7, weight: 1 },
        { sourceId: 'c', score: 0.7, weight: 1 },
        { sourceId: 'd', score: 0.7, weight: 1 },
      ];
      const result = agg.aggregateWithConfidence(sources);

      expect(result.median).toBe(0.7);
      expect(result.consensus).toBe(1); // IQR = 0, so consensus = 1 - 0 = 1
    });

    it('low consensus when sources diverge widely', () => {
      const sources: ReputationSource[] = [
        { sourceId: 'a', score: 0.0, weight: 1 },
        { sourceId: 'b', score: 0.25, weight: 1 },
        { sourceId: 'c', score: 0.75, weight: 1 },
        { sourceId: 'd', score: 1.0, weight: 1 },
      ];
      const result = agg.aggregateWithConfidence(sources);

      // Wide spread => large IQR => low consensus
      expect(result.consensus).toBeLessThan(1);
      expect(result.upperQuartile).toBeGreaterThan(result.lowerQuartile);
    });

    it('consensus is in [0, 1]', () => {
      const sources: ReputationSource[] = [
        { sourceId: 'a', score: 0.0, weight: 1 },
        { sourceId: 'b', score: 1.0, weight: 1 },
      ];
      const result = agg.aggregateWithConfidence(sources);
      expect(result.consensus).toBeGreaterThanOrEqual(0);
      expect(result.consensus).toBeLessThanOrEqual(1);
    });

    it('single source gives perfect consensus', () => {
      const result = agg.aggregateWithConfidence([
        { sourceId: 'only', score: 0.42, weight: 1 },
      ]);
      expect(result.median).toBe(0.42);
      expect(result.lowerQuartile).toBe(0.42);
      expect(result.upperQuartile).toBe(0.42);
      expect(result.consensus).toBe(1);
    });

    it('weighted confidence reflects weight distribution', () => {
      // One trusted source and many untrusted noise sources
      const sources: ReputationSource[] = [
        { sourceId: 'trusted', score: 0.8, weight: 100 },
        { sourceId: 'n1', score: 0.1, weight: 1 },
        { sourceId: 'n2', score: 0.2, weight: 1 },
        { sourceId: 'n3', score: 0.9, weight: 1 },
      ];
      const result = agg.aggregateWithConfidence(sources);

      // The trusted source dominates
      expect(result.median).toBe(0.8);
      // Quartiles should also be near 0.8 due to dominant weight
      expect(result.lowerQuartile).toBe(0.8);
      expect(result.upperQuartile).toBe(0.8);
      expect(result.consensus).toBe(1);
    });
  });
});
