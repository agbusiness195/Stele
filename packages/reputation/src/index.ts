import {
  sha256String,
  sha256Object,
  signString,
  verify,
  toHex,
  fromHex,
  timestamp,
} from '@stele/crypto';
import type { KeyPair, HashHex } from '@stele/crypto';
import type { Severity } from '@stele/ccl';
import { SteleError, SteleErrorCode } from '@stele/types';

export type {
  ExecutionReceipt,
  ReputationScore,
  ReputationStake,
  ReputationDelegation,
  Endorsement,
  ScoringConfig,
  ResourcePool,
  SlashingEvent,
  TrustDimension,
  MultidimensionalProfile,
  StakeTier,
  StakeTierConfig,
  StakedAgent,
} from './types.js';

import type {
  ExecutionReceipt,
  ReputationScore,
  ReputationStake,
  ReputationDelegation,
  Endorsement,
  ScoringConfig,
  ResourcePool,
  SlashingEvent,
  TrustDimension,
  MultidimensionalProfile,
  StakeTier,
  StakeTierConfig,
  StakedAgent,
} from './types.js';

// ---------------------------------------------------------------------------
// Default scoring configuration
// ---------------------------------------------------------------------------

/**
 * Default configuration for the reputation scoring algorithm.
 *
 * - recencyDecay: exponential decay base per recencyPeriod (0.95)
 * - recencyPeriod: decay period in seconds (86400 = 1 day)
 * - breachPenalty: per-severity penalty subtracted from outcome score
 * - minimumExecutions: below this threshold the score is scaled down
 * - endorsementWeight: blending factor for endorsement contribution
 */
export const DEFAULT_SCORING_CONFIG: ScoringConfig = {
  recencyDecay: 0.95,
  recencyPeriod: 86400,
  breachPenalty: {
    critical: 0.5,
    high: 0.3,
    medium: 0.15,
    low: 0.05,
  },
  minimumExecutions: 10,
  endorsementWeight: 0.15,
};

// ---------------------------------------------------------------------------
// Named scoring constants
// ---------------------------------------------------------------------------

/**
 * Outcome score values assigned to each execution result type.
 * Used when computing weighted reputation scores from execution receipts.
 */
const OUTCOME_SCORES = {
  /** A fully fulfilled covenant earns the maximum score. */
  FULFILLED: 1.0,
  /** A partially fulfilled covenant earns half credit. */
  PARTIAL: 0.5,
  /** A failed covenant earns zero credit. */
  FAILED: 0.0,
  /** Fallback breach penalty when no severity-specific penalty is configured. */
  DEFAULT_BREACH_PENALTY: 0.15,
} as const;

/**
 * Base severity scores for the graduated burn penalty curve.
 * Maps breach severity to a normalised [0, 1] score used as input
 * to the burn-fraction calculation.
 */
const SEVERITY_SCORES = {
  /** Critical breaches receive the maximum severity score. */
  CRITICAL: 1.0,
  /** High-severity breaches. */
  HIGH: 0.75,
  /** Medium-severity breaches. */
  MEDIUM: 0.5,
  /** Low-severity breaches. */
  LOW: 0.25,
  /** Default for unknown severity levels. */
  DEFAULT: 0.5,
} as const;

/**
 * Blending weights for DAG reputation propagation at merge points.
 * When a DAG node has parents, its score is a blend of its own
 * receipt score and the average of its parents' scores.
 */
const DAG_BLEND_WEIGHTS = {
  /** Weight given to the current node's own receipt score. */
  SELF: 0.6,
  /** Weight given to the averaged parent scores. */
  PARENT: 0.4,
} as const;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Build the hashable content object for a receipt.
 * Includes every field except id, agentSignature, principalSignature,
 * and receiptHash (the four derived/mutable fields).
 *
 * The object is fed into sha256Object which canonicalises key order
 * internally, so insertion order here does not affect the hash.
 */
function buildReceiptContent(params: {
  covenantId: HashHex;
  agentIdentityHash: HashHex;
  principalPublicKey: string;
  outcome: ExecutionReceipt['outcome'];
  breachSeverity?: Severity;
  proofHash: HashHex;
  durationMs: number;
  completedAt: string;
  previousReceiptHash: HashHex | null;
}): Record<string, unknown> {
  const content: Record<string, unknown> = {
    covenantId: params.covenantId,
    agentIdentityHash: params.agentIdentityHash,
    principalPublicKey: params.principalPublicKey,
    outcome: params.outcome,
    proofHash: params.proofHash,
    durationMs: params.durationMs,
    completedAt: params.completedAt,
    previousReceiptHash: params.previousReceiptHash,
  };
  if (params.breachSeverity !== undefined) {
    content.breachSeverity = params.breachSeverity;
  }
  return content;
}

/**
 * Build the hashable content object for a stake.
 * Excludes id and signature.
 */
function buildStakeContent(params: {
  agentIdentityHash: HashHex;
  covenantId: HashHex;
  amount: number;
  status: ReputationStake['status'];
  stakedAt: string;
}): Record<string, unknown> {
  return {
    agentIdentityHash: params.agentIdentityHash,
    covenantId: params.covenantId,
    amount: params.amount,
    status: params.status,
    stakedAt: params.stakedAt,
  };
}

/**
 * Build the hashable content object for a delegation.
 * Excludes id, sponsorSignature, and protégéSignature.
 */
function buildDelegationContent(params: {
  sponsorIdentityHash: HashHex;
  protégéIdentityHash: HashHex;
  riskAmount: number;
  scopes: string[];
  expiresAt: string;
  status: ReputationDelegation['status'];
}): Record<string, unknown> {
  return {
    sponsorIdentityHash: params.sponsorIdentityHash,
    protégéIdentityHash: params.protégéIdentityHash,
    riskAmount: params.riskAmount,
    scopes: params.scopes,
    expiresAt: params.expiresAt,
    status: params.status,
  };
}

/**
 * Build the hashable content object for an endorsement.
 * Excludes id and signature.
 */
function buildEndorsementContent(params: {
  endorserIdentityHash: HashHex;
  endorsedIdentityHash: HashHex;
  basis: Endorsement['basis'];
  scopes: string[];
  weight: number;
  issuedAt: string;
}): Record<string, unknown> {
  return {
    endorserIdentityHash: params.endorserIdentityHash,
    endorsedIdentityHash: params.endorsedIdentityHash,
    basis: params.basis,
    scopes: params.scopes,
    weight: params.weight,
    issuedAt: params.issuedAt,
  };
}

// ---------------------------------------------------------------------------
// Execution Receipts
// ---------------------------------------------------------------------------

/**
 * Create a new execution receipt, signed by the agent.
 *
 * The receiptHash is computed as sha256Object of all content fields
 * (excluding id, agentSignature, principalSignature, and receiptHash
 * itself). The id is set equal to the receiptHash. The agent signs
 * the receiptHash string with their private key.
 *
 * @param covenantId          - ID of the covenant that was executed.
 * @param agentIdentityHash   - Identity hash of the executing agent.
 * @param principalPublicKey  - Hex-encoded public key of the principal.
 * @param outcome             - Execution outcome.
 * @param proofHash           - Hash of the compliance proof.
 * @param durationMs          - Execution duration in milliseconds.
 * @param agentKeyPair        - Agent's key pair used to sign the receipt.
 * @param previousReceiptHash - Hash of the previous receipt in the chain (null for first).
 * @param breachSeverity      - Severity of breach (required when outcome is 'breached').
 * @returns A complete, signed ExecutionReceipt.
 */
export async function createReceipt(
  covenantId: HashHex,
  agentIdentityHash: HashHex,
  principalPublicKey: string,
  outcome: ExecutionReceipt['outcome'],
  proofHash: HashHex,
  durationMs: number,
  agentKeyPair: KeyPair,
  previousReceiptHash: HashHex | null = null,
  breachSeverity?: Severity,
): Promise<ExecutionReceipt> {
  const completedAt = timestamp();

  const content = buildReceiptContent({
    covenantId,
    agentIdentityHash,
    principalPublicKey,
    outcome,
    breachSeverity,
    proofHash,
    durationMs,
    completedAt,
    previousReceiptHash,
  });

  const receiptHash = sha256Object(content);
  const id = receiptHash;

  const signatureBytes = await signString(receiptHash, agentKeyPair.privateKey);
  const agentSignature = toHex(signatureBytes);

  const receipt: ExecutionReceipt = {
    id,
    covenantId,
    agentIdentityHash,
    principalPublicKey,
    outcome,
    ...(breachSeverity !== undefined ? { breachSeverity } : {}),
    proofHash,
    durationMs,
    completedAt,
    agentSignature,
    previousReceiptHash,
    receiptHash,
  };

  return receipt;
}

/**
 * Verify a receipt's integrity and agent signature.
 *
 * Performs two checks:
 *  1. The receiptHash matches the SHA-256 of the receipt's content fields.
 *  2. The agentSignature is a valid Ed25519 signature over the
 *     receiptHash, verified against the agentIdentityHash as the
 *     public key.
 *
 * Note: if agentIdentityHash is a composite identity hash (rather
 * than a raw public key hex), signature verification will return false.
 * In that case, callers should resolve the agent's actual public key
 * and perform signature verification separately.
 */
export async function verifyReceipt(receipt: ExecutionReceipt): Promise<boolean> {
  // 1. Verify receiptHash matches content
  const content = buildReceiptContent({
    covenantId: receipt.covenantId,
    agentIdentityHash: receipt.agentIdentityHash,
    principalPublicKey: receipt.principalPublicKey,
    outcome: receipt.outcome,
    breachSeverity: receipt.breachSeverity,
    proofHash: receipt.proofHash,
    durationMs: receipt.durationMs,
    completedAt: receipt.completedAt,
    previousReceiptHash: receipt.previousReceiptHash,
  });

  const expectedHash = sha256Object(content);
  if (expectedHash !== receipt.receiptHash) {
    return false;
  }

  // 2. Verify agent signature over the receiptHash
  try {
    const messageBytes = new TextEncoder().encode(receipt.receiptHash);
    const sigBytes = fromHex(receipt.agentSignature);
    const pubKeyBytes = fromHex(receipt.agentIdentityHash);
    return await verify(messageBytes, sigBytes, pubKeyBytes);
  } catch {
    return false;
  }
}

/**
 * Countersign a receipt with the principal's key pair.
 *
 * The principal signs the receiptHash string, producing a signature
 * that can be verified against principalPublicKey. Returns a new
 * receipt object with the principalSignature field set; the original
 * receipt is not mutated.
 */
export async function countersignReceipt(
  receipt: ExecutionReceipt,
  principalKeyPair: KeyPair,
): Promise<ExecutionReceipt> {
  const signatureBytes = await signString(receipt.receiptHash, principalKeyPair.privateKey);
  return {
    ...receipt,
    principalSignature: toHex(signatureBytes),
  };
}

// ---------------------------------------------------------------------------
// Receipt Chain Verification
// ---------------------------------------------------------------------------

/**
 * Verify that an ordered array of receipts forms a valid hash chain.
 *
 * Rules:
 * - The first receipt must have previousReceiptHash === null.
 * - Each subsequent receipt's previousReceiptHash must equal the
 *   preceding receipt's receiptHash.
 *
 * An empty array is considered a valid (trivial) chain.
 */
export function verifyReceiptChain(receipts: ExecutionReceipt[]): boolean {
  if (receipts.length === 0) {
    return true;
  }

  // First receipt must anchor the chain with a null previous hash
  if (receipts[0]!.previousReceiptHash !== null) {
    return false;
  }

  for (let i = 1; i < receipts.length; i++) {
    if (receipts[i]!.previousReceiptHash !== receipts[i - 1]!.receiptHash) {
      return false;
    }
  }

  return true;
}

// ---------------------------------------------------------------------------
// Merkle Root
// ---------------------------------------------------------------------------

/**
 * Compute a Merkle root from an array of execution receipts.
 *
 * Leaf nodes are the receiptHash values. Pairs of hashes are
 * concatenated (left + right) and fed through SHA-256 to produce
 * parent nodes. If a level has an odd number of nodes the last
 * node is duplicated before pairing.
 *
 * An empty array produces sha256String('') as the root.
 */
export function computeReceiptsMerkleRoot(receipts: ExecutionReceipt[]): HashHex {
  if (receipts.length === 0) {
    return sha256String('');
  }

  let level: HashHex[] = receipts.map((r) => r.receiptHash);

  while (level.length > 1) {
    const nextLevel: HashHex[] = [];

    // Duplicate last node if odd count
    if (level.length % 2 !== 0) {
      level.push(level[level.length - 1]!);
    }

    for (let i = 0; i < level.length; i += 2) {
      nextLevel.push(sha256String(level[i]! + level[i + 1]!));
    }

    level = nextLevel;
  }

  return level[0]!;
}

// ---------------------------------------------------------------------------
// Reputation Scoring
// ---------------------------------------------------------------------------

/**
 * Compute a comprehensive reputation score for an agent based on
 * their execution receipts and optional endorsements.
 *
 * Algorithm:
 *  1. Count outcomes (fulfilled, partial, failed, breached).
 *  2. For each receipt, compute a recency weight using exponential
 *     decay: weight = recencyDecay ^ (ageSeconds / recencyPeriod).
 *  3. Assign an outcome score to each receipt:
 *       fulfilled = 1.0, partial = 0.5, failed = 0.0,
 *       breached = -(breachPenalty[severity]).
 *  4. Compute the weighted average: sum(weight * score) / sum(weight).
 *  5. If totalExecutions < minimumExecutions, scale the score down
 *     by (totalExecutions / minimumExecutions).
 *  6. If endorsements are provided, blend the score:
 *       final = score * (1 - endorsementWeight) +
 *               endorsementWeight * avgEndorsementWeight.
 *  7. Clamp the result to [0.0, 1.0].
 *
 * The successRate is computed as (fulfilled + partial) / totalExecutions.
 * currentStake and totalBurned are initialised to 0; callers should
 * update these from stake data if available.
 */
export function computeReputationScore(
  agentIdentityHash: HashHex,
  receipts: ExecutionReceipt[],
  endorsements?: Endorsement[],
  config?: ScoringConfig,
): ReputationScore {
  const cfg = config ?? DEFAULT_SCORING_CONFIG;
  const now = Date.now();

  // --- Count outcomes ---
  let fulfilled = 0;
  let partial = 0;
  let failed = 0;
  let breached = 0;

  for (const r of receipts) {
    switch (r.outcome) {
      case 'fulfilled':
        fulfilled++;
        break;
      case 'partial':
        partial++;
        break;
      case 'failed':
        failed++;
        break;
      case 'breached':
        breached++;
        break;
    }
  }

  const totalExecutions = receipts.length;

  // --- Compute weighted score with recency decay ---
  let weightedSum = 0;
  let totalWeight = 0;

  for (const r of receipts) {
    const completedMs = new Date(r.completedAt).getTime();
    const ageSeconds = Math.max(0, (now - completedMs) / 1000);
    const recencyWeight = Math.pow(cfg.recencyDecay, ageSeconds / cfg.recencyPeriod);

    let outcomeScore: number;
    switch (r.outcome) {
      case 'fulfilled':
        outcomeScore = OUTCOME_SCORES.FULFILLED;
        break;
      case 'partial':
        outcomeScore = OUTCOME_SCORES.PARTIAL;
        break;
      case 'failed':
        outcomeScore = OUTCOME_SCORES.FAILED;
        break;
      case 'breached': {
        const severity: Severity = r.breachSeverity ?? 'medium';
        outcomeScore = -(cfg.breachPenalty[severity] ?? OUTCOME_SCORES.DEFAULT_BREACH_PENALTY);
        break;
      }
    }

    weightedSum += recencyWeight * outcomeScore;
    totalWeight += recencyWeight;
  }

  let weightedScore = totalWeight > 0 ? weightedSum / totalWeight : 0;

  // --- Apply minimum executions penalty ---
  if (totalExecutions > 0 && totalExecutions < cfg.minimumExecutions) {
    weightedScore *= totalExecutions / cfg.minimumExecutions;
  }

  // --- Factor in endorsements ---
  if (endorsements && endorsements.length > 0) {
    const avgEndorsementWeight =
      endorsements.reduce((sum, e) => sum + e.weight, 0) / endorsements.length;
    weightedScore =
      weightedScore * (1 - cfg.endorsementWeight) +
      cfg.endorsementWeight * avgEndorsementWeight;
  }

  // --- Clamp to [0, 1] ---
  weightedScore = Math.max(0, Math.min(1, weightedScore));

  // --- Compute Merkle root ---
  const receiptsMerkleRoot = computeReceiptsMerkleRoot(receipts);

  // --- Success rate ---
  const successRate = totalExecutions > 0
    ? (fulfilled + partial) / totalExecutions
    : 0;

  return {
    agentIdentityHash,
    totalExecutions,
    fulfilled,
    partial,
    failed,
    breached,
    successRate,
    weightedScore,
    receiptsMerkleRoot,
    lastUpdatedAt: new Date(now).toISOString(),
    currentStake: 0,
    totalBurned: 0,
  };
}

// ---------------------------------------------------------------------------
// Reputation Stakes
// ---------------------------------------------------------------------------

/**
 * Create a new reputation stake, signed by the agent.
 *
 * A stake represents reputation collateral that the agent puts at
 * risk when executing a covenant. If the agent breaches, the stake
 * may be burned.
 */
export async function createStake(
  agentIdentityHash: HashHex,
  covenantId: HashHex,
  amount: number,
  agentKeyPair: KeyPair,
): Promise<ReputationStake> {
  if (amount < 0 || amount > 1) {
    throw new SteleError(SteleErrorCode.REPUTATION_INVALID_RECEIPT, 'Stake amount must be between 0 and 1');
  }

  const stakedAt = timestamp();

  const content = buildStakeContent({
    agentIdentityHash,
    covenantId,
    amount,
    status: 'active',
    stakedAt,
  });

  const id = sha256Object(content);
  const signatureBytes = await signString(id, agentKeyPair.privateKey);

  return {
    id,
    agentIdentityHash,
    covenantId,
    amount,
    status: 'active',
    stakedAt,
    signature: toHex(signatureBytes),
  };
}

/**
 * Release a stake after covenant execution completes.
 *
 * Returns a new stake object with status='released' and resolvedAt
 * set to the current timestamp. The original stake is not mutated.
 *
 * @param stake   - The active stake to release.
 * @param outcome - The execution outcome (informational).
 */
export function releaseStake(
  stake: ReputationStake,
  _outcome: ExecutionReceipt['outcome'],
): ReputationStake {
  return {
    ...stake,
    status: 'released',
    resolvedAt: timestamp(),
  };
}

/**
 * Burn a stake due to a covenant breach.
 *
 * Returns a new stake object with status='burned' and resolvedAt
 * set to the current timestamp. The original stake is not mutated.
 */
export function burnStake(stake: ReputationStake): ReputationStake {
  return {
    ...stake,
    status: 'burned',
    resolvedAt: timestamp(),
  };
}

// ---------------------------------------------------------------------------
// Reputation Delegation
// ---------------------------------------------------------------------------

/**
 * Create a reputation delegation from a sponsor to a protege.
 *
 * A delegation allows a sponsor to vouch for a protege by putting
 * their own reputation at risk. Both parties must sign the delegation.
 * The id is computed as sha256Object of the content fields, and both
 * the sponsor and protege sign this id.
 *
 * @param sponsorIdentityHash - Identity hash of the sponsoring agent.
 * @param protégéIdentityHash - Identity hash of the protege agent.
 * @param riskAmount          - Amount of reputation at risk.
 * @param scopes              - Scopes the delegation covers.
 * @param expiresAt           - ISO 8601 expiration timestamp.
 * @param sponsorKeyPair      - Sponsor's key pair for signing.
 * @param protégéKeyPair      - Protege's key pair for countersigning.
 */
export async function createDelegation(
  sponsorIdentityHash: HashHex,
  protégéIdentityHash: HashHex,
  riskAmount: number,
  scopes: string[],
  expiresAt: string,
  sponsorKeyPair: KeyPair,
  protégéKeyPair: KeyPair,
): Promise<ReputationDelegation> {
  if (riskAmount < 0 || riskAmount > 1) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'Delegation riskAmount must be between 0 and 1');
  }
  if (scopes.length === 0) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'Delegation must have at least one scope');
  }

  const content = buildDelegationContent({
    sponsorIdentityHash,
    protégéIdentityHash,
    riskAmount,
    scopes,
    expiresAt,
    status: 'active',
  });

  const id = sha256Object(content);

  const sponsorSigBytes = await signString(id, sponsorKeyPair.privateKey);
  const protégéSigBytes = await signString(id, protégéKeyPair.privateKey);

  return {
    id,
    sponsorIdentityHash,
    protégéIdentityHash,
    riskAmount,
    scopes,
    expiresAt,
    status: 'active',
    sponsorSignature: toHex(sponsorSigBytes),
    protégéSignature: toHex(protégéSigBytes),
  };
}

/**
 * Burn a delegation due to a breach by the protege.
 *
 * Returns a new delegation with status='burned'. The original
 * delegation is not mutated.
 */
export function burnDelegation(delegation: ReputationDelegation): ReputationDelegation {
  return {
    ...delegation,
    status: 'burned',
  };
}

/**
 * Co-burn a delegation and compute the reputation impact on both parties.
 * When a protege breaches, both the delegation is burned AND the sponsor
 * loses reputation proportional to riskAmount.
 *
 * Returns the burned delegation plus reputation impact details.
 */
export function coBurnDelegation(
  delegation: ReputationDelegation,
  sponsorScore: ReputationScore,
): {
  burnedDelegation: ReputationDelegation;
  sponsorReputationLoss: number;
  newSponsorBurned: number;
} {
  const burnedDelegation: ReputationDelegation = {
    ...delegation,
    status: 'burned',
  };

  // Sponsor loses reputation proportional to risk amount
  const sponsorReputationLoss = delegation.riskAmount * sponsorScore.weightedScore;
  const newSponsorBurned = sponsorScore.totalBurned + sponsorReputationLoss;

  return {
    burnedDelegation,
    sponsorReputationLoss,
    newSponsorBurned,
  };
}

// ---------------------------------------------------------------------------
// Endorsements
// ---------------------------------------------------------------------------

/**
 * Create a new endorsement, signed by the endorser.
 *
 * An endorsement is a peer attestation about another agent's
 * track record. The endorser signs the id (hash of content fields)
 * with their private key.
 *
 * @param endorserIdentityHash - Identity hash of the endorsing agent.
 * @param endorsedIdentityHash - Identity hash of the endorsed agent.
 * @param basis                - Empirical basis for the endorsement.
 * @param scopes               - Scopes the endorsement covers.
 * @param weight               - Endorsement weight (0.0 to 1.0).
 * @param endorserKeyPair      - Endorser's key pair for signing.
 */
export async function createEndorsement(
  endorserIdentityHash: HashHex,
  endorsedIdentityHash: HashHex,
  basis: Endorsement['basis'],
  scopes: string[],
  weight: number,
  endorserKeyPair: KeyPair,
): Promise<Endorsement> {
  const issuedAt = timestamp();

  // Validate basis
  if (typeof basis.covenantsCompleted !== 'number' || basis.covenantsCompleted < 0) {
    throw new SteleError(SteleErrorCode.REPUTATION_INVALID_RECEIPT, 'Endorsement basis.covenantsCompleted must be a non-negative number');
  }
  if (typeof basis.breachRate !== 'number' || basis.breachRate < 0 || basis.breachRate > 1) {
    throw new SteleError(SteleErrorCode.REPUTATION_INVALID_RECEIPT, 'Endorsement basis.breachRate must be a number between 0 and 1');
  }
  if (basis.averageOutcomeScore !== undefined) {
    if (typeof basis.averageOutcomeScore !== 'number' || basis.averageOutcomeScore < 0 || basis.averageOutcomeScore > 1) {
      throw new SteleError(SteleErrorCode.REPUTATION_INVALID_RECEIPT, 'Endorsement basis.averageOutcomeScore must be a number between 0 and 1');
    }
  }

  // Validate weight
  if (weight < 0 || weight > 1) {
    throw new SteleError(SteleErrorCode.REPUTATION_INVALID_RECEIPT, 'Endorsement weight must be between 0 and 1');
  }

  const content = buildEndorsementContent({
    endorserIdentityHash,
    endorsedIdentityHash,
    basis,
    scopes,
    weight,
    issuedAt,
  });

  const id = sha256Object(content);
  const signatureBytes = await signString(id, endorserKeyPair.privateKey);

  return {
    id,
    endorserIdentityHash,
    endorsedIdentityHash,
    basis,
    scopes,
    weight,
    issuedAt,
    signature: toHex(signatureBytes),
  };
}

/**
 * Verify an endorsement's integrity and signature.
 *
 * Performs two checks:
 *  1. The id matches the SHA-256 of the endorsement's content fields.
 *  2. The signature is a valid Ed25519 signature over the id,
 *     verified against endorserIdentityHash as the public key.
 *
 * Note: if endorserIdentityHash is a composite identity hash (rather
 * than a raw public key hex), signature verification will return false.
 */
export async function verifyEndorsement(endorsement: Endorsement): Promise<boolean> {
  // 1. Recompute the expected id from content
  const content = buildEndorsementContent({
    endorserIdentityHash: endorsement.endorserIdentityHash,
    endorsedIdentityHash: endorsement.endorsedIdentityHash,
    basis: endorsement.basis,
    scopes: endorsement.scopes,
    weight: endorsement.weight,
    issuedAt: endorsement.issuedAt,
  });

  const expectedId = sha256Object(content);
  if (expectedId !== endorsement.id) {
    return false;
  }

  // 2. Verify signature over the id
  try {
    const messageBytes = new TextEncoder().encode(endorsement.id);
    const sigBytes = fromHex(endorsement.signature);
    const pubKeyBytes = fromHex(endorsement.endorserIdentityHash);
    return await verify(messageBytes, sigBytes, pubKeyBytes);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// DAG-Based Receipt Chain
// ---------------------------------------------------------------------------

/** A node in the receipt DAG, supporting multiple parents for concurrent execution. */
export interface ReceiptDAGNode {
  /** The receipt hash serving as node identifier. */
  receiptHash: HashHex;
  /** Parent receipt hashes (empty for root nodes). */
  parentHashes: HashHex[];
  /** The execution receipt associated with this node. */
  receipt: ExecutionReceipt;
}

/**
 * A directed acyclic graph of execution receipts supporting concurrent
 * execution paths.
 *
 * Unlike a linear chain where each receipt points to one predecessor,
 * a DAG allows multiple parents per node (merge points where concurrent
 * executions rejoin) and multiple children per node (fork points where
 * execution branches).
 *
 * This enables accurate reputation tracking when an agent is executing
 * multiple covenants concurrently.
 */
export class ReceiptDAG {
  private readonly nodes: Map<HashHex, ReceiptDAGNode> = new Map();
  private readonly children: Map<HashHex, Set<HashHex>> = new Map();

  /**
   * Add a receipt to the DAG.
   * @param receipt - The execution receipt.
   * @param parentHashes - Hashes of parent receipts (empty for root nodes).
   * @throws SteleError if any parent hash is not in the DAG.
   */
  addNode(receipt: ExecutionReceipt, parentHashes: HashHex[] = []): void {
    if (this.nodes.has(receipt.receiptHash)) {
      throw new SteleError(
        `Receipt ${receipt.receiptHash} already exists in DAG`,
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    for (const parentHash of parentHashes) {
      if (!this.nodes.has(parentHash)) {
        throw new SteleError(
          `Parent receipt ${parentHash} not found in DAG`,
          SteleErrorCode.PROTOCOL_INVALID_INPUT,
        );
      }
    }

    const node: ReceiptDAGNode = {
      receiptHash: receipt.receiptHash,
      parentHashes: [...parentHashes],
      receipt,
    };
    this.nodes.set(receipt.receiptHash, node);

    // Update children index
    if (!this.children.has(receipt.receiptHash)) {
      this.children.set(receipt.receiptHash, new Set());
    }
    for (const parentHash of parentHashes) {
      let childSet = this.children.get(parentHash);
      if (!childSet) {
        childSet = new Set();
        this.children.set(parentHash, childSet);
      }
      childSet.add(receipt.receiptHash);
    }
  }

  /** Get a node by receipt hash, or undefined. */
  getNode(hash: HashHex): ReceiptDAGNode | undefined {
    const node = this.nodes.get(hash);
    if (!node) return undefined;
    return { ...node, parentHashes: [...node.parentHashes] };
  }

  /** Get all root nodes (nodes with no parents). */
  getRoots(): HashHex[] {
    const roots: HashHex[] = [];
    for (const node of this.nodes.values()) {
      if (node.parentHashes.length === 0) {
        roots.push(node.receiptHash);
      }
    }
    return roots;
  }

  /** Get all leaf nodes (nodes with no children). */
  getLeaves(): HashHex[] {
    const leaves: HashHex[] = [];
    for (const hash of this.nodes.keys()) {
      const childSet = this.children.get(hash);
      if (!childSet || childSet.size === 0) {
        leaves.push(hash);
      }
    }
    return leaves;
  }

  /** Total number of nodes in the DAG. */
  get size(): number {
    return this.nodes.size;
  }

  /**
   * Find the lowest common ancestors (LCAs) of two nodes.
   *
   * Uses the standard algorithm: walk backwards from both nodes,
   * tracking all ancestors of each. The LCA is the first node
   * that appears in both ancestor sets.
   *
   * @returns Array of common ancestor hashes, or empty if none exist.
   */
  findCommonAncestors(hashA: HashHex, hashB: HashHex): HashHex[] {
    if (!this.nodes.has(hashA)) {
      throw new SteleError(
        `Node ${hashA} not found in DAG`,
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!this.nodes.has(hashB)) {
      throw new SteleError(
        `Node ${hashB} not found in DAG`,
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    if (hashA === hashB) return [hashA];

    // Collect all ancestors of A (including A itself)
    const ancestorsA = new Set<HashHex>();
    const queueA: HashHex[] = [hashA];
    while (queueA.length > 0) {
      const current = queueA.shift()!;
      if (ancestorsA.has(current)) continue;
      ancestorsA.add(current);
      const node = this.nodes.get(current);
      if (node) {
        for (const parent of node.parentHashes) {
          queueA.push(parent);
        }
      }
    }

    // Walk ancestors of B; collect those that are also ancestors of A
    const commonAncestors: HashHex[] = [];
    const ancestorsB = new Set<HashHex>();
    const queueB: HashHex[] = [hashB];
    while (queueB.length > 0) {
      const current = queueB.shift()!;
      if (ancestorsB.has(current)) continue;
      ancestorsB.add(current);
      if (ancestorsA.has(current)) {
        commonAncestors.push(current);
      }
      const node = this.nodes.get(current);
      if (node) {
        for (const parent of node.parentHashes) {
          queueB.push(parent);
        }
      }
    }

    // Filter to only lowest common ancestors (not ancestors of other LCAs)
    // An LCA is a common ancestor that is not an ancestor of any other common ancestor
    const lcaSet = new Set(commonAncestors);
    const result: HashHex[] = [];
    for (const ca of commonAncestors) {
      let isLowest = true;
      for (const other of commonAncestors) {
        if (other === ca) continue;
        // Check if ca is an ancestor of other
        if (this.isAncestor(ca, other)) {
          isLowest = false;
          break;
        }
      }
      if (isLowest) {
        result.push(ca);
      }
    }

    return result.length > 0 ? result : commonAncestors;
  }

  /**
   * Check if potentialAncestor is an ancestor of node.
   */
  private isAncestor(potentialAncestor: HashHex, node: HashHex): boolean {
    const visited = new Set<HashHex>();
    const queue: HashHex[] = [node];
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current === potentialAncestor) return true;
      if (visited.has(current)) continue;
      visited.add(current);
      const n = this.nodes.get(current);
      if (n) {
        for (const parent of n.parentHashes) {
          queue.push(parent);
        }
      }
    }
    return false;
  }

  /**
   * Compute reputation across all parallel branches using a topological
   * traversal of the DAG. At merge points, scores from parallel branches
   * are averaged (weighted by branch length).
   *
   * @param config - Scoring configuration.
   * @returns Weighted reputation score in [0, 1].
   */
  computeDAGReputation(config?: ScoringConfig): number {
    const cfg = config ?? DEFAULT_SCORING_CONFIG;
    if (this.nodes.size === 0) return 0;

    // Topological sort via Kahn's algorithm
    const inDegree = new Map<HashHex, number>();
    for (const [hash, node] of this.nodes) {
      inDegree.set(hash, node.parentHashes.length);
    }

    const queue: HashHex[] = [];
    for (const [hash, deg] of inDegree) {
      if (deg === 0) queue.push(hash);
    }

    const sorted: HashHex[] = [];
    while (queue.length > 0) {
      const current = queue.shift()!;
      sorted.push(current);
      const childSet = this.children.get(current);
      if (childSet) {
        for (const child of childSet) {
          const newDeg = (inDegree.get(child) ?? 1) - 1;
          inDegree.set(child, newDeg);
          if (newDeg === 0) queue.push(child);
        }
      }
    }

    // Compute per-node score and propagate through the DAG
    const nodeScores = new Map<HashHex, number>();
    const now = Date.now();

    for (const hash of sorted) {
      const node = this.nodes.get(hash)!;
      const receipt = node.receipt;

      // Compute this receipt's score
      const completedMs = new Date(receipt.completedAt).getTime();
      const ageSeconds = Math.max(0, (now - completedMs) / 1000);
      const recencyWeight = Math.pow(cfg.recencyDecay, ageSeconds / cfg.recencyPeriod);

      let outcomeScore: number;
      switch (receipt.outcome) {
        case 'fulfilled':
          outcomeScore = OUTCOME_SCORES.FULFILLED;
          break;
        case 'partial':
          outcomeScore = OUTCOME_SCORES.PARTIAL;
          break;
        case 'failed':
          outcomeScore = OUTCOME_SCORES.FAILED;
          break;
        case 'breached': {
          const sev: Severity = receipt.breachSeverity ?? 'medium';
          outcomeScore = -(cfg.breachPenalty[sev] ?? OUTCOME_SCORES.DEFAULT_BREACH_PENALTY);
          break;
        }
      }

      let score = recencyWeight * outcomeScore;

      // At merge points, blend with parent scores
      if (node.parentHashes.length > 0) {
        let parentSum = 0;
        let parentCount = 0;
        for (const parentHash of node.parentHashes) {
          const parentScore = nodeScores.get(parentHash);
          if (parentScore !== undefined) {
            parentSum += parentScore;
            parentCount++;
          }
        }
        if (parentCount > 0) {
          const parentAvg = parentSum / parentCount;
          score = DAG_BLEND_WEIGHTS.SELF * score + DAG_BLEND_WEIGHTS.PARENT * parentAvg;
        }
      }

      nodeScores.set(hash, score);
    }

    // Final score: average of all leaf node scores
    const leaves = this.getLeaves();
    if (leaves.length === 0) return 0;

    let totalScore = 0;
    for (const leaf of leaves) {
      totalScore += nodeScores.get(leaf) ?? 0;
    }

    return Math.max(0, Math.min(1, totalScore / leaves.length));
  }
}

// ---------------------------------------------------------------------------
// Multi-Model Decay
// ---------------------------------------------------------------------------

/** Supported decay function types. */
export type DecayModelType = 'exponential' | 'weibull' | 'gamma';

/** Configuration for a reputation decay model. */
export interface DecayModelConfig {
  /** The decay function type. */
  model: DecayModelType;
  /**
   * Parameters specific to the chosen model:
   * - exponential: { lambda: number } where decay = e^(-lambda * t)
   * - weibull: { k: number; lambda: number } where decay = e^(-(t/lambda)^k)
   * - gamma: { alpha: number; beta: number } where decay approximated via incomplete gamma
   */
  params: Record<string, number>;
}

/**
 * Computes reputation decay using different statistical distributions.
 *
 * Supports three models:
 * - **Exponential**: Constant hazard rate. Reputation decays at the same
 *   rate regardless of age. Simple but may not capture real-world patterns.
 * - **Weibull**: Flexible hazard rate. k < 1 gives decreasing hazard
 *   (early reputation matters more), k > 1 gives increasing hazard
 *   (old reputation decays faster).
 * - **Gamma**: The decay follows a gamma-distribution-shaped curve,
 *   allowing a peak in "relevance" at some intermediate age.
 */
export class ReputationDecayModel {
  private readonly modelType: DecayModelType;
  private readonly params: Record<string, number>;

  constructor(config: DecayModelConfig) {
    this.modelType = config.model;
    this.params = { ...config.params };

    switch (this.modelType) {
      case 'exponential': {
        const lambda = this.params['lambda'];
        if (lambda === undefined || lambda <= 0) {
          throw new SteleError(
            'Exponential decay requires lambda > 0',
            SteleErrorCode.PROTOCOL_INVALID_INPUT,
          );
        }
        break;
      }
      case 'weibull': {
        const k = this.params['k'];
        const lambda = this.params['lambda'];
        if (k === undefined || k <= 0) {
          throw new SteleError(
            'Weibull decay requires k > 0',
            SteleErrorCode.PROTOCOL_INVALID_INPUT,
          );
        }
        if (lambda === undefined || lambda <= 0) {
          throw new SteleError(
            'Weibull decay requires lambda > 0',
            SteleErrorCode.PROTOCOL_INVALID_INPUT,
          );
        }
        break;
      }
      case 'gamma': {
        const alpha = this.params['alpha'];
        const beta = this.params['beta'];
        if (alpha === undefined || alpha <= 0) {
          throw new SteleError(
            'Gamma decay requires alpha > 0',
            SteleErrorCode.PROTOCOL_INVALID_INPUT,
          );
        }
        if (beta === undefined || beta <= 0) {
          throw new SteleError(
            'Gamma decay requires beta > 0',
            SteleErrorCode.PROTOCOL_INVALID_INPUT,
          );
        }
        break;
      }
      default:
        throw new SteleError(
          `Unknown decay model: ${config.model}`,
          SteleErrorCode.PROTOCOL_INVALID_INPUT,
        );
    }
  }

  /**
   * Compute the decay factor at time t.
   * @param t - Time elapsed (in the same units used to configure the model). Must be >= 0.
   * @returns A decay factor in [0, 1] where 1 = fully preserved, 0 = fully decayed.
   */
  decay(t: number): number {
    if (t < 0) {
      throw new SteleError(
        'Time t must be non-negative',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (t === 0) return 1;

    switch (this.modelType) {
      case 'exponential': {
        const lambda = this.params['lambda']!;
        return Math.exp(-lambda * t);
      }
      case 'weibull': {
        const k = this.params['k']!;
        const lambda = this.params['lambda']!;
        return Math.exp(-Math.pow(t / lambda, k));
      }
      case 'gamma': {
        // Use the survival function of the gamma distribution:
        // S(t) = 1 - P(alpha, beta*t) where P is the regularized lower incomplete gamma
        const alpha = this.params['alpha']!;
        const beta = this.params['beta']!;
        return 1 - regularizedGammaP(alpha, beta * t);
      }
    }
  }

  /**
   * Apply decay to a reputation score.
   * @param score - Current reputation score.
   * @param t - Time elapsed.
   * @returns Decayed reputation score.
   */
  apply(score: number, t: number): number {
    return score * this.decay(t);
  }

  /** The model type. */
  get type(): DecayModelType {
    return this.modelType;
  }
}

/**
 * Regularized lower incomplete gamma function P(a, x).
 * Uses series expansion for small x, continued fraction for large x.
 * This is a standard numerical approximation.
 */
function regularizedGammaP(a: number, x: number): number {
  if (x < 0) return 0;
  if (x === 0) return 0;

  // Use series expansion: P(a,x) = e^(-x) * x^a * sum(x^n / gamma(a+n+1))
  if (x < a + 1) {
    return gammaPSeries(a, x);
  } else {
    // Use continued fraction for large x
    return 1 - gammaQContinuedFraction(a, x);
  }
}

/** Series expansion for regularized lower incomplete gamma. */
function gammaPSeries(a: number, x: number): number {
  const maxIterations = 200;
  const epsilon = 1e-10;

  let sum = 1 / a;
  let term = 1 / a;

  for (let n = 1; n < maxIterations; n++) {
    term *= x / (a + n);
    sum += term;
    if (Math.abs(term) < Math.abs(sum) * epsilon) break;
  }

  return sum * Math.exp(-x + a * Math.log(x) - lnGamma(a));
}

/** Continued fraction for upper incomplete gamma Q(a, x). */
function gammaQContinuedFraction(a: number, x: number): number {
  const maxIterations = 200;
  const epsilon = 1e-10;
  const fpMin = 1e-30;

  let b = x + 1 - a;
  let c = 1 / fpMin;
  let d = 1 / b;
  let h = d;

  for (let i = 1; i < maxIterations; i++) {
    const an = -i * (i - a);
    b += 2;
    d = an * d + b;
    if (Math.abs(d) < fpMin) d = fpMin;
    c = b + an / c;
    if (Math.abs(c) < fpMin) c = fpMin;
    d = 1 / d;
    const del = d * c;
    h *= del;
    if (Math.abs(del - 1) < epsilon) break;
  }

  return Math.exp(-x + a * Math.log(x) - lnGamma(a)) * h;
}

/** Log-gamma function using Stirling's approximation (Lanczos). */
function lnGamma(x: number): number {
  // Lanczos approximation coefficients
  const g = 7;
  const c = [
    0.99999999999980993,
    676.5203681218851,
    -1259.1392167224028,
    771.32342877765313,
    -176.61502916214059,
    12.507343278686905,
    -0.13857109526572012,
    9.9843695780195716e-6,
    1.5056327351493116e-7,
  ];

  if (x < 0.5) {
    // Reflection formula
    return Math.log(Math.PI / Math.sin(Math.PI * x)) - lnGamma(1 - x);
  }

  x -= 1;
  let a = c[0]!;
  const t = x + g + 0.5;
  for (let i = 1; i < g + 2; i++) {
    a += c[i]! / (x + i);
  }

  return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
}

// ---------------------------------------------------------------------------
// Graduated Stake Burning
// ---------------------------------------------------------------------------

/** Configuration for the graduated burn penalty curve. */
export interface GraduatedBurnConfig {
  /** Minimum burn fraction (applied for the mildest breaches). */
  minBurnFraction: number;
  /** Maximum burn fraction (applied for the most severe breaches). */
  maxBurnFraction: number;
  /**
   * Exponent for the penalty curve. Controls non-linearity:
   * - 1.0 = linear scaling
   * - > 1.0 = superlinear (harsh on severe breaches)
   * - < 1.0 = sublinear (lenient on severe breaches)
   */
  curveExponent: number;
  /** Weight of agent history in adjusting the burn (0 = ignore history, 1 = max adjustment). */
  historyWeight: number;
}

const DEFAULT_BURN_CONFIG: GraduatedBurnConfig = {
  minBurnFraction: 0.05,
  maxBurnFraction: 1.0,
  curveExponent: 1.5,
  historyWeight: 0.3,
};

/**
 * Replaces all-or-nothing stake burning with proportional penalties.
 *
 * The burn amount is calculated based on:
 * 1. **Breach severity** - mapped to a base severity score in [0, 1]
 * 2. **Agent history** - agents with more past breaches get a higher penalty
 * 3. **Stake amount** - the burn is a fraction of the staked amount
 *
 * The penalty curve is: burnFraction = min + (max - min) * adjustedSeverity^exponent
 * where adjustedSeverity incorporates both the breach severity and agent history.
 */
export class GraduatedBurner {
  private readonly config: GraduatedBurnConfig;

  constructor(config?: Partial<GraduatedBurnConfig>) {
    this.config = { ...DEFAULT_BURN_CONFIG, ...config };

    if (this.config.minBurnFraction < 0 || this.config.minBurnFraction > 1) {
      throw new SteleError(
        'minBurnFraction must be in [0, 1]',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (this.config.maxBurnFraction < this.config.minBurnFraction || this.config.maxBurnFraction > 1) {
      throw new SteleError(
        'maxBurnFraction must be in [minBurnFraction, 1]',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (this.config.curveExponent <= 0) {
      throw new SteleError(
        'curveExponent must be > 0',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (this.config.historyWeight < 0 || this.config.historyWeight > 1) {
      throw new SteleError(
        'historyWeight must be in [0, 1]',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
  }

  /**
   * Calculate the burn amount for a stake.
   *
   * @param stakeAmount - Total staked amount.
   * @param severity - Breach severity.
   * @param pastBreachCount - Number of past breaches by this agent.
   * @param totalPastExecutions - Total executions by this agent (for normalization).
   * @returns Object with burnAmount and burnFraction.
   */
  calculateBurn(
    stakeAmount: number,
    severity: Severity,
    pastBreachCount: number,
    totalPastExecutions: number,
  ): { burnAmount: number; burnFraction: number } {
    if (stakeAmount < 0) {
      throw new SteleError(
        'stakeAmount must be non-negative',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (pastBreachCount < 0 || !Number.isInteger(pastBreachCount)) {
      throw new SteleError(
        'pastBreachCount must be a non-negative integer',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (totalPastExecutions < 0 || !Number.isInteger(totalPastExecutions)) {
      throw new SteleError(
        'totalPastExecutions must be a non-negative integer',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    // Map severity to a base score in [0, 1]
    const baseSeverity = this.severityScore(severity);

    // Compute history adjustment: breach ratio scaled by historyWeight
    const breachRatio = totalPastExecutions > 0
      ? pastBreachCount / totalPastExecutions
      : 0;
    const historyAdjustment = this.config.historyWeight * breachRatio;

    // Combined severity, clamped to [0, 1]
    const adjustedSeverity = Math.min(1, baseSeverity + historyAdjustment);

    // Apply the penalty curve
    const { minBurnFraction, maxBurnFraction, curveExponent } = this.config;
    const burnFraction = minBurnFraction +
      (maxBurnFraction - minBurnFraction) * Math.pow(adjustedSeverity, curveExponent);

    const clampedFraction = Math.max(0, Math.min(1, burnFraction));
    const burnAmount = stakeAmount * clampedFraction;

    return { burnAmount, burnFraction: clampedFraction };
  }

  /**
   * Map severity to a base score in [0, 1].
   */
  private severityScore(severity: Severity): number {
    switch (severity) {
      case 'critical':
        return SEVERITY_SCORES.CRITICAL;
      case 'high':
        return SEVERITY_SCORES.HIGH;
      case 'medium':
        return SEVERITY_SCORES.MEDIUM;
      case 'low':
        return SEVERITY_SCORES.LOW;
      default:
        return SEVERITY_SCORES.DEFAULT;
    }
  }
}

// ---------------------------------------------------------------------------
// Reputation Aggregation (Weighted Median)
// ---------------------------------------------------------------------------

/** A reputation score from a single source for aggregation. */
export interface ReputationSource {
  /** Identifier of the reputation source. */
  sourceId: string;
  /** The reputation score reported by this source. */
  score: number;
  /** Weight/reliability of this source (higher = more trusted). */
  weight: number;
}

/**
 * Aggregates reputation scores from multiple independent sources
 * using weighted median (robust to outliers) rather than simple averaging.
 *
 * The weighted median is the value where the cumulative weight of
 * all smaller values equals 50% of the total weight. This provides
 * Byzantine fault tolerance: up to ~50% of sources can be malicious
 * without affecting the result (vs ~0% for simple averaging).
 */
export class ReputationAggregator {
  /**
   * Compute the weighted median of reputation scores.
   *
   * @param sources - Array of reputation sources with scores and weights.
   * @returns The weighted median score.
   * @throws SteleError if sources is empty or contains invalid values.
   */
  aggregate(sources: ReputationSource[]): number {
    if (sources.length === 0) {
      throw new SteleError(
        'At least one reputation source is required',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    for (const source of sources) {
      if (source.score < 0 || source.score > 1) {
        throw new SteleError(
          `Invalid score ${source.score} for source ${source.sourceId}: must be in [0, 1]`,
          SteleErrorCode.PROTOCOL_INVALID_INPUT,
        );
      }
      if (source.weight < 0) {
        throw new SteleError(
          `Invalid weight ${source.weight} for source ${source.sourceId}: must be non-negative`,
          SteleErrorCode.PROTOCOL_INVALID_INPUT,
        );
      }
    }

    // Filter out zero-weight sources
    const nonZero = sources.filter((s) => s.weight > 0);
    if (nonZero.length === 0) {
      throw new SteleError(
        'At least one source must have positive weight',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    // Sort by score
    const sorted = [...nonZero].sort((a, b) => a.score - b.score);
    const totalWeight = sorted.reduce((sum, s) => sum + s.weight, 0);
    const halfWeight = totalWeight / 2;

    // Find the weighted median: the score where cumulative weight reaches 50%
    let cumWeight = 0;
    for (let i = 0; i < sorted.length; i++) {
      cumWeight += sorted[i]!.weight;
      if (cumWeight >= halfWeight) {
        // If we're exactly at the boundary and there's a next value,
        // interpolate between current and next
        if (cumWeight === halfWeight && i + 1 < sorted.length) {
          return (sorted[i]!.score + sorted[i + 1]!.score) / 2;
        }
        return sorted[i]!.score;
      }
    }

    // Fallback: return the last score (shouldn't reach here with valid input)
    return sorted[sorted.length - 1]!.score;
  }

  /**
   * Compute both the weighted median and a confidence interval.
   *
   * The confidence interval is based on the weighted interquartile range (IQR).
   * A narrow IQR indicates high consensus; a wide IQR indicates disagreement.
   *
   * @param sources - Array of reputation sources.
   * @returns Object with median, lower quartile, upper quartile, and consensus score.
   */
  aggregateWithConfidence(sources: ReputationSource[]): {
    median: number;
    lowerQuartile: number;
    upperQuartile: number;
    consensus: number;
  } {
    const median = this.aggregate(sources);

    const nonZero = sources.filter((s) => s.weight > 0);
    const sorted = [...nonZero].sort((a, b) => a.score - b.score);
    const totalWeight = sorted.reduce((sum, s) => sum + s.weight, 0);

    const lowerQuartile = this.weightedQuantile(sorted, totalWeight, 0.25);
    const upperQuartile = this.weightedQuantile(sorted, totalWeight, 0.75);

    // Consensus: 1 - IQR (normalized). High consensus when IQR is small.
    const iqr = upperQuartile - lowerQuartile;
    const consensus = Math.max(0, 1 - iqr);

    return { median, lowerQuartile, upperQuartile, consensus };
  }

  /**
   * Compute a weighted quantile.
   */
  private weightedQuantile(
    sorted: ReputationSource[],
    totalWeight: number,
    quantile: number,
  ): number {
    const target = totalWeight * quantile;
    let cumWeight = 0;

    for (let i = 0; i < sorted.length; i++) {
      cumWeight += sorted[i]!.weight;
      if (cumWeight >= target) {
        return sorted[i]!.score;
      }
    }

    return sorted[sorted.length - 1]!.score;
  }
}

// ---------------------------------------------------------------------------
// Item 30: Trust as Bounded Resource
// ---------------------------------------------------------------------------

/**
 * Create a new resource pool backed by collateral.
 *
 * Trust cannot exceed the economic value risked to back it.
 * The collateralization bound prevents trust inflation and ensures
 * trust has real scarcity.
 *
 * @param totalCollateral - The total collateral backing the pool.
 * @returns A fresh ResourcePool with all trust available.
 */
export function createResourcePool(totalCollateral: number): ResourcePool {
  return {
    totalCollateral,
    allocatedTrust: 0,
    availableTrust: totalCollateral,
    utilizationRatio: 0,
    participants: new Map<string, number>(),
  };
}

/**
 * Allocate trust from the pool to an agent.
 *
 * Only succeeds if the requested amount does not exceed the available
 * trust in the pool. This enforces the collateralization bound: total
 * allocated trust can never exceed total collateral.
 *
 * @param pool - The resource pool to allocate from.
 * @param agentId - The agent to allocate trust to.
 * @param amount - The amount of trust to allocate.
 * @returns The updated pool and whether the allocation succeeded.
 */
export function allocateTrust(
  pool: ResourcePool,
  agentId: string,
  amount: number,
): { pool: ResourcePool; allocated: boolean; reason: string } {
  if (amount <= 0) {
    return { pool, allocated: false, reason: 'Amount must be positive' };
  }
  if (amount > pool.availableTrust) {
    return {
      pool,
      allocated: false,
      reason: `Requested ${amount} exceeds available trust ${pool.availableTrust}`,
    };
  }

  const newParticipants = new Map(pool.participants);
  const existing = newParticipants.get(agentId) ?? 0;
  newParticipants.set(agentId, existing + amount);

  const newAllocated = pool.allocatedTrust + amount;
  const newAvailable = pool.availableTrust - amount;
  const newUtilization = pool.totalCollateral > 0 ? newAllocated / pool.totalCollateral : 0;

  return {
    pool: {
      totalCollateral: pool.totalCollateral,
      allocatedTrust: newAllocated,
      availableTrust: newAvailable,
      utilizationRatio: newUtilization,
      participants: newParticipants,
    },
    allocated: true,
    reason: 'Allocation successful',
  };
}

/**
 * Release trust back to the pool from an agent.
 *
 * Decreases allocated trust and increases available trust.
 *
 * @param pool - The resource pool.
 * @param agentId - The agent releasing trust.
 * @param amount - The amount of trust to release.
 * @returns The updated pool.
 */
export function releaseTrust(
  pool: ResourcePool,
  agentId: string,
  amount: number,
): ResourcePool {
  const existing = pool.participants.get(agentId) ?? 0;
  const releaseAmount = Math.min(amount, existing);

  const newParticipants = new Map(pool.participants);
  const remaining = existing - releaseAmount;
  if (remaining <= 0) {
    newParticipants.delete(agentId);
  } else {
    newParticipants.set(agentId, remaining);
  }

  const newAllocated = pool.allocatedTrust - releaseAmount;
  const newAvailable = pool.availableTrust + releaseAmount;
  const newUtilization = pool.totalCollateral > 0 ? newAllocated / pool.totalCollateral : 0;

  return {
    totalCollateral: pool.totalCollateral,
    allocatedTrust: newAllocated,
    availableTrust: newAvailable,
    utilizationRatio: newUtilization,
    participants: newParticipants,
  };
}

/**
 * Slash an agent's stake from the pool.
 *
 * Removes the slashed amount from the pool entirely (reduces totalCollateral
 * and allocatedTrust). If the slashing event is marked as redistributed,
 * the amount is added back to availableTrust instead of being destroyed.
 *
 * @param pool - The resource pool.
 * @param event - The slashing event details.
 * @returns The updated pool.
 */
export function slashStake(pool: ResourcePool, event: SlashingEvent): ResourcePool {
  const existing = pool.participants.get(event.agentId) ?? 0;
  const slashAmount = Math.min(event.amount, existing);

  const newParticipants = new Map(pool.participants);
  const remaining = existing - slashAmount;
  if (remaining <= 0) {
    newParticipants.delete(event.agentId);
  } else {
    newParticipants.set(event.agentId, remaining);
  }

  const newAllocated = pool.allocatedTrust - slashAmount;
  let newCollateral: number;
  let newAvailable: number;

  if (event.redistributed) {
    // Redistributed: collateral stays, slashed amount goes back to available
    newCollateral = pool.totalCollateral;
    newAvailable = pool.availableTrust + slashAmount;
  } else {
    // Destroyed: collateral is reduced
    newCollateral = pool.totalCollateral - slashAmount;
    newAvailable = pool.availableTrust;
  }

  const newUtilization = newCollateral > 0 ? newAllocated / newCollateral : 0;

  return {
    totalCollateral: newCollateral,
    allocatedTrust: newAllocated,
    availableTrust: newAvailable,
    utilizationRatio: newUtilization,
    participants: newParticipants,
  };
}

/**
 * Compute the collateralization ratio of a resource pool.
 *
 * Returns allocatedTrust / totalCollateral. Must never exceed 1.0.
 *
 * @param pool - The resource pool.
 * @returns The collateralization ratio in [0, 1].
 */
export function collateralizationRatio(pool: ResourcePool): number {
  if (pool.totalCollateral <= 0) return 0;
  return Math.min(1, pool.allocatedTrust / pool.totalCollateral);
}

// ---------------------------------------------------------------------------
// Item 46: Multidimensional Trust Profile (Anti-Gaming)
// ---------------------------------------------------------------------------

/** Default dimension weights (equal weighting). */
const DEFAULT_DIMENSION_WEIGHTS = {
  hardEnforcement: 0.2,
  attestationCoverage: 0.2,
  covenantBreadth: 0.2,
  historyDepth: 0.2,
  stakeRatio: 0.2,
};

/**
 * Compute a multidimensional trust profile for an agent.
 *
 * Five dimensions trade off against each other. The composite score
 * is a weighted geometric mean, which prevents gaming by optimising
 * only one dimension. The gaming resistance metric measures how
 * balanced the dimensions are.
 *
 * @param params - The agent's scores across each dimension.
 * @returns A complete MultidimensionalProfile.
 */
export function computeProfile(params: {
  agentId: string;
  hardEnforcement: number;
  attestationCoverage: number;
  covenantBreadth: number;
  historyDepth: number;
  stakeRatio: number;
  weights?: {
    hardEnforcement?: number;
    attestationCoverage?: number;
    covenantBreadth?: number;
    historyDepth?: number;
    stakeRatio?: number;
  };
}): MultidimensionalProfile {
  const weights = {
    hardEnforcement: params.weights?.hardEnforcement ?? DEFAULT_DIMENSION_WEIGHTS.hardEnforcement,
    attestationCoverage: params.weights?.attestationCoverage ?? DEFAULT_DIMENSION_WEIGHTS.attestationCoverage,
    covenantBreadth: params.weights?.covenantBreadth ?? DEFAULT_DIMENSION_WEIGHTS.covenantBreadth,
    historyDepth: params.weights?.historyDepth ?? DEFAULT_DIMENSION_WEIGHTS.historyDepth,
    stakeRatio: params.weights?.stakeRatio ?? DEFAULT_DIMENSION_WEIGHTS.stakeRatio,
  };

  const dimensions = {
    hardEnforcement: {
      name: 'hardEnforcement',
      score: Math.max(0, Math.min(1, params.hardEnforcement)),
      weight: weights.hardEnforcement,
      evidence: 1,
    },
    attestationCoverage: {
      name: 'attestationCoverage',
      score: Math.max(0, Math.min(1, params.attestationCoverage)),
      weight: weights.attestationCoverage,
      evidence: 1,
    },
    covenantBreadth: {
      name: 'covenantBreadth',
      score: Math.max(0, Math.min(1, params.covenantBreadth)),
      weight: weights.covenantBreadth,
      evidence: 1,
    },
    historyDepth: {
      name: 'historyDepth',
      score: Math.max(0, Math.min(1, params.historyDepth)),
      weight: weights.historyDepth,
      evidence: 1,
    },
    stakeRatio: {
      name: 'stakeRatio',
      score: Math.max(0, Math.min(1, params.stakeRatio)),
      weight: weights.stakeRatio,
      evidence: 1,
    },
  };

  // Compute weighted geometric mean: product(score_i ^ weight_i)
  const dimEntries = Object.values(dimensions) as TrustDimension[];
  let logSum = 0;
  for (const dim of dimEntries) {
    // Use a small epsilon to avoid log(0)
    const safeScore = Math.max(dim.score, 1e-10);
    logSum += dim.weight * Math.log(safeScore);
  }
  const compositeScore = Math.max(0, Math.min(1, Math.exp(logSum)));

  // Gaming resistance: 1 - (max(scores) - min(scores))
  const scores = dimEntries.map((d) => d.score);
  const maxScore = Math.max(...scores);
  const minScore = Math.min(...scores);
  const gamingResistance = Math.max(0, Math.min(1, 1 - maxScore + minScore));

  return {
    agentId: params.agentId,
    dimensions,
    compositeScore,
    gamingResistance,
  };
}

/**
 * Compare two multidimensional trust profiles.
 *
 * Profile a dominates profile b if a >= b in ALL dimensions.
 * Otherwise, neither dominates. Also reports which dimensions
 * each profile is stronger in.
 *
 * @param a - First profile.
 * @param b - Second profile.
 * @returns Domination result and per-dimension comparison.
 */
export function compareProfiles(
  a: MultidimensionalProfile,
  b: MultidimensionalProfile,
): {
  dominates: 'a' | 'b' | 'neither';
  strongerDimensions: Record<string, 'a' | 'b' | 'tie'>;
} {
  const dimNames = [
    'hardEnforcement',
    'attestationCoverage',
    'covenantBreadth',
    'historyDepth',
    'stakeRatio',
  ] as const;

  const strongerDimensions: Record<string, 'a' | 'b' | 'tie'> = {};
  let aWins = 0;
  let bWins = 0;
  let ties = 0;

  for (const name of dimNames) {
    const scoreA = a.dimensions[name].score;
    const scoreB = b.dimensions[name].score;
    if (scoreA > scoreB) {
      strongerDimensions[name] = 'a';
      aWins++;
    } else if (scoreB > scoreA) {
      strongerDimensions[name] = 'b';
      bWins++;
    } else {
      strongerDimensions[name] = 'tie';
      ties++;
    }
  }

  let dominates: 'a' | 'b' | 'neither';
  if (bWins === 0 && aWins > 0) {
    dominates = 'a';
  } else if (aWins === 0 && bWins > 0) {
    dominates = 'b';
  } else {
    dominates = 'neither';
  }

  return { dominates, strongerDimensions };
}

// ---------------------------------------------------------------------------
// Item 75: Productive Staking Tiers
// ---------------------------------------------------------------------------

/**
 * Configuration for each staking tier.
 *
 * Higher stake = verification income + marketplace ranking + governance weight.
 * - Basic ($1): entry level
 * - Verified ($10): moderate benefits
 * - Certified ($100): significant benefits
 * - Institutional ($1,000+): maximum benefits
 */
export const STAKE_TIERS: Record<StakeTier, StakeTierConfig> = {
  basic: {
    tier: 'basic',
    minimumStake: 1,
    verificationIncomeRate: 0.0001,
    marketplaceRankBoost: 1.0,
    governanceWeight: 1,
    maxDelegations: 5,
  },
  verified: {
    tier: 'verified',
    minimumStake: 10,
    verificationIncomeRate: 0.0002,
    marketplaceRankBoost: 1.5,
    governanceWeight: 2,
    maxDelegations: 20,
  },
  certified: {
    tier: 'certified',
    minimumStake: 100,
    verificationIncomeRate: 0.0005,
    marketplaceRankBoost: 3.0,
    governanceWeight: 5,
    maxDelegations: 100,
  },
  institutional: {
    tier: 'institutional',
    minimumStake: 1000,
    verificationIncomeRate: 0.001,
    marketplaceRankBoost: 10.0,
    governanceWeight: 20,
    maxDelegations: 1000,
  },
};

/**
 * Assign a staking tier based on the staked amount.
 *
 * Returns the highest tier where the staked amount meets or exceeds
 * the minimum stake requirement.
 *
 * @param stakedAmount - The amount staked by the agent.
 * @returns The assigned tier.
 */
export function assignTier(stakedAmount: number): StakeTier {
  if (stakedAmount >= STAKE_TIERS.institutional.minimumStake) return 'institutional';
  if (stakedAmount >= STAKE_TIERS.certified.minimumStake) return 'certified';
  if (stakedAmount >= STAKE_TIERS.verified.minimumStake) return 'verified';
  return 'basic';
}

/**
 * Create a staked agent with the correct tier and configuration.
 *
 * @param agentId - The agent identifier.
 * @param stakedAmount - The amount staked.
 * @returns A StakedAgent with tier, config, and initial counters.
 */
export function createStakedAgent(agentId: string, stakedAmount: number): StakedAgent {
  const tier = assignTier(stakedAmount);
  return {
    agentId,
    tier,
    stakedAmount,
    earnedIncome: 0,
    queriesServed: 0,
    config: { ...STAKE_TIERS[tier] },
  };
}

/**
 * Record a query served by a staked agent.
 *
 * Increments queriesServed and adds the verification income rate
 * to the agent's earned income. Returns a new agent object; the
 * original is not mutated.
 *
 * @param agent - The staked agent.
 * @returns The updated agent with incremented counters.
 */
export function recordQuery(agent: StakedAgent): StakedAgent {
  return {
    ...agent,
    queriesServed: agent.queriesServed + 1,
    earnedIncome: agent.earnedIncome + agent.config.verificationIncomeRate,
  };
}

/**
 * Compute the governance vote for a staked agent.
 *
 * Returns the base vote multiplied by the agent's governance weight.
 *
 * @param agent - The staked agent.
 * @param baseVote - The base vote value.
 * @returns The weighted vote.
 */
export function computeGovernanceVote(agent: StakedAgent, baseVote: number): number {
  return baseVote * agent.config.governanceWeight;
}
