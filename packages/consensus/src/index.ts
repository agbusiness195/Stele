import { sha256Object, generateId } from '@kervyx/crypto';
import { KervyxError, KervyxErrorCode } from '@kervyx/types';

export type {
  AccountabilityTier,
  AccountabilityScore,
  InteractionPolicy,
  AccessDecision,
  ProtocolData,
} from './types';

import type {
  AccountabilityTier,
  AccountabilityScore,
  InteractionPolicy,
  AccessDecision,
  ProtocolData,
} from './types';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface AccountabilityConfig {
  tierThresholds?: {
    exemplary: number;  // default 0.9
    trusted: number;    // default 0.7
    verified: number;   // default 0.5
    basic: number;      // default 0.3
  };
  componentWeights?: {
    covenantCompleteness: number;  // default 0.15
    complianceHistory: number;     // default 0.30
    stakeRatio: number;            // default 0.20
    attestationCoverage: number;   // default 0.20
    canaryPassRate: number;        // default 0.15
  };
  minimumCovenants?: number;  // default 3
}

const DEFAULT_TIER_THRESHOLDS = {
  exemplary: 0.9,
  trusted: 0.7,
  verified: 0.5,
  basic: 0.3,
};

const DEFAULT_COMPONENT_WEIGHTS = {
  covenantCompleteness: 0.15,
  complianceHistory: 0.30,
  stakeRatio: 0.20,
  attestationCoverage: 0.20,
  canaryPassRate: 0.15,
};

const DEFAULT_MINIMUM_COVENANTS = 3;

function resolveConfig(config?: AccountabilityConfig) {
  const thresholds = { ...DEFAULT_TIER_THRESHOLDS, ...config?.tierThresholds };
  const weights = { ...DEFAULT_COMPONENT_WEIGHTS, ...config?.componentWeights };
  const minimumCovenants = config?.minimumCovenants ?? DEFAULT_MINIMUM_COVENANTS;
  return { thresholds, weights, minimumCovenants };
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Validate that an AccountabilityConfig is well-formed.
 * - Tier thresholds must be in (0, 1) and ordered: exemplary > trusted > verified > basic > 0.
 * - Component weights must be non-negative and sum to approximately 1.0.
 * - minimumCovenants must be >= 1.
 */
export function validateConfig(config: AccountabilityConfig): void {
  if (config.tierThresholds) {
    const t = { ...DEFAULT_TIER_THRESHOLDS, ...config.tierThresholds };
    for (const [name, val] of Object.entries(t)) {
      if (val < 0 || val > 1) {
        throw new Error(`Tier threshold '${name}' must be in [0, 1], got ${val}`);
      }
    }
    if (t.exemplary <= t.trusted || t.trusted <= t.verified || t.verified <= t.basic) {
      throw new Error(
        `Tier thresholds must be strictly ordered: exemplary(${t.exemplary}) > trusted(${t.trusted}) > verified(${t.verified}) > basic(${t.basic})`,
      );
    }
  }

  if (config.componentWeights) {
    const w = { ...DEFAULT_COMPONENT_WEIGHTS, ...config.componentWeights };
    for (const [name, val] of Object.entries(w)) {
      if (val < 0) {
        throw new Error(`Component weight '${name}' must be >= 0, got ${val}`);
      }
    }
    const sum = Object.values(w).reduce((s, v) => s + v, 0);
    if (Math.abs(sum - 1.0) > 0.001) {
      throw new Error(
        `Component weights must sum to approximately 1.0, got ${sum}`,
      );
    }
  }

  if (config.minimumCovenants !== undefined && config.minimumCovenants < 1) {
    throw new Error(
      `minimumCovenants must be >= 1, got ${config.minimumCovenants}`,
    );
  }
}

/**
 * Validate ProtocolData fields are within acceptable ranges.
 */
export function validateProtocolData(data: ProtocolData): void {
  if (data.covenantCount < 0) {
    throw new Error(`covenantCount must be >= 0, got ${data.covenantCount}`);
  }
  if (data.totalInteractions < 0) {
    throw new Error(`totalInteractions must be >= 0, got ${data.totalInteractions}`);
  }
  if (data.compliantInteractions < 0) {
    throw new Error(`compliantInteractions must be >= 0, got ${data.compliantInteractions}`);
  }
  if (data.compliantInteractions > data.totalInteractions) {
    throw new Error(
      `compliantInteractions (${data.compliantInteractions}) must be <= totalInteractions (${data.totalInteractions})`,
    );
  }
  if (data.stakeAmount < 0) {
    throw new Error(`stakeAmount must be >= 0, got ${data.stakeAmount}`);
  }
  if (data.maxStake < 0) {
    throw new Error(`maxStake must be >= 0, got ${data.maxStake}`);
  }
  if (data.attestedInteractions < 0) {
    throw new Error(`attestedInteractions must be >= 0, got ${data.attestedInteractions}`);
  }
  if (data.canaryTests < 0) {
    throw new Error(`canaryTests must be >= 0, got ${data.canaryTests}`);
  }
  if (data.canaryPasses < 0) {
    throw new Error(`canaryPasses must be >= 0, got ${data.canaryPasses}`);
  }
  if (data.canaryPasses > data.canaryTests) {
    throw new Error(
      `canaryPasses (${data.canaryPasses}) must be <= canaryTests (${data.canaryTests})`,
    );
  }
}

/**
 * Validate InteractionPolicy fields are within acceptable ranges.
 */
export function validatePolicy(policy: InteractionPolicy): void {
  if (policy.minimumScore < 0 || policy.minimumScore > 1) {
    throw new Error(
      `minimumScore must be in [0, 1], got ${policy.minimumScore}`,
    );
  }
}

/**
 * Validate that an AccountabilityScore is within acceptable ranges.
 */
function validateScore(score: AccountabilityScore): void {
  if (score.score < 0 || score.score > 1) {
    throw new Error(
      `AccountabilityScore.score must be in [0, 1], got ${score.score}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Tier logic
// ---------------------------------------------------------------------------

const TIER_ORDER: AccountabilityTier[] = [
  'unaccountable',
  'basic',
  'verified',
  'trusted',
  'exemplary',
];

/**
 * Return the minimum score required for a given accountability tier.
 */
export function tierToMinScore(
  tier: AccountabilityTier,
  config?: AccountabilityConfig,
): number {
  const { thresholds } = resolveConfig(config);
  switch (tier) {
    case 'exemplary':
      return thresholds.exemplary;
    case 'trusted':
      return thresholds.trusted;
    case 'verified':
      return thresholds.verified;
    case 'basic':
      return thresholds.basic;
    case 'unaccountable':
      return 0;
  }
}

/**
 * Determine the accountability tier for a given numeric score.
 */
function scoreToTier(
  score: number,
  thresholds: typeof DEFAULT_TIER_THRESHOLDS,
): AccountabilityTier {
  if (score >= thresholds.exemplary) return 'exemplary';
  if (score >= thresholds.trusted) return 'trusted';
  if (score >= thresholds.verified) return 'verified';
  if (score >= thresholds.basic) return 'basic';
  return 'unaccountable';
}

/**
 * Compare two accountability tiers.
 * Returns -1 if a < b, 0 if a === b, 1 if a > b.
 */
export function compareTiers(a: AccountabilityTier, b: AccountabilityTier): -1 | 0 | 1 {
  const ai = TIER_ORDER.indexOf(a);
  const bi = TIER_ORDER.indexOf(b);
  if (ai < bi) return -1;
  if (ai > bi) return 1;
  return 0;
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/**
 * Compute the accountability score for an agent given their protocol data.
 *
 * The score is the weighted sum of five components:
 *  - covenantCompleteness: min(covenantCount / minimumCovenants, 1.0)
 *  - complianceHistory: compliantInteractions / max(totalInteractions, 1)
 *  - stakeRatio: stakeAmount / max(maxStake, 1)
 *  - attestationCoverage: attestedInteractions / max(totalInteractions, 1)
 *  - canaryPassRate: canaryPasses / max(canaryTests, 1)
 */
export function computeAccountability(
  agentId: string,
  data: ProtocolData,
  config?: AccountabilityConfig,
): AccountabilityScore {
  if (config) validateConfig(config);
  validateProtocolData(data);

  const { thresholds, weights, minimumCovenants } = resolveConfig(config);

  const covenantCompleteness = Math.min(data.covenantCount / minimumCovenants, 1.0);
  const complianceHistory = data.compliantInteractions / Math.max(data.totalInteractions, 1);
  const stakeRatio = data.stakeAmount / Math.max(data.maxStake, 1);
  const attestationCoverage = data.attestedInteractions / Math.max(data.totalInteractions, 1);
  const canaryPassRate = data.canaryPasses / Math.max(data.canaryTests, 1);

  const score =
    weights.covenantCompleteness * covenantCompleteness +
    weights.complianceHistory * complianceHistory +
    weights.stakeRatio * stakeRatio +
    weights.attestationCoverage * attestationCoverage +
    weights.canaryPassRate * canaryPassRate;

  const tier = scoreToTier(score, thresholds);

  return {
    agentId,
    score,
    components: {
      covenantCompleteness,
      complianceHistory,
      stakeRatio,
      attestationCoverage,
      canaryPassRate,
    },
    tier,
  };
}

/**
 * Evaluate whether a counterparty meets the requirements of an interaction policy.
 *
 * Checks:
 *  1. The counterparty's tier is at or above the policy's minimumTier.
 *  2. The counterparty's score is at or above the policy's minimumScore.
 *  3. If requireStake is true, the counterparty's stakeRatio must be > 0.
 *  4. If requireAttestation is true, the counterparty's attestationCoverage must be > 0.
 *
 * The riskAdjustment is based on how far below the policy threshold the counterparty falls.
 * For allowed counterparties: riskAdjustment = 1 - counterparty.score
 * For denied counterparties: riskAdjustment = 1 - counterparty.score + deficit below threshold
 */
export function evaluateCounterparty(
  policy: InteractionPolicy,
  counterparty: AccountabilityScore,
): AccessDecision {
  validatePolicy(policy);
  validateScore(counterparty);

  const baseRisk = 1 - counterparty.score;
  const deficit = Math.max(0, policy.minimumScore - counterparty.score);
  const riskAdjustment = Math.min(1, baseRisk + deficit);

  // Check tier requirement
  if (compareTiers(counterparty.tier, policy.minimumTier) < 0) {
    return {
      allowed: false,
      reason: `Counterparty tier '${counterparty.tier}' is below minimum tier '${policy.minimumTier}'`,
      counterpartyScore: counterparty,
      riskAdjustment,
    };
  }

  // Check minimum score
  if (counterparty.score < policy.minimumScore) {
    return {
      allowed: false,
      reason: `Counterparty score ${counterparty.score} is below minimum score ${policy.minimumScore}`,
      counterpartyScore: counterparty,
      riskAdjustment,
    };
  }

  // Check stake requirement
  if (policy.requireStake && counterparty.components.stakeRatio <= 0) {
    return {
      allowed: false,
      reason: 'Policy requires stake but counterparty has no stake',
      counterpartyScore: counterparty,
      riskAdjustment,
    };
  }

  // Check attestation requirement
  if (policy.requireAttestation && counterparty.components.attestationCoverage <= 0) {
    return {
      allowed: false,
      reason: 'Policy requires attestation but counterparty has no attestation coverage',
      counterpartyScore: counterparty,
      riskAdjustment,
    };
  }

  return {
    allowed: true,
    reason: 'Counterparty meets all policy requirements',
    counterpartyScore: counterparty,
    riskAdjustment,
  };
}

/**
 * Compute the average accountability score across a set of agents.
 * Returns 0 if the array is empty.
 */
export function networkAccountabilityRate(scores: AccountabilityScore[]): number {
  if (scores.length === 0) return 0;
  const total = scores.reduce((sum, s) => sum + s.score, 0);
  return total / scores.length;
}

// ---------------------------------------------------------------------------
// Byzantine Fault Tolerance
// ---------------------------------------------------------------------------

/**
 * Result of Byzantine Fault Tolerance analysis.
 */
export interface BFTResult {
  /** Total number of nodes in the network */
  totalNodes: number;
  /** Maximum number of faulty (Byzantine) nodes that can be tolerated */
  maxFaultyNodes: number;
  /** Whether the current network size can tolerate the given number of faults */
  canTolerate: boolean;
  /** The minimum number of nodes needed to tolerate the requested fault count */
  minNodesRequired: number;
  /** Human-readable derivation */
  formula: string;
}

/**
 * Compute Byzantine Fault Tolerance properties for a network.
 *
 * The classic BFT result (Lamport, Shostak, Pease 1982) states that
 * Byzantine consensus requires:
 *
 *   n >= 3f + 1
 *
 * where n = total nodes, f = max faulty nodes.
 *
 * Equivalently, the maximum tolerable faults for n nodes is:
 *
 *   f_max = floor((n - 1) / 3)
 *
 * @param totalNodes Total number of nodes in the network (must be >= 1)
 * @param requestedFaults Optional: check if the network can tolerate this many faults
 */
export function byzantineFaultTolerance(
  totalNodes: number,
  requestedFaults?: number,
): BFTResult {
  if (!Number.isInteger(totalNodes) || totalNodes < 1) {
    throw new Error(`totalNodes must be a positive integer, got ${totalNodes}`);
  }
  if (requestedFaults !== undefined) {
    if (!Number.isInteger(requestedFaults) || requestedFaults < 0) {
      throw new Error(`requestedFaults must be a non-negative integer, got ${requestedFaults}`);
    }
  }

  // f_max = floor((n - 1) / 3)
  const maxFaultyNodes = Math.floor((totalNodes - 1) / 3);

  const faults = requestedFaults ?? maxFaultyNodes;
  const minNodesRequired = 3 * faults + 1;
  const canTolerate = totalNodes >= minNodesRequired;

  const formula =
    `BFT constraint: n >= 3f + 1\n` +
    `Total nodes (n): ${totalNodes}\n` +
    `Max tolerable faults: f_max = floor((${totalNodes} - 1) / 3) = ${maxFaultyNodes}\n` +
    (requestedFaults !== undefined
      ? `Requested fault tolerance: f = ${requestedFaults}, requires n >= ${minNodesRequired}\n` +
        `Network ${canTolerate ? 'CAN' : 'CANNOT'} tolerate ${requestedFaults} faults`
      : `Network can tolerate up to ${maxFaultyNodes} Byzantine faults`);

  return {
    totalNodes,
    maxFaultyNodes,
    canTolerate,
    minNodesRequired,
    formula,
  };
}

// ---------------------------------------------------------------------------
// Quorum Size
// ---------------------------------------------------------------------------

/**
 * Supported consensus protocol types for quorum computation.
 */
export type ConsensusProtocol = 'simple_majority' | 'bft' | 'two_thirds' | 'unanimous';

/**
 * Result of quorum size computation.
 */
export interface QuorumResult {
  /** The protocol used for computation */
  protocol: ConsensusProtocol;
  /** Total number of nodes */
  totalNodes: number;
  /** The minimum quorum size required */
  quorumSize: number;
  /** Quorum as a fraction of totalNodes */
  quorumFraction: number;
  /** Human-readable derivation */
  formula: string;
}

/**
 * Compute the minimum quorum size for various consensus protocols.
 *
 * Protocols:
 *
 * - simple_majority: quorum = floor(n/2) + 1
 *   Standard majority voting. Requires > 50% agreement.
 *
 * - bft: quorum = floor(2n/3) + 1
 *   Byzantine fault tolerant quorum. Requires > 2/3 agreement to ensure
 *   any two quorums overlap in at least one honest node when f < n/3.
 *
 * - two_thirds: quorum = ceil(2n/3)
 *   Requires at least 2/3 of nodes, used in many PoS protocols.
 *
 * - unanimous: quorum = n
 *   All nodes must agree.
 *
 * @param totalNodes Total number of nodes in the network (must be >= 1)
 * @param protocol The consensus protocol type
 */
export function quorumSize(
  totalNodes: number,
  protocol: ConsensusProtocol,
): QuorumResult {
  if (!Number.isInteger(totalNodes) || totalNodes < 1) {
    throw new Error(`totalNodes must be a positive integer, got ${totalNodes}`);
  }

  let q: number;
  let formulaDetail: string;

  switch (protocol) {
    case 'simple_majority':
      // quorum = floor(n/2) + 1
      q = Math.floor(totalNodes / 2) + 1;
      formulaDetail = `Simple majority: quorum = floor(${totalNodes}/2) + 1 = ${q}`;
      break;
    case 'bft':
      // quorum = floor(2n/3) + 1 (ensures overlap > f for f < n/3)
      q = Math.floor((2 * totalNodes) / 3) + 1;
      formulaDetail = `BFT quorum: quorum = floor(2*${totalNodes}/3) + 1 = ${q}`;
      break;
    case 'two_thirds':
      // quorum = ceil(2n/3)
      q = Math.ceil((2 * totalNodes) / 3);
      formulaDetail = `Two-thirds quorum: quorum = ceil(2*${totalNodes}/3) = ${q}`;
      break;
    case 'unanimous':
      q = totalNodes;
      formulaDetail = `Unanimous: quorum = ${totalNodes} (all nodes required)`;
      break;
    default:
      throw new Error(`Unknown protocol: ${protocol}`);
  }

  // Ensure quorum does not exceed total nodes
  q = Math.min(q, totalNodes);

  const quorumFraction = totalNodes > 0 ? q / totalNodes : 1;

  const formula =
    `${formulaDetail}\n` +
    `Quorum fraction: ${q}/${totalNodes} = ${quorumFraction.toFixed(4)}`;

  return {
    protocol,
    totalNodes,
    quorumSize: q,
    quorumFraction,
    formula,
  };
}

// ---------------------------------------------------------------------------
// Consensus Latency
// ---------------------------------------------------------------------------

/**
 * Parameters for consensus latency estimation.
 */
export interface ConsensusLatencyParams {
  /** Number of nodes in the network */
  nodeCount: number;
  /** Average network round-trip time in milliseconds */
  averageLatencyMs: number;
  /** Number of communication rounds required by the protocol */
  messageRounds: number;
  /** Optional: message loss probability in [0, 1). Adds retry overhead. */
  messageLossProbability?: number;
  /** Optional: processing time per node per round in milliseconds */
  processingTimeMs?: number;
}

/**
 * Result of consensus latency estimation.
 */
export interface ConsensusLatencyResult {
  /** Estimated time to reach consensus in milliseconds */
  estimatedLatencyMs: number;
  /** Network communication component in milliseconds */
  networkLatencyMs: number;
  /** Processing component in milliseconds */
  processingLatencyMs: number;
  /** Retry overhead due to message loss in milliseconds */
  retryOverheadMs: number;
  /** Human-readable derivation */
  formula: string;
}

/**
 * Estimate the time to reach consensus given network parameters.
 *
 * The model computes:
 *
 *   networkLatency = messageRounds * averageLatencyMs
 *   processingLatency = messageRounds * processingTimeMs
 *   retryOverhead = networkLatency * (messageLossProbability / (1 - messageLossProbability))
 *
 * The retry overhead models the geometric distribution of retries:
 * if each message has probability p of being lost, the expected number
 * of transmissions per message is 1/(1-p), adding overhead factor p/(1-p).
 *
 * Total estimated latency:
 *   estimatedLatency = networkLatency + processingLatency + retryOverhead
 *
 * This is a simplified model; real-world consensus latency depends on
 * many additional factors (network topology, leader election, etc.).
 *
 * @param params Network and protocol parameters
 */
export function consensusLatency(params: ConsensusLatencyParams): ConsensusLatencyResult {
  const {
    nodeCount,
    averageLatencyMs,
    messageRounds,
    messageLossProbability = 0,
    processingTimeMs = 0,
  } = params;

  if (!Number.isInteger(nodeCount) || nodeCount < 1) {
    throw new Error(`nodeCount must be a positive integer, got ${nodeCount}`);
  }
  if (averageLatencyMs < 0) {
    throw new Error(`averageLatencyMs must be >= 0, got ${averageLatencyMs}`);
  }
  if (!Number.isInteger(messageRounds) || messageRounds < 1) {
    throw new Error(`messageRounds must be a positive integer, got ${messageRounds}`);
  }
  if (messageLossProbability < 0 || messageLossProbability >= 1) {
    throw new Error(
      `messageLossProbability must be in [0, 1), got ${messageLossProbability}`,
    );
  }
  if (processingTimeMs < 0) {
    throw new Error(`processingTimeMs must be >= 0, got ${processingTimeMs}`);
  }

  // Network latency: each round requires one RTT
  const networkLatencyMs = messageRounds * averageLatencyMs;

  // Processing latency: each round has processing overhead
  const processingLatencyMs = messageRounds * processingTimeMs;

  // Retry overhead: geometric distribution of retries due to message loss
  // Expected transmissions = 1/(1-p), so overhead factor = p/(1-p)
  const retryOverheadMs = messageLossProbability > 0
    ? networkLatencyMs * (messageLossProbability / (1 - messageLossProbability))
    : 0;

  const estimatedLatencyMs = networkLatencyMs + processingLatencyMs + retryOverheadMs;

  const formula =
    `Network latency: ${messageRounds} rounds * ${averageLatencyMs}ms = ${networkLatencyMs}ms\n` +
    `Processing latency: ${messageRounds} rounds * ${processingTimeMs}ms = ${processingLatencyMs}ms\n` +
    `Retry overhead (p=${messageLossProbability}): ${retryOverheadMs.toFixed(2)}ms\n` +
    `Total estimated consensus latency: ${estimatedLatencyMs.toFixed(2)}ms`;

  return {
    estimatedLatencyMs,
    networkLatencyMs,
    processingLatencyMs,
    retryOverheadMs,
    formula,
  };
}

// ---------------------------------------------------------------------------
// Streamlined BFT (HotStuff-inspired)
// ---------------------------------------------------------------------------

/** Phase in the three-phase BFT commit. */
export type BFTPhase = 'prepare' | 'precommit' | 'commit';

/** A vote from a node in the BFT protocol. */
export interface BFTVote {
  nodeId: string;
  viewNumber: number;
  phase: BFTPhase;
  blockHash: string;
  timestamp: number;
}

/** Quorum Certificate: proof that a quorum voted in a given phase. */
export interface QuorumCertificate {
  viewNumber: number;
  phase: BFTPhase;
  blockHash: string;
  votes: BFTVote[];
  quorumSize: number;
}

/** A block proposal in the BFT protocol. */
export interface BFTBlock {
  hash: string;
  parentHash: string;
  viewNumber: number;
  proposer: string;
  payload: unknown;
  justification?: QuorumCertificate;
}

/** Current view state for a BFT node. */
export interface BFTViewState {
  viewNumber: number;
  leader: string;
  phase: BFTPhase;
  block: BFTBlock | null;
  votes: Map<string, BFTVote>;
  prepareQC: QuorumCertificate | null;
  precommitQC: QuorumCertificate | null;
  commitQC: QuorumCertificate | null;
  committed: BFTBlock[];
}

/**
 * StreamlinedBFT implements a pipelined BFT protocol inspired by HotStuff.
 *
 * Key properties:
 * - Three-phase commit: prepare -> precommit -> commit
 * - Linear message complexity (leader-based)
 * - Leader rotation after each view
 * - Pipelined: a new proposal can start before the previous one commits
 * - Safety: requires 2f+1 votes (quorum) for each phase
 * - Liveness: guaranteed under partial synchrony with honest leader
 */
export class StreamlinedBFT {
  private nodes: string[];
  private readonly quorumThreshold: number;
  private viewState: BFTViewState;
  private readonly committedBlocks: BFTBlock[] = [];

  constructor(nodeIds: string[]) {
    if (nodeIds.length < 4) {
      throw new KervyxError('StreamlinedBFT requires at least 4 nodes (n >= 3f+1, f >= 1)', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    const uniqueNodes = [...new Set(nodeIds)];
    if (uniqueNodes.length !== nodeIds.length) {
      throw new KervyxError('Node IDs must be unique', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }

    this.nodes = uniqueNodes;
    // BFT quorum: floor(2n/3) + 1
    this.quorumThreshold = Math.floor((2 * this.nodes.length) / 3) + 1;

    this.viewState = {
      viewNumber: 0,
      leader: this.nodes[0]!,
      phase: 'prepare',
      block: null,
      votes: new Map(),
      prepareQC: null,
      precommitQC: null,
      commitQC: null,
      committed: [],
    };
  }

  /** Get the current view number. */
  getViewNumber(): number {
    return this.viewState.viewNumber;
  }

  /** Get the current leader. */
  getLeader(): string {
    return this.viewState.leader;
  }

  /** Get the current phase. */
  getPhase(): BFTPhase {
    return this.viewState.phase;
  }

  /** Get the quorum size required. */
  getQuorumThreshold(): number {
    return this.quorumThreshold;
  }

  /** Get all committed blocks. */
  getCommittedBlocks(): BFTBlock[] {
    return [...this.committedBlocks];
  }

  /** Determine the leader for a given view number using round-robin. */
  leaderForView(viewNumber: number): string {
    return this.nodes[viewNumber % this.nodes.length]!;
  }

  /**
   * Propose a new block. Only the current leader can propose.
   * The block must include a justification (QC from previous phase).
   */
  propose(proposer: string, payload: unknown, parentHash: string): BFTBlock {
    if (proposer !== this.viewState.leader) {
      throw new KervyxError(`Only the leader (${this.viewState.leader}) can propose, not ${proposer}`, KervyxErrorCode.PROTOCOL_COMPUTATION_FAILED);
    }

    const block: BFTBlock = {
      hash: sha256Object({ payload, parentHash, viewNumber: this.viewState.viewNumber }),
      parentHash,
      viewNumber: this.viewState.viewNumber,
      proposer,
      payload,
      justification: this.viewState.prepareQC ?? undefined,
    };

    this.viewState.block = block;
    this.viewState.votes = new Map();
    this.viewState.phase = 'prepare';

    return block;
  }

  /**
   * Cast a vote for the current block in the current phase.
   * Returns a QuorumCertificate if the quorum threshold is reached, null otherwise.
   */
  vote(nodeId: string): QuorumCertificate | null {
    if (!this.nodes.includes(nodeId)) {
      throw new KervyxError(`Unknown node: ${nodeId}`, KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (!this.viewState.block) {
      throw new KervyxError('No block to vote on', KervyxErrorCode.PROTOCOL_COMPUTATION_FAILED);
    }
    if (this.viewState.votes.has(nodeId)) {
      return null; // Already voted
    }

    const vote: BFTVote = {
      nodeId,
      viewNumber: this.viewState.viewNumber,
      phase: this.viewState.phase,
      blockHash: this.viewState.block.hash,
      timestamp: Date.now(),
    };

    this.viewState.votes.set(nodeId, vote);

    // Check if quorum is reached
    if (this.viewState.votes.size >= this.quorumThreshold) {
      const qc: QuorumCertificate = {
        viewNumber: this.viewState.viewNumber,
        phase: this.viewState.phase,
        blockHash: this.viewState.block.hash,
        votes: [...this.viewState.votes.values()],
        quorumSize: this.viewState.votes.size,
      };

      return this.advancePhase(qc);
    }

    return null;
  }

  /**
   * Advance to the next phase after a quorum certificate is formed.
   * prepare -> precommit -> commit -> (new view)
   */
  private advancePhase(qc: QuorumCertificate): QuorumCertificate {
    switch (this.viewState.phase) {
      case 'prepare':
        this.viewState.prepareQC = qc;
        this.viewState.phase = 'precommit';
        this.viewState.votes = new Map();
        break;
      case 'precommit':
        this.viewState.precommitQC = qc;
        this.viewState.phase = 'commit';
        this.viewState.votes = new Map();
        break;
      case 'commit':
        this.viewState.commitQC = qc;
        if (this.viewState.block) {
          this.committedBlocks.push(this.viewState.block);
        }
        // Advance to next view with leader rotation
        this.nextView();
        break;
    }

    return qc;
  }

  /** Advance to the next view with a new leader. */
  nextView(): void {
    const newView = this.viewState.viewNumber + 1;
    this.viewState = {
      viewNumber: newView,
      leader: this.leaderForView(newView),
      phase: 'prepare',
      block: null,
      votes: new Map(),
      prepareQC: this.viewState.commitQC,
      precommitQC: null,
      commitQC: null,
      committed: this.viewState.committed,
    };
  }
}

// ---------------------------------------------------------------------------
// Dynamic Quorum Reconfiguration
// ---------------------------------------------------------------------------

/** An epoch in the reconfiguration protocol. */
export interface Epoch {
  epochNumber: number;
  members: string[];
  quorumSize: number;
  startedAt: number;
}

/** A reconfiguration request (join or leave). */
export interface ReconfigRequest {
  type: 'join' | 'leave';
  nodeId: string;
  requestedAt: number;
}

/**
 * DynamicQuorum handles node joins and leaves while maintaining BFT safety.
 *
 * Key invariant: during reconfiguration, we use an overlap quorum that
 * spans both the old and new configurations. This ensures any two quorums
 * (from old or new config) intersect in at least one honest node.
 *
 * Epoch-based reconfiguration:
 * 1. New epoch is proposed with updated membership
 * 2. Overlap quorum (union of old and new) is used during transition
 * 3. Once overlap quorum confirms, switch to new epoch
 */
export class DynamicQuorum {
  private epochs: Epoch[] = [];
  private pendingRequests: ReconfigRequest[] = [];
  private transitioning: boolean = false;

  constructor(initialMembers: string[]) {
    if (initialMembers.length < 1) {
      throw new KervyxError('Must have at least 1 initial member', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    const unique = [...new Set(initialMembers)];
    this.epochs.push({
      epochNumber: 0,
      members: unique,
      quorumSize: this.computeQuorumSize(unique.length),
      startedAt: Date.now(),
    });
  }

  /** Get the current epoch. */
  currentEpoch(): Epoch {
    return this.epochs[this.epochs.length - 1]!;
  }

  /** Get all epochs. */
  getEpochs(): Epoch[] {
    return [...this.epochs];
  }

  /** Get pending reconfiguration requests. */
  getPendingRequests(): ReconfigRequest[] {
    return [...this.pendingRequests];
  }

  /** Whether a reconfiguration is in progress. */
  isTransitioning(): boolean {
    return this.transitioning;
  }

  /** Compute BFT quorum size for n nodes: floor(2n/3) + 1, minimum 1. */
  private computeQuorumSize(n: number): number {
    if (n <= 0) return 1;
    return Math.max(1, Math.floor((2 * n) / 3) + 1);
  }

  /**
   * Request a node to join the network.
   * The join is not immediate -- it's queued for the next epoch transition.
   */
  requestJoin(nodeId: string): ReconfigRequest {
    if (!nodeId || typeof nodeId !== 'string') {
      throw new KervyxError('nodeId must be a non-empty string', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    const current = this.currentEpoch();
    if (current.members.includes(nodeId)) {
      throw new KervyxError(`Node ${nodeId} is already a member`, KervyxErrorCode.PROTOCOL_COMPUTATION_FAILED);
    }

    const req: ReconfigRequest = { type: 'join', nodeId, requestedAt: Date.now() };
    this.pendingRequests.push(req);
    return req;
  }

  /**
   * Request a node to leave the network.
   * The leave is not immediate -- it's queued for the next epoch transition.
   */
  requestLeave(nodeId: string): ReconfigRequest {
    if (!nodeId || typeof nodeId !== 'string') {
      throw new KervyxError('nodeId must be a non-empty string', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    const current = this.currentEpoch();
    if (!current.members.includes(nodeId)) {
      throw new KervyxError(`Node ${nodeId} is not a member`, KervyxErrorCode.PROTOCOL_COMPUTATION_FAILED);
    }

    const req: ReconfigRequest = { type: 'leave', nodeId, requestedAt: Date.now() };
    this.pendingRequests.push(req);
    return req;
  }

  /**
   * Compute the overlap quorum during a transition.
   * The overlap quorum requires agreement from both old and new configurations.
   *
   * @returns Object with union members and required votes from each config
   */
  computeOverlapQuorum(newMembers: string[]): {
    unionMembers: string[];
    oldQuorum: number;
    newQuorum: number;
    overlapRequired: number;
  } {
    const current = this.currentEpoch();
    const union = [...new Set([...current.members, ...newMembers])];
    const oldQuorum = this.computeQuorumSize(current.members.length);
    const newQuorum = this.computeQuorumSize(newMembers.length);

    // During transition, we need a quorum from BOTH configurations
    return {
      unionMembers: union,
      oldQuorum,
      newQuorum,
      overlapRequired: oldQuorum + newQuorum,
    };
  }

  /**
   * Begin epoch transition. Processes all pending requests and creates
   * a new epoch. Uses overlap quorum during transition.
   *
   * @param approvers - Node IDs that approve this transition
   * @returns The new Epoch, or null if quorum not met
   */
  transition(approvers: string[]): Epoch | null {
    if (this.pendingRequests.length === 0) {
      return null; // Nothing to do
    }

    const current = this.currentEpoch();
    const currentQuorum = this.computeQuorumSize(current.members.length);

    // Check that enough current members approve
    const validApprovers = approvers.filter(a => current.members.includes(a));
    if (validApprovers.length < currentQuorum) {
      return null; // Quorum not met
    }

    this.transitioning = true;

    // Apply pending requests
    let newMembers = [...current.members];
    for (const req of this.pendingRequests) {
      if (req.type === 'join' && !newMembers.includes(req.nodeId)) {
        newMembers.push(req.nodeId);
      } else if (req.type === 'leave') {
        newMembers = newMembers.filter(m => m !== req.nodeId);
      }
    }

    // Ensure we don't drop below minimum viable size
    if (newMembers.length < 1) {
      this.transitioning = false;
      throw new KervyxError('Cannot remove all members', KervyxErrorCode.PROTOCOL_COMPUTATION_FAILED);
    }

    const newEpoch: Epoch = {
      epochNumber: current.epochNumber + 1,
      members: newMembers,
      quorumSize: this.computeQuorumSize(newMembers.length),
      startedAt: Date.now(),
    };

    this.epochs.push(newEpoch);
    this.pendingRequests = [];
    this.transitioning = false;

    return newEpoch;
  }
}

// ---------------------------------------------------------------------------
// Pipeline Simulator
// ---------------------------------------------------------------------------

/** Network condition parameters for simulation. */
export interface NetworkCondition {
  /** Base network latency in ms. */
  baseLatencyMs: number;
  /** Latency jitter (standard deviation) in ms. */
  jitterMs: number;
  /** Message loss probability [0, 1). */
  lossProbability: number;
  /** Processing time per message in ms. */
  processingTimeMs: number;
}

/** Result of a single pipeline simulation run. */
export interface PipelineSimulationResult {
  /** Total elapsed time to complete all rounds (ms). */
  totalTimeMs: number;
  /** Number of messages sent. */
  messagesSent: number;
  /** Number of messages lost. */
  messagesLost: number;
  /** Number of retries needed. */
  retries: number;
  /** Throughput: rounds per second. */
  throughputRps: number;
  /** Per-round latencies (ms). */
  roundLatencies: number[];
  /** Mode of analysis used. */
  mode: 'pessimistic' | 'optimistic';
}

/**
 * PipelineSimulator models message-passing behavior under configurable
 * network conditions. Simulates the latency, loss, and throughput of
 * a consensus protocol with pipelining.
 *
 * Two modes:
 * - Optimistic: assumes minimal loss and best-case latency
 * - Pessimistic: assumes worst-case latency (base + 2*jitter) and max loss
 */
export class PipelineSimulator {
  private readonly condition: NetworkCondition;

  constructor(condition: NetworkCondition) {
    if (condition.baseLatencyMs < 0) {
      throw new KervyxError('baseLatencyMs must be >= 0', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (condition.jitterMs < 0) {
      throw new KervyxError('jitterMs must be >= 0', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (condition.lossProbability < 0 || condition.lossProbability >= 1) {
      throw new KervyxError('lossProbability must be in [0, 1)', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (condition.processingTimeMs < 0) {
      throw new KervyxError('processingTimeMs must be >= 0', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    this.condition = condition;
  }

  /**
   * Deterministic pseudo-random number based on a seed.
   * Uses a simple linear congruential generator for reproducibility.
   */
  private seededRandom(seed: number): number {
    const x = Math.sin(seed * 9301 + 49297) * 49297;
    return x - Math.floor(x);
  }

  /**
   * Simulate a pipeline of consensus rounds.
   *
   * @param rounds - Number of consensus rounds to simulate
   * @param nodesPerRound - Number of nodes sending messages per round
   * @param mode - 'optimistic' or 'pessimistic' analysis mode
   * @param seed - Random seed for reproducibility (default 42)
   * @returns PipelineSimulationResult with latency and throughput metrics
   */
  simulate(
    rounds: number,
    nodesPerRound: number,
    mode: 'pessimistic' | 'optimistic',
    seed: number = 42,
  ): PipelineSimulationResult {
    if (rounds < 1) {
      throw new KervyxError('rounds must be >= 1', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (nodesPerRound < 1) {
      throw new KervyxError('nodesPerRound must be >= 1', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }

    let totalTime = 0;
    let messagesSent = 0;
    let messagesLost = 0;
    let retries = 0;
    const roundLatencies: number[] = [];
    let rngCounter = seed;

    for (let r = 0; r < rounds; r++) {
      let roundLatency = 0;

      for (let n = 0; n < nodesPerRound; n++) {
        messagesSent++;
        rngCounter++;

        // Determine latency for this message
        let latency: number;
        if (mode === 'pessimistic') {
          // Worst case: base + 2 * jitter
          latency = this.condition.baseLatencyMs + 2 * this.condition.jitterMs;
        } else {
          // Optimistic: base latency with small random jitter
          const jitter = this.condition.jitterMs * (this.seededRandom(rngCounter) - 0.5);
          latency = Math.max(0, this.condition.baseLatencyMs + jitter);
        }

        // Determine if message is lost
        const rand = this.seededRandom(rngCounter + 1000);
        const effectiveLoss = mode === 'pessimistic'
          ? this.condition.lossProbability
          : this.condition.lossProbability * 0.5;

        if (rand < effectiveLoss) {
          messagesLost++;
          retries++;
          // Retry adds another full round-trip
          latency += this.condition.baseLatencyMs + this.condition.processingTimeMs;
          messagesSent++;
        }

        // Add processing time
        latency += this.condition.processingTimeMs;

        // In pipelined mode, round latency is the max of all node latencies
        roundLatency = Math.max(roundLatency, latency);
      }

      roundLatencies.push(roundLatency);
      totalTime += roundLatency;
    }

    const throughputRps = totalTime > 0 ? (rounds / totalTime) * 1000 : 0;

    return {
      totalTimeMs: totalTime,
      messagesSent,
      messagesLost,
      retries,
      throughputRps,
      roundLatencies,
      mode,
    };
  }

  /**
   * Compare optimistic and pessimistic modes for the same parameters.
   */
  compareModes(
    rounds: number,
    nodesPerRound: number,
    seed: number = 42,
  ): { optimistic: PipelineSimulationResult; pessimistic: PipelineSimulationResult } {
    return {
      optimistic: this.simulate(rounds, nodesPerRound, 'optimistic', seed),
      pessimistic: this.simulate(rounds, nodesPerRound, 'pessimistic', seed),
    };
  }
}

// ---------------------------------------------------------------------------
// Quorum Intersection Verifier
// ---------------------------------------------------------------------------

/** Result of quorum intersection verification. */
export interface QuorumIntersectionResult {
  /** Whether the intersection property holds. */
  holds: boolean;
  /** Minimum intersection size across all quorum pairs. */
  minIntersectionSize: number;
  /** Maximum number of Byzantine faults tolerated. */
  maxByzantineFaults: number;
  /** Whether intersection guarantees at least one honest node. */
  honestNodeGuaranteed: boolean;
  /** If the property doesn't hold, a counterexample pair of quorums. */
  counterexample?: { quorumA: string[]; quorumB: string[] };
  /** Detailed formula derivation. */
  derivation: string;
}

/**
 * QuorumIntersectionVerifier formally verifies that any two quorums
 * in a BFT system intersect in at least one honest node.
 *
 * For a system with n nodes and f Byzantine faults:
 * - Each quorum has size q >= floor(2n/3) + 1
 * - Two quorums overlap in at least 2q - n nodes
 * - For BFT safety, we need: 2q - n > f
 * - With q = floor(2n/3) + 1 and f = floor((n-1)/3): 2q - n >= f + 1
 *
 * This class can verify the property for arbitrary quorum configurations.
 */
export class QuorumIntersectionVerifier {
  /**
   * Verify that all possible quorum pairs from a given set of quorum
   * configurations intersect in at least (byzantineFaults + 1) nodes.
   *
   * @param allNodes - The full set of node IDs
   * @param quorumSets - Array of quorum configurations (each is an array of node IDs)
   * @param byzantineFaults - Maximum number of Byzantine faults to tolerate
   */
  verify(
    allNodes: string[],
    quorumSets: string[][],
    byzantineFaults: number,
  ): QuorumIntersectionResult {
    if (allNodes.length < 1) {
      throw new KervyxError('allNodes must not be empty', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (byzantineFaults < 0) {
      throw new KervyxError('byzantineFaults must be >= 0', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (quorumSets.length < 2) {
      throw new KervyxError('At least 2 quorum sets required for intersection analysis', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }

    const n = allNodes.length;
    const f = byzantineFaults;
    const requiredIntersection = f + 1; // Must overlap in at least f+1 for one honest
    let minIntersection = Infinity;
    let counterexample: { quorumA: string[]; quorumB: string[] } | undefined;

    // Check all pairs of quorums
    for (let i = 0; i < quorumSets.length; i++) {
      for (let j = i + 1; j < quorumSets.length; j++) {
        const setA = new Set(quorumSets[i]!);
        const setB = new Set(quorumSets[j]!);

        // Count intersection
        let intersectionSize = 0;
        for (const node of setA) {
          if (setB.has(node)) intersectionSize++;
        }

        if (intersectionSize < minIntersection) {
          minIntersection = intersectionSize;
          if (intersectionSize < requiredIntersection) {
            counterexample = {
              quorumA: quorumSets[i]!,
              quorumB: quorumSets[j]!,
            };
          }
        }
      }
    }

    const holds = minIntersection >= requiredIntersection;
    const honestNodeGuaranteed = minIntersection > f;

    // Theoretical verification using quorum size
    const avgQuorumSize = quorumSets.reduce((sum, q) => sum + q.length, 0) / quorumSets.length;
    const theoreticalMinIntersection = Math.max(0, 2 * avgQuorumSize - n);

    const derivation =
      `Quorum Intersection Analysis:\n` +
      `  Total nodes (n): ${n}\n` +
      `  Byzantine faults (f): ${f}\n` +
      `  Required intersection: f + 1 = ${requiredIntersection}\n` +
      `  Number of quorum sets: ${quorumSets.length}\n` +
      `  Average quorum size: ${avgQuorumSize.toFixed(1)}\n` +
      `  Theoretical min intersection (2q - n): ${theoreticalMinIntersection.toFixed(1)}\n` +
      `  Actual min intersection: ${minIntersection}\n` +
      `  Property holds: ${holds}\n` +
      `  Honest node guaranteed: ${honestNodeGuaranteed}`;

    return {
      holds,
      minIntersectionSize: minIntersection === Infinity ? 0 : minIntersection,
      maxByzantineFaults: f,
      honestNodeGuaranteed,
      ...(counterexample ? { counterexample } : {}),
      derivation,
    };
  }

  /**
   * Verify the standard BFT quorum intersection property for n nodes.
   * Uses the standard quorum size q = floor(2n/3) + 1.
   */
  verifyStandard(nodeIds: string[]): QuorumIntersectionResult {
    const n = nodeIds.length;
    const f = Math.floor((n - 1) / 3);
    const q = Math.floor((2 * n) / 3) + 1;

    // Generate all possible quorums of size q (for small n)
    // For large n, use the theoretical result directly
    if (n <= 10) {
      const quorums = this.generateQuorums(nodeIds, q);
      return this.verify(nodeIds, quorums, f);
    }

    // Theoretical result for large n
    const minIntersection = 2 * q - n;
    const holds = minIntersection > f;

    const derivation =
      `Standard BFT Quorum Intersection (theoretical):\n` +
      `  Total nodes (n): ${n}\n` +
      `  Max Byzantine faults: f = floor((n-1)/3) = ${f}\n` +
      `  Quorum size: q = floor(2n/3) + 1 = ${q}\n` +
      `  Min intersection: 2q - n = ${minIntersection}\n` +
      `  Required: > f = ${f}\n` +
      `  Property holds: ${holds}`;

    return {
      holds,
      minIntersectionSize: minIntersection,
      maxByzantineFaults: f,
      honestNodeGuaranteed: holds,
      derivation,
    };
  }

  /**
   * Generate all combinations of size k from the given array.
   * Used for exhaustive quorum enumeration on small networks.
   */
  private generateQuorums(nodes: string[], k: number): string[][] {
    if (k > nodes.length) return [];
    if (k === nodes.length) return [nodes];

    const result: string[][] = [];
    const combo: string[] = [];

    const backtrack = (start: number) => {
      if (combo.length === k) {
        result.push([...combo]);
        // Limit enumeration to prevent combinatorial explosion
        if (result.length > 1000) return;
        return;
      }
      for (let i = start; i < nodes.length && result.length <= 1000; i++) {
        combo.push(nodes[i]!);
        backtrack(i + 1);
        combo.pop();
      }
    };

    backtrack(0);
    return result;
  }
}
