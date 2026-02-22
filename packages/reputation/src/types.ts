import type { HashHex } from '@kervyx/crypto';

export interface ExecutionReceipt {
  id: HashHex;
  covenantId: HashHex;
  agentIdentityHash: HashHex;
  principalPublicKey: string;
  outcome: 'fulfilled' | 'partial' | 'failed' | 'breached';
  breachSeverity?: import('@kervyx/ccl').Severity;
  proofHash: HashHex;
  durationMs: number;
  completedAt: string;
  agentSignature: string;
  principalSignature?: string;
  previousReceiptHash: HashHex | null;
  receiptHash: HashHex;
}

export interface ReputationScore {
  agentIdentityHash: HashHex;
  totalExecutions: number;
  fulfilled: number;
  partial: number;
  failed: number;
  breached: number;
  successRate: number;
  weightedScore: number;
  receiptsMerkleRoot: HashHex;
  lastUpdatedAt: string;
  currentStake: number;
  totalBurned: number;
}

export interface ReputationStake {
  id: HashHex;
  agentIdentityHash: HashHex;
  covenantId: HashHex;
  amount: number;
  status: 'active' | 'released' | 'burned';
  stakedAt: string;
  resolvedAt?: string;
  signature: string;
}

export interface ReputationDelegation {
  id: HashHex;
  sponsorIdentityHash: HashHex;
  protégéIdentityHash: HashHex;
  riskAmount: number;
  scopes: string[];
  expiresAt: string;
  status: 'active' | 'expired' | 'burned' | 'revoked';
  sponsorSignature: string;
  protégéSignature: string;
}

export interface Endorsement {
  id: HashHex;
  endorserIdentityHash: HashHex;
  endorsedIdentityHash: HashHex;
  basis: {
    covenantsCompleted: number;
    breachRate: number;
    averageOutcomeScore?: number;
  };
  scopes: string[];
  weight: number;
  issuedAt: string;
  signature: string;
}

export interface ScoringConfig {
  recencyDecay: number;
  recencyPeriod: number;
  breachPenalty: Record<import('@kervyx/ccl').Severity, number>;
  minimumExecutions: number;
  endorsementWeight: number;
}

// ---------------------------------------------------------------------------
// Item 30: Trust as Bounded Resource
// ---------------------------------------------------------------------------

/** A pool of trust backed by collateral. Trust cannot exceed economic value risked. */
export interface ResourcePool {
  totalCollateral: number;
  allocatedTrust: number;
  availableTrust: number;
  utilizationRatio: number;
  participants: Map<string, number>; // agentId -> allocated trust
}

/** An event where an agent's stake is slashed for misbehaviour. */
export interface SlashingEvent {
  agentId: string;
  amount: number;
  reason: string;
  timestamp: number;
  redistributed: boolean;
}

// ---------------------------------------------------------------------------
// Item 46: Multidimensional Trust Profile (Anti-Gaming)
// ---------------------------------------------------------------------------

/** A single dimension of a trust profile. */
export interface TrustDimension {
  name: string;
  score: number; // 0-1
  weight: number;
  evidence: number; // number of data points backing this score
}

/** A multidimensional trust profile with five dimensions that trade off against each other. */
export interface MultidimensionalProfile {
  agentId: string;
  dimensions: {
    hardEnforcement: TrustDimension;    // coverage of hard-enforced constraints
    attestationCoverage: TrustDimension; // % of actions with external attestation
    covenantBreadth: TrustDimension;     // scope of covenant commitments
    historyDepth: TrustDimension;        // length of verifiable track record
    stakeRatio: TrustDimension;          // economic value at risk relative to operations
  };
  compositeScore: number; // weighted geometric mean (prevents gaming one dimension)
  gamingResistance: number; // 0-1, how resistant to single-dimension gaming
}

// ---------------------------------------------------------------------------
// Item 75: Productive Staking Tiers
// ---------------------------------------------------------------------------

/** Staking tier levels. */
export type StakeTier = 'basic' | 'verified' | 'certified' | 'institutional';

/** Configuration for a staking tier. */
export interface StakeTierConfig {
  tier: StakeTier;
  minimumStake: number;
  verificationIncomeRate: number; // per-query income rate
  marketplaceRankBoost: number;   // multiplier for marketplace ranking
  governanceWeight: number;        // voting weight multiplier
  maxDelegations: number;          // how many agents can delegate to this one
}

/** An agent that has staked to a tier. */
export interface StakedAgent {
  agentId: string;
  tier: StakeTier;
  stakedAmount: number;
  earnedIncome: number;
  queriesServed: number;
  config: StakeTierConfig;
}
