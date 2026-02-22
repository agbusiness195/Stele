/**
 * Trust-gated access control for the Kervyx protocol.
 *
 * Agents without Kervyx covenant compliance get no access to premium APIs.
 * Trust scores determine the access tier: denied, basic, standard, or premium.
 * Supports grace periods for new agents and bypass tokens for testing.
 *
 * @packageDocumentation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

/** Configuration for trust-gated access control. */
export interface TrustGateConfig {
  /** Minimum trust score required for any access. Default: 0.5 */
  minimumTrustScore: number;
  /** Trust score threshold for premium access. Default: 0.9 */
  premiumThreshold: number;
  /** Grace period in milliseconds for newly registered agents. Default: 86400000 (24h) */
  gracePeriodMs: number;
  /** Pre-authorized bypass tokens for testing. Default: [] */
  bypassTokens: string[];
}

/** Access level granted to an agent based on their trust score. */
export type AccessLevel = 'denied' | 'basic' | 'standard' | 'premium';

/** The decision output from evaluating an agent's access level. */
export interface GateDecision {
  /** The agent being evaluated. */
  agentId: string;
  /** The access level granted. */
  accessLevel: AccessLevel;
  /** The agent's trust score used for evaluation. */
  trustScore: number;
  /** Human-readable reason for the decision. */
  reason: string;
  /** Timestamp when this decision expires. */
  expiresAt: number;
  /** Maximum requests per minute allowed at this access level. */
  rateLimit: number;
}

// ─── Rate limits per access level ────────────────────────────────────────────

const RATE_LIMITS: Record<AccessLevel, number> = {
  denied: 0,
  basic: 10,
  standard: 100,
  premium: 1000,
};

/** Decision TTL: 1 hour. */
const DECISION_TTL_MS = 3600000;

// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Create a trust gate configuration with sensible defaults.
 *
 * @param config - Optional partial configuration overrides.
 * @returns A complete TrustGateConfig.
 */
export function createTrustGate(config?: Partial<TrustGateConfig>): TrustGateConfig {
  return {
    minimumTrustScore: config?.minimumTrustScore ?? 0.5,
    premiumThreshold: config?.premiumThreshold ?? 0.9,
    gracePeriodMs: config?.gracePeriodMs ?? 86400000,
    bypassTokens: config?.bypassTokens ?? [],
  };
}

// ─── Evaluation ──────────────────────────────────────────────────────────────

/**
 * Evaluate an agent's access level based on their trust score and configuration.
 *
 * Decision logic (checked in order):
 * 1. If a valid bypass token is provided, grant `premium` access.
 * 2. If the agent is within the grace period, grant at least `basic` access.
 * 3. If trust score is below the minimum, deny access.
 * 4. Otherwise, assign tier based on score thresholds.
 *
 * @param gate - The trust gate configuration.
 * @param params - Agent parameters for evaluation.
 * @returns A GateDecision with the access level and metadata.
 */
export function evaluateAccess(
  gate: TrustGateConfig,
  params: {
    agentId: string;
    trustScore: number;
    registeredAt?: number;
    bypassToken?: string;
  },
): GateDecision {
  const { agentId, trustScore, registeredAt, bypassToken } = params;
  const now = Date.now();

  // 1. Bypass token check
  if (bypassToken && gate.bypassTokens.includes(bypassToken)) {
    return {
      agentId,
      accessLevel: 'premium',
      trustScore,
      reason: 'Access granted via bypass token',
      expiresAt: now + DECISION_TTL_MS,
      rateLimit: RATE_LIMITS.premium,
    };
  }

  // 2. Grace period check
  const inGracePeriod =
    registeredAt !== undefined && registeredAt + gate.gracePeriodMs > now;

  // 3. Below minimum threshold
  if (trustScore < gate.minimumTrustScore) {
    if (inGracePeriod) {
      return {
        agentId,
        accessLevel: 'basic',
        trustScore,
        reason: 'Access granted during grace period for new agent',
        expiresAt: now + DECISION_TTL_MS,
        rateLimit: RATE_LIMITS.basic,
      };
    }

    return {
      agentId,
      accessLevel: 'denied',
      trustScore,
      reason: `Trust score ${trustScore} is below minimum threshold ${gate.minimumTrustScore}`,
      expiresAt: now + DECISION_TTL_MS,
      rateLimit: RATE_LIMITS.denied,
    };
  }

  // 4. Tiered access based on trust score
  if (trustScore >= gate.premiumThreshold) {
    return {
      agentId,
      accessLevel: 'premium',
      trustScore,
      reason: `Trust score ${trustScore} qualifies for premium access`,
      expiresAt: now + DECISION_TTL_MS,
      rateLimit: RATE_LIMITS.premium,
    };
  }

  if (trustScore >= 0.7) {
    return {
      agentId,
      accessLevel: 'standard',
      trustScore,
      reason: `Trust score ${trustScore} qualifies for standard access`,
      expiresAt: now + DECISION_TTL_MS,
      rateLimit: RATE_LIMITS.standard,
    };
  }

  return {
    agentId,
    accessLevel: 'basic',
    trustScore,
    reason: `Trust score ${trustScore} qualifies for basic access`,
    expiresAt: now + DECISION_TTL_MS,
    rateLimit: RATE_LIMITS.basic,
  };
}

// ─── Revenue Analysis ────────────────────────────────────────────────────────

/**
 * Calculate the revenue lift from Kervyx adoption.
 *
 * Non-Kervyx agents pay basic pricing (1x). Kervyx agents at standard tier
 * also pay 1x, while Kervyx agents at premium tier pay the premium price
 * multiplier. The lift percentage measures how much more revenue Kervyx
 * adoption generates compared to a baseline of all agents at 1x.
 *
 * @param params - Revenue calculation parameters.
 * @returns Total revenue, Kervyx-attributable revenue, and lift percentage.
 */
export function calculateRevenueLift(params: {
  totalAgents: number;
  kervyxAdoptionRate: number;
  premiumRate: number;
  premiumPriceMultiplier: number;
}): { totalRevenue: number; kervyxRevenue: number; liftPercentage: number } {
  const { totalAgents, kervyxAdoptionRate, premiumRate, premiumPriceMultiplier } = params;

  const kervyxAgents = totalAgents * kervyxAdoptionRate;
  const nonKervyxAgents = totalAgents - kervyxAgents;
  const premiumAgents = kervyxAgents * premiumRate;
  const standardKervyxAgents = kervyxAgents - premiumAgents;

  // Non-Kervyx agents: basic pricing (1x each)
  const nonKervyxRevenue = nonKervyxAgents * 1;

  // Kervyx standard agents: 1x each
  const standardRevenue = standardKervyxAgents * 1;

  // Kervyx premium agents: premiumPriceMultiplier each
  const premiumRevenue = premiumAgents * premiumPriceMultiplier;

  const kervyxRevenue = standardRevenue + premiumRevenue;
  const totalRevenue = nonKervyxRevenue + kervyxRevenue;

  // Baseline: all agents at 1x
  const baseRevenue = totalAgents * 1;

  const liftPercentage =
    baseRevenue === 0 ? 0 : ((kervyxRevenue - baseRevenue) / baseRevenue) * 100;

  return {
    totalRevenue,
    kervyxRevenue,
    liftPercentage,
  };
}
