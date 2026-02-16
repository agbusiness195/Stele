export type {
  HonestyParameters,
  HonestyProof,
} from './types';

import { SteleError, SteleErrorCode } from '@stele/types';
import type { HonestyParameters, HonestyProof } from './types';

/**
 * Validate that all HonestyParameters are within acceptable ranges.
 * Throws descriptive errors on any violation.
 */
export function validateParameters(params: Partial<HonestyParameters>): void {
  if (params.stakeAmount !== undefined && params.stakeAmount < 0) {
    throw new SteleError(`stakeAmount must be >= 0, got ${params.stakeAmount}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (params.detectionProbability !== undefined) {
    if (params.detectionProbability < 0 || params.detectionProbability > 1) {
      throw new SteleError(
        `detectionProbability must be in [0, 1], got ${params.detectionProbability}`,
      );
    }
  }
  if (params.reputationValue !== undefined && params.reputationValue < 0) {
    throw new SteleError(`reputationValue must be >= 0, got ${params.reputationValue}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (params.maxViolationGain !== undefined && params.maxViolationGain < 0) {
    throw new SteleError(`maxViolationGain must be >= 0, got ${params.maxViolationGain}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (params.coburn !== undefined && params.coburn < 0) {
    throw new SteleError(`coburn must be >= 0, got ${params.coburn}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
}

function validateFull(params: HonestyParameters): void {
  validateParameters(params);
}

/**
 * Core theorem: Honesty dominates when:
 *   stake * detectionProbability + reputationValue + coburn > maxViolationGain
 *
 * Prove (or disprove) that honesty is the dominant strategy for the given parameters.
 * Returns a structured proof with step-by-step derivation.
 */
export function proveHonesty(params: HonestyParameters): HonestyProof {
  validateFull(params);

  const { stakeAmount, detectionProbability, reputationValue, maxViolationGain, coburn } = params;

  const s = stakeAmount;
  const d = detectionProbability;
  const r = reputationValue;
  const c = coburn;
  const g = maxViolationGain;

  const total = s * d + r + c;
  const margin = total - g;
  const isDominantStrategy = margin > 0;

  const requiredStake = minimumStake({
    detectionProbability,
    reputationValue,
    maxViolationGain,
    coburn,
  });

  const requiredDetection = minimumDetection({
    stakeAmount,
    reputationValue,
    maxViolationGain,
    coburn,
  });

  const formula =
    `Expected cost of dishonesty: stake(${s}) × detection(${d}) + reputation(${r}) + coburn(${c}) = ${total}\n` +
    `Maximum gain from violation: ${g}\n` +
    `Margin: ${total} - ${g} = ${margin}\n` +
    `Honesty is ${isDominantStrategy ? 'dominant' : 'not dominant'} strategy`;

  return {
    isDominantStrategy,
    margin,
    requiredStake,
    requiredDetection,
    formula,
  };
}

/**
 * Compute the minimum stake required for honesty to dominate,
 * given all other parameters.
 *
 * minimumStake = (maxViolationGain - reputationValue - coburn) / detectionProbability
 * Clamped to max(0, result). If detectionProbability is 0, returns Infinity.
 */
export function minimumStake(
  params: Omit<HonestyParameters, 'stakeAmount'>,
): number {
  validateParameters(params);

  const { detectionProbability, reputationValue, maxViolationGain, coburn } = params;

  if (detectionProbability === 0) {
    return Infinity;
  }

  const raw = (maxViolationGain - reputationValue - coburn) / detectionProbability;
  return Math.max(0, raw);
}

/**
 * Compute the minimum detection probability required for honesty to dominate,
 * given all other parameters.
 *
 * minimumDetection = (maxViolationGain - reputationValue - coburn) / stakeAmount
 * Clamped to [0, 1]. If stakeAmount is 0, returns 1 (need 100% detection).
 */
export function minimumDetection(
  params: Omit<HonestyParameters, 'detectionProbability'>,
): number {
  validateParameters(params);

  const { stakeAmount, reputationValue, maxViolationGain, coburn } = params;

  if (stakeAmount === 0) {
    return 1;
  }

  const raw = (maxViolationGain - reputationValue - coburn) / stakeAmount;
  return Math.max(0, Math.min(1, raw));
}

/**
 * Compute the expected cost an agent would incur from a breach:
 *   stakeAmount * detectionProbability + coburn
 */
export function expectedCostOfBreach(params: HonestyParameters): number {
  validateFull(params);
  return params.stakeAmount * params.detectionProbability + params.coburn;
}

/**
 * Compute the honesty margin:
 *   (stake * detection + reputation + coburn) - maxViolationGain
 *
 * Positive margin means honesty dominates.
 */
export function honestyMargin(params: HonestyParameters): number {
  validateFull(params);
  const { stakeAmount, detectionProbability, reputationValue, maxViolationGain, coburn } = params;
  return (stakeAmount * detectionProbability + reputationValue + coburn) - maxViolationGain;
}

// ---------------------------------------------------------------------------
// Repeated Game Equilibrium (Folk Theorem)
// ---------------------------------------------------------------------------

/**
 * Parameters for a repeated (iterated) game between two strategies.
 */
export interface RepeatedGameParams {
  /** Payoff when both cooperate (reward) */
  cooperatePayoff: number;
  /** Payoff when both defect (punishment) */
  defectPayoff: number;
  /** Payoff for defecting while opponent cooperates (temptation) */
  temptationPayoff: number;
  /** Payoff for cooperating while opponent defects (sucker's payoff) */
  suckerPayoff: number;
  /** Discount factor per round, in (0, 1). Higher = more patient agents. */
  discountFactor: number;
}

/**
 * Result of repeated game equilibrium analysis.
 */
export interface RepeatedGameResult {
  /** Whether cooperation can be sustained as a subgame-perfect equilibrium */
  cooperationSustainable: boolean;
  /** The minimum discount factor required for cooperation (Folk Theorem threshold) */
  minDiscountFactor: number;
  /** The actual discount factor provided */
  actualDiscountFactor: number;
  /** Margin: actualDiscountFactor - minDiscountFactor. Positive means cooperation is sustainable. */
  margin: number;
  /** Human-readable derivation */
  formula: string;
}

/**
 * Compute the discount factor threshold for cooperation in an infinitely
 * repeated game using the Folk Theorem / grim trigger strategy analysis.
 *
 * The Folk Theorem states that cooperation can be sustained as a subgame-perfect
 * Nash equilibrium in an infinitely repeated game if the discount factor delta
 * satisfies:
 *
 *   delta >= (T - R) / (T - P)
 *
 * where:
 *   T = temptation payoff (defect while other cooperates)
 *   R = reward payoff (mutual cooperation)
 *   P = punishment payoff (mutual defection)
 *   S = sucker payoff (cooperate while other defects)
 *
 * Preconditions (Prisoner's Dilemma structure): T > R > P > S
 *
 * Intuition: A sufficiently patient agent (high delta) values future cooperation
 * payoffs enough that the one-shot temptation gain is not worth the punishment
 * of perpetual defection.
 */
export function repeatedGameEquilibrium(params: RepeatedGameParams): RepeatedGameResult {
  const { cooperatePayoff: R, defectPayoff: P, temptationPayoff: T, suckerPayoff: S, discountFactor: delta } = params;

  // Validate payoff ordering: T > R > P > S (Prisoner's Dilemma structure)
  if (T <= R) {
    throw new SteleError(
      `temptationPayoff (${T}) must be > cooperatePayoff (${R}) for a valid dilemma`,
    );
  }
  if (R <= P) {
    throw new SteleError(
      `cooperatePayoff (${R}) must be > defectPayoff (${P}) for a valid dilemma`,
    );
  }
  if (P <= S) {
    throw new SteleError(
      `defectPayoff (${P}) must be > suckerPayoff (${S}) for a valid dilemma`,
    );
  }

  // Validate discount factor is in (0, 1)
  if (delta <= 0 || delta >= 1) {
    throw new SteleError(
      `discountFactor must be in (0, 1), got ${delta}`,
    );
  }

  // Folk Theorem threshold: delta_min = (T - R) / (T - P)
  const minDiscountFactor = (T - R) / (T - P);
  const margin = delta - minDiscountFactor;
  const cooperationSustainable = margin >= 0;

  const formula =
    `Folk Theorem threshold: delta_min = (T - R) / (T - P) = (${T} - ${R}) / (${T} - ${P}) = ${minDiscountFactor.toFixed(6)}\n` +
    `Actual discount factor: delta = ${delta}\n` +
    `Margin: ${delta} - ${minDiscountFactor.toFixed(6)} = ${margin.toFixed(6)}\n` +
    `Cooperation is ${cooperationSustainable ? 'sustainable' : 'not sustainable'} as equilibrium`;

  return {
    cooperationSustainable,
    minDiscountFactor,
    actualDiscountFactor: delta,
    margin,
    formula,
  };
}

// ---------------------------------------------------------------------------
// Coalition Stability (Core of Cooperative Game Theory)
// ---------------------------------------------------------------------------

/**
 * A characteristic function value for a coalition.
 * The coalition is represented as a sorted array of agent indices.
 */
export interface CoalitionValue {
  /** Sorted array of agent indices forming this coalition */
  coalition: number[];
  /** The value (payoff) this coalition can achieve on its own */
  value: number;
}

/**
 * Result of coalition stability analysis.
 */
export interface CoalitionStabilityResult {
  /** Whether the allocation is in the core (no blocking coalition exists) */
  isStable: boolean;
  /** List of blocking coalitions (coalitions that can profitably deviate) */
  blockingCoalitions: Array<{
    coalition: number[];
    coalitionValue: number;
    currentAllocation: number;
    surplus: number;
  }>;
  /** The total allocation vs the grand coalition value */
  efficiency: number;
  /** Human-readable summary */
  formula: string;
}

/**
 * Check whether an allocation is in the core of a cooperative game.
 *
 * In cooperative game theory, the "core" is the set of allocations where no
 * subset (coalition) of agents can do better by breaking away. Formally,
 * an allocation x is in the core if:
 *
 *   1. Group rationality: sum(x_i for all i) = v(N)  (efficiency)
 *   2. Coalition rationality: For every coalition S subset of N:
 *        sum(x_i for i in S) >= v(S)
 *
 * If any coalition S has sum(x_i for i in S) < v(S), that coalition is a
 * "blocking coalition" -- its members could do better by deviating.
 *
 * @param agentCount Number of agents (indexed 0 to agentCount-1)
 * @param allocation Array of payoffs allocated to each agent. Length must equal agentCount.
 * @param coalitionValues Array of CoalitionValue entries defining v(S) for subsets S.
 *        Must include the grand coalition (all agents). Unspecified coalitions default to v(S) = 0.
 */
export function coalitionStability(
  agentCount: number,
  allocation: number[],
  coalitionValues: CoalitionValue[],
): CoalitionStabilityResult {
  if (agentCount < 1) {
    throw new SteleError(`agentCount must be >= 1, got ${agentCount}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (allocation.length !== agentCount) {
    throw new SteleError(
      `allocation length (${allocation.length}) must equal agentCount (${agentCount})`,
    );
  }

  // Build a map from coalition key to value for fast lookup
  const valueMap = new Map<string, number>();
  for (const cv of coalitionValues) {
    const key = [...cv.coalition].sort((a, b) => a - b).join(',');
    valueMap.set(key, cv.value);
  }

  // Grand coalition value
  const grandCoalition = Array.from({ length: agentCount }, (_, i) => i);
  const grandKey = grandCoalition.join(',');
  const grandCoalitionValue = valueMap.get(grandKey);
  if (grandCoalitionValue === undefined) {
    throw new SteleError('coalitionValues must include the grand coalition (all agents)', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }

  // Efficiency check: sum of allocation vs grand coalition value
  const totalAllocation = allocation.reduce((s, v) => s + v, 0);
  const efficiency = grandCoalitionValue > 0 ? totalAllocation / grandCoalitionValue : 1;

  // Check all subsets (coalitions) for blocking
  const blockingCoalitions: CoalitionStabilityResult['blockingCoalitions'] = [];

  // Enumerate all non-empty proper subsets of agents
  const totalSubsets = 1 << agentCount; // 2^n
  for (let mask = 1; mask < totalSubsets - 1; mask++) {
    const coalition: number[] = [];
    for (let i = 0; i < agentCount; i++) {
      if (mask & (1 << i)) {
        coalition.push(i);
      }
    }

    const key = coalition.join(',');
    const coalitionValue = valueMap.get(key) ?? 0;
    const currentAllocation = coalition.reduce((s, i) => s + (allocation[i] ?? 0), 0);

    // A coalition blocks if it can get more by deviating
    if (coalitionValue > currentAllocation) {
      blockingCoalitions.push({
        coalition,
        coalitionValue,
        currentAllocation,
        surplus: coalitionValue - currentAllocation,
      });
    }
  }

  const isStable = blockingCoalitions.length === 0;

  const formula = blockingCoalitions.length === 0
    ? `Allocation is in the core: no coalition can profitably deviate.\n` +
      `Grand coalition value: ${grandCoalitionValue}, total allocation: ${totalAllocation}, efficiency: ${efficiency.toFixed(4)}`
    : `Allocation is NOT in the core: ${blockingCoalitions.length} blocking coalition(s) found.\n` +
      blockingCoalitions.map(bc =>
        `  Coalition {${bc.coalition.join(',')}} has v(S)=${bc.coalitionValue} > allocated=${bc.currentAllocation} (surplus=${bc.surplus.toFixed(4)})`
      ).join('\n') +
      `\nGrand coalition value: ${grandCoalitionValue}, total allocation: ${totalAllocation}, efficiency: ${efficiency.toFixed(4)}`;

  return {
    isStable,
    blockingCoalitions,
    efficiency,
    formula,
  };
}

// ---------------------------------------------------------------------------
// Mechanism Design (Incentive Compatibility)
// ---------------------------------------------------------------------------

/**
 * Parameters for mechanism design analysis.
 */
export interface MechanismDesignParams {
  /** The gain an agent gets from dishonest behavior */
  dishonestGain: number;
  /** The probability of detecting dishonest behavior, in [0, 1] */
  detectionProbability: number;
  /** Intrinsic cost the agent bears from being dishonest (moral cost, etc.), >= 0 */
  intrinsicHonestyCost?: number;
}

/**
 * Result of mechanism design analysis.
 */
export interface MechanismDesignResult {
  /** The minimum penalty to make honest behavior incentive-compatible */
  minimumPenalty: number;
  /**
   * Whether a finite penalty can enforce honesty.
   * False when detectionProbability is 0 and dishonestGain > intrinsicHonestyCost.
   */
  enforceable: boolean;
  /** The expected penalty given detection probability */
  expectedPenalty: number;
  /** Human-readable derivation */
  formula: string;
}

/**
 * Compute the minimum penalty required to make honest behavior
 * incentive-compatible in a mechanism design setting.
 *
 * An agent will behave honestly if the expected penalty for dishonesty
 * exceeds the gain from dishonesty:
 *
 *   detectionProbability * penalty + intrinsicHonestyCost >= dishonestGain
 *
 * Solving for the minimum penalty:
 *
 *   penalty_min = (dishonestGain - intrinsicHonestyCost) / detectionProbability
 *
 * This implements the Revelation Principle insight: a mechanism is
 * incentive-compatible if truth-telling is a dominant strategy, which
 * requires the penalty for lying to outweigh the benefit.
 *
 * When detectionProbability = 0 and dishonestGain > intrinsicHonestyCost,
 * no finite penalty can enforce honesty (enforceable = false).
 */
export function mechanismDesign(params: MechanismDesignParams): MechanismDesignResult {
  const { dishonestGain, detectionProbability, intrinsicHonestyCost = 0 } = params;

  if (dishonestGain < 0) {
    throw new SteleError(`dishonestGain must be >= 0, got ${dishonestGain}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (detectionProbability < 0 || detectionProbability > 1) {
    throw new SteleError(
      `detectionProbability must be in [0, 1], got ${detectionProbability}`,
    );
  }
  if (intrinsicHonestyCost < 0) {
    throw new SteleError(
      `intrinsicHonestyCost must be >= 0, got ${intrinsicHonestyCost}`,
    );
  }

  const netGain = dishonestGain - intrinsicHonestyCost;

  // If intrinsic cost already exceeds gain, no penalty needed
  if (netGain <= 0) {
    return {
      minimumPenalty: 0,
      enforceable: true,
      expectedPenalty: 0,
      formula:
        `Intrinsic honesty cost (${intrinsicHonestyCost}) >= dishonest gain (${dishonestGain}).\n` +
        `No penalty needed: honest behavior is already incentive-compatible.`,
    };
  }

  // If detection is impossible, no finite penalty works
  if (detectionProbability === 0) {
    return {
      minimumPenalty: Infinity,
      enforceable: false,
      expectedPenalty: 0,
      formula:
        `Detection probability is 0 but net dishonest gain is ${netGain} > 0.\n` +
        `No finite penalty can enforce honesty without detection.`,
    };
  }

  // penalty_min = netGain / detectionProbability
  const minimumPenalty = netGain / detectionProbability;
  const expectedPenalty = minimumPenalty * detectionProbability;

  const formula =
    `Incentive compatibility constraint: p * penalty + intrinsicCost >= dishonestGain\n` +
    `  ${detectionProbability} * penalty + ${intrinsicHonestyCost} >= ${dishonestGain}\n` +
    `  penalty >= (${dishonestGain} - ${intrinsicHonestyCost}) / ${detectionProbability}\n` +
    `  penalty >= ${minimumPenalty.toFixed(6)}\n` +
    `Expected penalty at minimum: ${detectionProbability} * ${minimumPenalty.toFixed(6)} = ${expectedPenalty.toFixed(6)}`;

  return {
    minimumPenalty,
    enforceable: true,
    expectedPenalty,
    formula,
  };
}

// ---------------------------------------------------------------------------
// Principal-Agent Model (Game Theory Applies to Operators, Not Agents)
// ---------------------------------------------------------------------------

/**
 * Represents the human/organization operating one or more AI agents.
 * Game theory targets the principal (operator), not the stochastic LLM.
 * If an agent breaches due to hallucination, the principal still bears cost.
 */
export interface OperatorPrincipal {
  operatorId: string;
  agentIds: string[];
  totalStake: number;
  monitoringBudget: number;
  liabilityExposure: number;
}

/**
 * Result of principal-agent modeling.
 */
export interface PrincipalAgentModel {
  operator: OperatorPrincipal;
  agentBreachProbability: number;
  monitoringEffectiveness: number;
  operatorExpectedCost: number;
  incentiveCompatible: boolean;
  optimalMonitoringSpend: number;
}

/**
 * Model the principal-agent relationship between an operator and their AI agents.
 *
 * LLMs are stochastic, not rational actors. Game theory should target the
 * principal (human/org operating the agent). If an agent breaches due to
 * hallucination, the principal still bears the cost.
 *
 * The model computes:
 * - agentBreachProbability = agentBreachRate * (1 - monitoringEffectiveness)
 * - operatorExpectedCost = agentBreachProbability * breachCost + monitoringBudget
 * - optimalMonitoringSpend = the spend where marginal monitoring cost equals
 *   marginal reduction in expected breach cost (using diminishing returns model:
 *   effectiveness(spend) = spend / (spend + monitoringCostPerUnit))
 * - incentiveCompatible = true when operatorExpectedCost < liabilityExposure
 */
export function modelPrincipalAgent(params: {
  operator: OperatorPrincipal;
  agentBreachRate: number;
  detectionRate: number;
  breachCost: number;
  monitoringCostPerUnit: number;
}): PrincipalAgentModel {
  const { operator, agentBreachRate, detectionRate, breachCost, monitoringCostPerUnit } = params;

  if (agentBreachRate < 0 || agentBreachRate > 1) {
    throw new SteleError(`agentBreachRate must be in [0, 1], got ${agentBreachRate}`);
  }
  if (detectionRate < 0 || detectionRate > 1) {
    throw new SteleError(`detectionRate must be in [0, 1], got ${detectionRate}`);
  }
  if (breachCost < 0) {
    throw new SteleError(`breachCost must be >= 0, got ${breachCost}`);
  }
  if (monitoringCostPerUnit < 0) {
    throw new SteleError(`monitoringCostPerUnit must be >= 0, got ${monitoringCostPerUnit}`);
  }

  const monitoringEffectiveness = detectionRate;

  // Effective breach probability: base rate reduced by monitoring
  const agentBreachProbability = agentBreachRate * (1 - monitoringEffectiveness);

  // Expected cost to operator: expected breach losses + monitoring budget
  const operatorExpectedCost = agentBreachProbability * breachCost + operator.monitoringBudget;

  // Optimal monitoring spend using diminishing returns model:
  //   effectiveness(spend) = spend / (spend + monitoringCostPerUnit)
  //   Total cost = agentBreachRate * (1 - effectiveness(spend)) * breachCost + spend
  //   d(totalCost)/d(spend) = 0 =>
  //   spend = sqrt(agentBreachRate * breachCost * monitoringCostPerUnit) - monitoringCostPerUnit
  const optimalMonitoringSpend = Math.max(
    0,
    Math.sqrt(agentBreachRate * breachCost * monitoringCostPerUnit) - monitoringCostPerUnit,
  );

  // Operator is incentivized to use the system when expected cost < liability exposure
  const incentiveCompatible = operatorExpectedCost < operator.liabilityExposure;

  return {
    operator,
    agentBreachProbability,
    monitoringEffectiveness,
    operatorExpectedCost,
    incentiveCompatible,
    optimalMonitoringSpend,
  };
}

// ---------------------------------------------------------------------------
// Adoption Tier Analysis (Three Tiers with Honest Detection)
// ---------------------------------------------------------------------------

/**
 * Three adoption tiers with different detection characteristics:
 * - solo: ~60-70% detection (single-party self-verification)
 * - bilateral: ~85-95% detection (cross-verification between two parties)
 * - network: >99% detection (multi-party network verification)
 */
export type AdoptionTier = 'solo' | 'bilateral' | 'network';

/**
 * Result of adoption tier analysis.
 */
export interface TierAnalysis {
  tier: AdoptionTier;
  detectionFloor: number;
  detectionCeiling: number;
  effectiveDetection: number;
  participantCount: number;
  gameTheoryApplicable: boolean;
  adjustedStake: number;
  honestEquilibrium: boolean;
}

/** Floor/ceiling parameters for each adoption tier */
const TIER_PARAMS: Record<AdoptionTier, { floor: number; ceiling: number }> = {
  solo: { floor: 0.60, ceiling: 0.70 },
  bilateral: { floor: 0.85, ceiling: 0.95 },
  network: { floor: 0.99, ceiling: 0.999 },
};

/**
 * Analyze a specific adoption tier to determine detection effectiveness,
 * adjusted stake, and whether an honest equilibrium exists.
 *
 * Rules:
 * - solo: floor=0.60, ceiling=0.70, adjustedStake = stake * 1.0
 * - bilateral: floor=0.85, ceiling=0.95, adjustedStake = stake * 1.5
 * - network: floor=0.99, ceiling=0.999, adjustedStake = stake * sqrt(participantCount)
 * - effectiveDetection = clamp(baseDetectionRate, floor, ceiling)
 * - honestEquilibrium = adjustedStake * effectiveDetection > breachGain
 *
 * Game theory is applicable for bilateral and network tiers (strategic
 * interaction between multiple participants), but not for solo tier
 * (single-party, no strategic interaction).
 */
export function analyzeTier(params: {
  tier: AdoptionTier;
  baseDetectionRate: number;
  participantCount: number;
  stake: number;
  breachGain: number;
}): TierAnalysis {
  const { tier, baseDetectionRate, participantCount, stake, breachGain } = params;

  if (baseDetectionRate < 0 || baseDetectionRate > 1) {
    throw new SteleError(`baseDetectionRate must be in [0, 1], got ${baseDetectionRate}`);
  }
  if (participantCount < 1) {
    throw new SteleError(`participantCount must be >= 1, got ${participantCount}`);
  }
  if (stake < 0) {
    throw new SteleError(`stake must be >= 0, got ${stake}`);
  }
  if (breachGain < 0) {
    throw new SteleError(`breachGain must be >= 0, got ${breachGain}`);
  }

  const { floor, ceiling } = TIER_PARAMS[tier];

  // Clamp detection rate to tier bounds
  const effectiveDetection = Math.max(floor, Math.min(ceiling, baseDetectionRate));

  // Compute adjusted stake based on tier
  let adjustedStake: number;
  switch (tier) {
    case 'solo':
      adjustedStake = stake * 1.0;
      break;
    case 'bilateral':
      adjustedStake = stake * 1.5;
      break;
    case 'network':
      adjustedStake = stake * Math.sqrt(participantCount);
      break;
  }

  // Game theory requires strategic interaction (multiple participants)
  const gameTheoryApplicable = tier !== 'solo';

  // Honest equilibrium: expected cost of breach exceeds gain
  const honestEquilibrium = adjustedStake * effectiveDetection > breachGain;

  return {
    tier,
    detectionFloor: floor,
    detectionCeiling: ceiling,
    effectiveDetection,
    participantCount,
    gameTheoryApplicable,
    adjustedStake,
    honestEquilibrium,
  };
}

// ---------------------------------------------------------------------------
// Impossibility Conjectures (Formal Bounds as Conjectures)
// ---------------------------------------------------------------------------

/**
 * Status of a formal conjecture:
 * - conjecture: Unproven formal statement
 * - informal_argument: Supported by informal reasoning but not rigorous proof
 * - formally_proven: Rigorously proven (rare in this domain)
 */
export type ConjectureStatus = 'conjecture' | 'informal_argument' | 'formally_proven';

/**
 * A formal conjecture about impossibility bounds in trust protocols.
 * Stated as conjectures with informal arguments, not proven theorems,
 * to be intellectually honest about what we know vs. what we believe.
 */
export interface Conjecture {
  id: string;
  name: string;
  statement: string;
  status: ConjectureStatus;
  confidence: number;
  informalArgument: string;
  implications: string[];
  counterexampleSpace: string;
}

/**
 * Define a new conjecture with the given parameters.
 * Defaults: confidence=0.5, status='conjecture', implications=[], counterexampleSpace=''.
 */
export function defineConjecture(params: {
  id: string;
  name: string;
  statement: string;
  informalArgument: string;
  confidence?: number;
  implications?: string[];
  counterexampleSpace?: string;
}): Conjecture {
  const confidence = params.confidence ?? 0.5;

  if (confidence < 0 || confidence > 1) {
    throw new SteleError(`confidence must be in [0, 1], got ${confidence}`);
  }
  if (!params.id) {
    throw new SteleError('id must be a non-empty string');
  }
  if (!params.name) {
    throw new SteleError('name must be a non-empty string');
  }
  if (!params.statement) {
    throw new SteleError('statement must be a non-empty string');
  }
  if (!params.informalArgument) {
    throw new SteleError('informalArgument must be a non-empty string');
  }

  return {
    id: params.id,
    name: params.name,
    statement: params.statement,
    status: 'conjecture',
    confidence,
    informalArgument: params.informalArgument,
    implications: params.implications ?? [],
    counterexampleSpace: params.counterexampleSpace ?? '',
  };
}

/**
 * Return the four standard conjectures of the Stele/Kova protocol:
 *
 * 1. Observation Bound — verification cost proportional to action space
 * 2. Trust-Privacy Tradeoff — trust and privacy cannot both be maximized
 * 3. Composition Limit — trust degrades at most linearly with chain length
 * 4. Collateralization Theorem — trust cannot exceed economic value at risk
 */
export function getStandardConjectures(): Conjecture[] {
  return [
    {
      id: 'observation_bound',
      name: 'Observation Bound',
      statement: 'Complete behavioral verification requires observation proportional to action space',
      status: 'conjecture',
      confidence: 0.85,
      informalArgument:
        'To verify that an agent has not taken any forbidden action, one must observe a ' +
        'fraction of the action space proportional to its size. Sampling-based approaches ' +
        'can reduce the constant factor but not the asymptotic relationship. This follows ' +
        'from information-theoretic lower bounds on hypothesis testing.',
      implications: [
        'Monitoring cost scales with agent capability',
        'Full verification of unbounded agents is infeasible',
        'Practical systems must accept probabilistic guarantees',
      ],
      counterexampleSpace:
        'A verification scheme that achieves complete coverage with sub-linear observation ' +
        'would disprove this conjecture. Potential avenues: structured action spaces with ' +
        'exploitable symmetries, or cryptographic commitments that compress verification.',
    },
    {
      id: 'trust_privacy_tradeoff',
      name: 'Trust-Privacy Tradeoff',
      statement: 'Trust verification and privacy preservation cannot both be maximized simultaneously',
      status: 'informal_argument',
      confidence: 0.90,
      informalArgument:
        'Verifying trustworthy behavior requires observing actions, but privacy requires ' +
        'concealing them. Zero-knowledge proofs can partially bridge this gap, but there ' +
        'exist classes of behavioral properties (e.g., intent, context-dependent decisions) ' +
        'that resist zero-knowledge verification. The tradeoff is fundamental to any system ' +
        'that must balance accountability with confidentiality.',
      implications: [
        'Privacy-preserving trust requires accepting lower trust guarantees',
        'High-trust systems necessarily leak some behavioral information',
        'Zero-knowledge techniques can shift but not eliminate the tradeoff curve',
      ],
      counterexampleSpace:
        'A system achieving both perfect privacy and perfect trust verification would ' +
        'disprove this. Most likely requires a breakthrough in zero-knowledge proofs for ' +
        'behavioral properties or a fundamentally new model of trust that does not require observation.',
    },
    {
      id: 'composition_limit',
      name: 'Composition Limit',
      statement: 'Composed trust guarantees degrade at most linearly with chain length',
      status: 'conjecture',
      confidence: 0.75,
      informalArgument:
        'When trust is composed across a chain of agents (A trusts B trusts C ...), each ' +
        'link introduces potential failure. Under reasonable independence assumptions, the ' +
        'trust guarantee at the end of a chain of length n is at most 1/n of the single-link ' +
        'guarantee. This is an upper bound; actual degradation may be worse (exponential) ' +
        'without careful protocol design.',
      implications: [
        'Long delegation chains require stronger per-link guarantees',
        'Trust transitivity is fundamentally lossy',
        'Protocol design should minimize chain depth',
      ],
      counterexampleSpace:
        'A composition scheme where trust degrades sub-linearly (e.g., logarithmically) ' +
        'would tighten this bound. Potential avenues: redundant verification paths, ' +
        'reputation aggregation across multiple chains.',
    },
    {
      id: 'collateralization_theorem',
      name: 'Collateralization Theorem',
      statement: 'Trust cannot exceed economic value risked to back it',
      status: 'informal_argument',
      confidence: 0.95,
      informalArgument:
        'A rational operator will breach any covenant where the gain from breaching exceeds ' +
        'the collateral at risk. Therefore, the maximum trust one can place in a covenanted ' +
        'agent is bounded by the economic value the operator has staked. This follows directly ' +
        'from the assumption of rational self-interest and is the foundation of stake-based ' +
        'trust systems.',
      implications: [
        'Stake must be proportional to the value of the interaction',
        'Under-collateralized covenants are not credible',
        'Trust in high-value interactions requires high-value collateral',
      ],
      counterexampleSpace:
        'A mechanism where rational operators maintain trust beyond their staked collateral. ' +
        'Reputation systems and repeated games can effectively increase the "virtual collateral" ' +
        'but this conjecture claims they cannot exceed the total economic value at risk ' +
        '(including future reputation value).',
    },
  ];
}

// ---------------------------------------------------------------------------
// Impossibility Bounds Analysis (Protocol Level)
// ---------------------------------------------------------------------------

/**
 * A concrete bound derived from analyzing parameters against a conjecture.
 */
export interface ImpossibilityBound {
  conjecture: Conjecture;
  lowerBound?: number;
  upperBound?: number;
  tightnessEstimate: number;
  knownAchievable: boolean;
}

/**
 * Analyze concrete parameter values against the four standard conjectures
 * to produce impossibility bounds for a specific protocol configuration.
 *
 * Returns bounds for each conjecture:
 * - observation_bound: lowerBound = actionSpaceSize / observationBudget
 * - trust_privacy_tradeoff: upperBound = 1 - privacyRequirement
 * - composition_limit: upperBound = 1 / chainLength
 * - collateralization_theorem: upperBound = collateral
 *
 * @param params.actionSpaceSize Size of the agent's action space
 * @param params.observationBudget Budget (in observation units) available for monitoring
 * @param params.privacyRequirement Privacy requirement level, in [0, 1]
 * @param params.chainLength Length of the trust delegation chain (>= 1)
 * @param params.collateral Economic value staked as collateral
 */
export function analyzeImpossibilityBounds(params: {
  actionSpaceSize: number;
  observationBudget: number;
  privacyRequirement: number;
  chainLength: number;
  collateral: number;
}): ImpossibilityBound[] {
  const { actionSpaceSize, observationBudget, privacyRequirement, chainLength, collateral } = params;

  if (actionSpaceSize < 0) {
    throw new SteleError(`actionSpaceSize must be >= 0, got ${actionSpaceSize}`);
  }
  if (observationBudget <= 0) {
    throw new SteleError(`observationBudget must be > 0, got ${observationBudget}`);
  }
  if (privacyRequirement < 0 || privacyRequirement > 1) {
    throw new SteleError(`privacyRequirement must be in [0, 1], got ${privacyRequirement}`);
  }
  if (chainLength < 1) {
    throw new SteleError(`chainLength must be >= 1, got ${chainLength}`);
  }
  if (collateral < 0) {
    throw new SteleError(`collateral must be >= 0, got ${collateral}`);
  }

  const conjectures = getStandardConjectures();

  const observationBound = conjectures.find(c => c.id === 'observation_bound')!;
  const trustPrivacy = conjectures.find(c => c.id === 'trust_privacy_tradeoff')!;
  const compositionLimit = conjectures.find(c => c.id === 'composition_limit')!;
  const collateralization = conjectures.find(c => c.id === 'collateralization_theorem')!;

  // Observation bound: ratio of action space to observation budget
  // Higher ratio means worse coverage; tightness increases with ratio
  const observationRatio = actionSpaceSize / observationBudget;
  const observationTightness = Math.min(1, observationBudget / actionSpaceSize);

  // Trust-privacy: max achievable trust given privacy constraint
  const maxTrust = 1 - privacyRequirement;
  const privacyTightness = privacyRequirement > 0 ? Math.min(1, maxTrust) : 0;

  // Composition: trust per hop in chain
  const compositionUpperBound = 1 / chainLength;
  const compositionTightness = Math.min(1, 1 / chainLength);

  // Collateralization: max trust backed by collateral
  const collateralTightness = collateral > 0 ? Math.min(1, 1 / collateral) : 0;

  return [
    {
      conjecture: observationBound,
      lowerBound: observationRatio,
      upperBound: undefined,
      tightnessEstimate: observationTightness,
      knownAchievable: observationRatio <= 1,
    },
    {
      conjecture: trustPrivacy,
      lowerBound: undefined,
      upperBound: maxTrust,
      tightnessEstimate: privacyTightness,
      knownAchievable: maxTrust > 0,
    },
    {
      conjecture: compositionLimit,
      lowerBound: undefined,
      upperBound: compositionUpperBound,
      tightnessEstimate: compositionTightness,
      knownAchievable: chainLength === 1,
    },
    {
      conjecture: collateralization,
      lowerBound: undefined,
      upperBound: collateral,
      tightnessEstimate: collateralTightness,
      knownAchievable: collateral > 0,
    },
  ];
}
