export type {
  HonestyParameters,
  HonestyProof,
} from './types';

import type { HonestyParameters, HonestyProof } from './types';

/**
 * Validate that all HonestyParameters are within acceptable ranges.
 * Throws descriptive errors on any violation.
 */
export function validateParameters(params: Partial<HonestyParameters>): void {
  if (params.stakeAmount !== undefined && params.stakeAmount < 0) {
    throw new Error(`stakeAmount must be >= 0, got ${params.stakeAmount}`);
  }
  if (params.detectionProbability !== undefined) {
    if (params.detectionProbability < 0 || params.detectionProbability > 1) {
      throw new Error(
        `detectionProbability must be in [0, 1], got ${params.detectionProbability}`,
      );
    }
  }
  if (params.reputationValue !== undefined && params.reputationValue < 0) {
    throw new Error(`reputationValue must be >= 0, got ${params.reputationValue}`);
  }
  if (params.maxViolationGain !== undefined && params.maxViolationGain < 0) {
    throw new Error(`maxViolationGain must be >= 0, got ${params.maxViolationGain}`);
  }
  if (params.coburn !== undefined && params.coburn < 0) {
    throw new Error(`coburn must be >= 0, got ${params.coburn}`);
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
    throw new Error(
      `temptationPayoff (${T}) must be > cooperatePayoff (${R}) for a valid dilemma`,
    );
  }
  if (R <= P) {
    throw new Error(
      `cooperatePayoff (${R}) must be > defectPayoff (${P}) for a valid dilemma`,
    );
  }
  if (P <= S) {
    throw new Error(
      `defectPayoff (${P}) must be > suckerPayoff (${S}) for a valid dilemma`,
    );
  }

  // Validate discount factor is in (0, 1)
  if (delta <= 0 || delta >= 1) {
    throw new Error(
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
    throw new Error(`agentCount must be >= 1, got ${agentCount}`);
  }
  if (allocation.length !== agentCount) {
    throw new Error(
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
    throw new Error('coalitionValues must include the grand coalition (all agents)');
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
    throw new Error(`dishonestGain must be >= 0, got ${dishonestGain}`);
  }
  if (detectionProbability < 0 || detectionProbability > 1) {
    throw new Error(
      `detectionProbability must be in [0, 1], got ${detectionProbability}`,
    );
  }
  if (intrinsicHonestyCost < 0) {
    throw new Error(
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
    throw new Error(`agentBreachRate must be in [0, 1], got ${agentBreachRate}`);
  }
  if (detectionRate < 0 || detectionRate > 1) {
    throw new Error(`detectionRate must be in [0, 1], got ${detectionRate}`);
  }
  if (breachCost < 0) {
    throw new Error(`breachCost must be >= 0, got ${breachCost}`);
  }
  if (monitoringCostPerUnit < 0) {
    throw new Error(`monitoringCostPerUnit must be >= 0, got ${monitoringCostPerUnit}`);
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
    throw new Error(`baseDetectionRate must be in [0, 1], got ${baseDetectionRate}`);
  }
  if (participantCount < 1) {
    throw new Error(`participantCount must be >= 1, got ${participantCount}`);
  }
  if (stake < 0) {
    throw new Error(`stake must be >= 0, got ${stake}`);
  }
  if (breachGain < 0) {
    throw new Error(`breachGain must be >= 0, got ${breachGain}`);
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
    throw new Error(`confidence must be in [0, 1], got ${confidence}`);
  }
  if (!params.id) {
    throw new Error('id must be a non-empty string');
  }
  if (!params.name) {
    throw new Error('name must be a non-empty string');
  }
  if (!params.statement) {
    throw new Error('statement must be a non-empty string');
  }
  if (!params.informalArgument) {
    throw new Error('informalArgument must be a non-empty string');
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
    throw new Error(`actionSpaceSize must be >= 0, got ${actionSpaceSize}`);
  }
  if (observationBudget <= 0) {
    throw new Error(`observationBudget must be > 0, got ${observationBudget}`);
  }
  if (privacyRequirement < 0 || privacyRequirement > 1) {
    throw new Error(`privacyRequirement must be in [0, 1], got ${privacyRequirement}`);
  }
  if (chainLength < 1) {
    throw new Error(`chainLength must be >= 1, got ${chainLength}`);
  }
  if (collateral < 0) {
    throw new Error(`collateral must be >= 0, got ${collateral}`);
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

// ---------------------------------------------------------------------------
// Evolutionary Stable Strategy (ESS) Analysis
// ---------------------------------------------------------------------------
//
// "Honest behavior isn't just a Nash equilibrium — it's an Evolutionary Stable
// Strategy. No alternative strategy can spread through the population. A small
// group of cheaters can't gain a foothold."

/**
 * Parameters for Evolutionary Stable Strategy analysis.
 */
export interface ESSParameters {
  /** Population size */
  populationSize: number;
  /** Fraction of mutant (dishonest) strategy, in (0, 1) */
  mutantFraction: number;
  /** Payoff matrix: payoffs[i][j] = payoff to strategy i when playing against strategy j */
  /** Index 0 = honest, Index 1 = dishonest */
  payoffMatrix: [[number, number], [number, number]];
}

/**
 * Result of ESS analysis for the honest strategy.
 */
export interface ESSResult {
  /** Whether honest strategy is an ESS */
  isESS: boolean;
  /** Whether honest strategy satisfies the strict Nash condition: E(honest,honest) > E(dishonest,honest) */
  strictNashCondition: boolean;
  /** Whether honest strategy satisfies the stability condition: if E(h,h)=E(d,h), then E(h,d) > E(d,d) */
  stabilityCondition: boolean;
  /** Invasion fitness of the mutant strategy (negative = mutant dies out) */
  invasionFitness: number;
  /** Critical mutant fraction where honest strategy loses ESS property */
  criticalMutantFraction: number;
  /** Expected generations until mutant extinction (if ESS) */
  expectedExtinctionGenerations: number;
  formula: string;
}

/**
 * Analyze whether the honest strategy (index 0) is an Evolutionary Stable
 * Strategy (ESS) against a mutant dishonest strategy (index 1).
 *
 * A strategy σ is an ESS if for any mutant strategy τ:
 *   1. Strict Nash condition: E(σ, σ) > E(τ, σ)
 *      OR
 *   2. If E(σ, σ) = E(τ, σ), then stability condition: E(σ, τ) > E(τ, τ)
 *
 * Additionally computes:
 * - Invasion fitness: In a mixed population with fraction ε of mutants,
 *   fitness_mutant = (1-ε)*E(d,h) + ε*E(d,d)
 *   fitness_honest = (1-ε)*E(h,h) + ε*E(h,d)
 *   invasionFitness = fitness_mutant - fitness_honest (negative means mutant dies)
 *
 * - Critical mutant fraction: the ε* at which fitness_mutant = fitness_honest.
 *   Setting invasionFitness = 0 and solving for ε:
 *     (1-ε)*E(d,h) + ε*E(d,d) = (1-ε)*E(h,h) + ε*E(h,d)
 *     ε* = (E(h,h) - E(d,h)) / ((E(h,h) - E(d,h)) - (E(h,d) - E(d,d)))
 *   Clamped to [0, 1]. If denominator is 0, returns 1 (never loses ESS).
 *
 * - Expected generations to extinction: Uses a Wright-Fisher-like approximation
 *   based on selection coefficient s and effective population size Ne.
 *   s = -invasionFitness / avg_fitness (selection against mutant)
 *   Expected extinction time ~ (1 / s) * ln(Ne * mutantFraction)
 *   This is an approximation; exact Wright-Fisher dynamics are stochastic.
 */
export function analyzeESS(params: ESSParameters): ESSResult {
  const { populationSize, mutantFraction, payoffMatrix } = params;

  if (populationSize < 2) {
    throw new Error(`populationSize must be >= 2, got ${populationSize}`);
  }
  if (mutantFraction <= 0 || mutantFraction >= 1) {
    throw new Error(`mutantFraction must be in (0, 1), got ${mutantFraction}`);
  }

  // Extract payoffs: payoffMatrix[strategy_row][opponent_col]
  const E_hh = payoffMatrix[0][0]; // E(honest, honest)
  const E_hd = payoffMatrix[0][1]; // E(honest, dishonest)
  const E_dh = payoffMatrix[1][0]; // E(dishonest, honest)
  const E_dd = payoffMatrix[1][1]; // E(dishonest, dishonest)

  // --- ESS Condition 1: Strict Nash condition ---
  // E(honest, honest) > E(dishonest, honest)
  const strictNashCondition = E_hh > E_dh;

  // --- ESS Condition 2: Stability condition (Bishop-Cannings) ---
  // If E(h,h) = E(d,h), then check E(h,d) > E(d,d)
  const isNashEquality = Math.abs(E_hh - E_dh) < 1e-12;
  const stabilityCondition = isNashEquality ? E_hd > E_dd : true;

  // ESS = strict Nash condition met, OR (Nash equality AND stability condition)
  const isESS = strictNashCondition || (isNashEquality && stabilityCondition);

  // --- Invasion fitness ---
  // In a population with fraction ε of mutants and (1-ε) of honest:
  const eps = mutantFraction;
  const fitnessHonest = (1 - eps) * E_hh + eps * E_hd;
  const fitnessMutant = (1 - eps) * E_dh + eps * E_dd;
  const invasionFitness = fitnessMutant - fitnessHonest;

  // --- Critical mutant fraction ---
  // Solve: (1-ε)*E(d,h) + ε*E(d,d) = (1-ε)*E(h,h) + ε*E(h,d)
  // => ε * [(E(d,d) - E(h,d)) - (E(d,h) - E(h,h))] = E(h,h) - E(d,h)
  // => ε* = (E(h,h) - E(d,h)) / [(E(h,h) - E(d,h)) - (E(h,d) - E(d,d))]
  const numerator = E_hh - E_dh;
  const denominator = (E_hh - E_dh) - (E_hd - E_dd);
  let criticalMutantFraction: number;
  if (Math.abs(denominator) < 1e-12) {
    // If denominator is 0, the fitness difference doesn't depend on ε
    // If numerator > 0, honest always dominates; critical fraction = 1 (never reached)
    // If numerator <= 0, honest never dominates; critical fraction = 0
    criticalMutantFraction = numerator > 0 ? 1 : 0;
  } else {
    criticalMutantFraction = Math.max(0, Math.min(1, numerator / denominator));
  }

  // --- Expected generations to extinction (Wright-Fisher approximation) ---
  // Selection coefficient against the mutant: s = -invasionFitness / avgFitness
  // Expected extinction time ~ (1/s) * ln(N * ε) for a deleterious allele
  let expectedExtinctionGenerations: number;
  const avgFitness = (1 - eps) * fitnessHonest + eps * fitnessMutant;
  if (invasionFitness < -1e-12 && avgFitness > 0) {
    // Mutant is deleterious: negative invasion fitness means honest is favored
    const selectionCoefficient = -invasionFitness / avgFitness;
    const mutantCount = populationSize * eps;
    // Wright-Fisher: expected time to extinction ~ (1/s) * ln(N_e * initial_freq)
    // For small mutant count, use ln(mutantCount) as approximate scale
    expectedExtinctionGenerations = Math.max(
      1,
      (1 / selectionCoefficient) * Math.log(Math.max(1, mutantCount)),
    );
  } else if (invasionFitness >= -1e-12 && invasionFitness <= 1e-12) {
    // Neutral: drift-based extinction, expected time ~ N_e for a neutral allele
    expectedExtinctionGenerations = populationSize;
  } else {
    // Mutant is advantageous: it won't go extinct (in expectation)
    expectedExtinctionGenerations = Infinity;
  }

  const formula =
    `ESS Analysis for Honest Strategy (index 0):\n` +
    `  Payoff matrix: E(h,h)=${E_hh}, E(h,d)=${E_hd}, E(d,h)=${E_dh}, E(d,d)=${E_dd}\n` +
    `  Strict Nash condition: E(h,h)=${E_hh} > E(d,h)=${E_dh} => ${strictNashCondition}\n` +
    `  Stability condition: E(h,d)=${E_hd} > E(d,d)=${E_dd} => ${E_hd > E_dd} (relevant only if Nash equality)\n` +
    `  Honest strategy is${isESS ? '' : ' NOT'} an ESS\n` +
    `  Invasion fitness at ε=${eps}: ${invasionFitness.toFixed(6)} (${invasionFitness < 0 ? 'mutant dies out' : 'mutant spreads'})\n` +
    `  Critical mutant fraction: ${criticalMutantFraction.toFixed(6)}\n` +
    `  Expected generations to mutant extinction: ${expectedExtinctionGenerations === Infinity ? '∞' : expectedExtinctionGenerations.toFixed(2)}`;

  return {
    isESS,
    strictNashCondition,
    stabilityCondition,
    invasionFitness,
    criticalMutantFraction,
    expectedExtinctionGenerations,
    formula,
  };
}

// ---------------------------------------------------------------------------
// Evolutionary Dynamics Simulation (Replicator Dynamics)
// ---------------------------------------------------------------------------

/**
 * Parameters for the evolutionary dynamics simulation.
 */
export interface EvolutionSimulationParams {
  /** Initial fraction of honest strategy in the population, in (0, 1) */
  initialHonestFraction: number;
  /** Payoff matrix: payoffs[i][j] = payoff to strategy i when playing against strategy j */
  /** Index 0 = honest, Index 1 = dishonest */
  payoffMatrix: [[number, number], [number, number]];
  /** Number of generations to simulate */
  generations: number;
}

/**
 * A single step in the evolutionary trajectory.
 */
export interface EvolutionStep {
  generation: number;
  honestFraction: number;
  dishonestFraction: number;
  honestFitness: number;
  dishonestFitness: number;
  averageFitness: number;
}

/**
 * Result of the evolutionary dynamics simulation.
 */
export interface EvolutionSimulationResult {
  /** Full trajectory of strategy fractions over time */
  trajectory: EvolutionStep[];
  /** Final fraction of honest strategy */
  finalHonestFraction: number;
  /** Whether dishonest strategy converged to 0 (fraction < 1e-6) */
  dishonestExtinct: boolean;
  /** Generation at which dishonest fraction first fell below 1e-6 (or -1 if never) */
  extinctionGeneration: number;
  /** Human-readable summary */
  formula: string;
}

/**
 * Simulate evolutionary population dynamics using the discrete-time replicator
 * equation to show that dishonest strategies go extinct when honest is an ESS.
 *
 * Replicator dynamics (discrete time):
 *   x_i(t+1) = x_i(t) * f_i(t) / avg_f(t)
 *
 * where:
 *   x_i(t) = fraction of strategy i at time t
 *   f_i(t) = fitness of strategy i = sum_j( x_j(t) * payoff[i][j] )
 *   avg_f(t) = sum_i( x_i(t) * f_i(t) )
 *
 * The simulation tracks the trajectory of strategy fractions and determines
 * whether the dishonest strategy goes extinct (fraction drops below 1e-6).
 */
export function simulateEvolution(params: EvolutionSimulationParams): EvolutionSimulationResult {
  const { initialHonestFraction, payoffMatrix, generations } = params;

  if (initialHonestFraction <= 0 || initialHonestFraction >= 1) {
    throw new Error(`initialHonestFraction must be in (0, 1), got ${initialHonestFraction}`);
  }
  if (generations < 1) {
    throw new Error(`generations must be >= 1, got ${generations}`);
  }

  const E_hh = payoffMatrix[0][0];
  const E_hd = payoffMatrix[0][1];
  const E_dh = payoffMatrix[1][0];
  const E_dd = payoffMatrix[1][1];

  // Ensure all payoffs are positive for replicator dynamics to be well-defined
  // (fitness must be positive). We shift all payoffs by a constant if needed.
  const minPayoff = Math.min(E_hh, E_hd, E_dh, E_dd);
  const shift = minPayoff < 1 ? 1 - minPayoff : 0;
  const P_hh = E_hh + shift;
  const P_hd = E_hd + shift;
  const P_dh = E_dh + shift;
  const P_dd = E_dd + shift;

  const trajectory: EvolutionStep[] = [];
  let xH = initialHonestFraction; // honest fraction
  let xD = 1 - xH;               // dishonest fraction
  const EXTINCTION_THRESHOLD = 1e-6;
  let extinctionGeneration = -1;

  for (let gen = 0; gen <= generations; gen++) {
    // Fitness of each strategy in the current population mix
    const fH = xH * P_hh + xD * P_hd;
    const fD = xH * P_dh + xD * P_dd;
    const avgF = xH * fH + xD * fD;

    // Record step with original (unshifted) fitness values for clarity
    trajectory.push({
      generation: gen,
      honestFraction: xH,
      dishonestFraction: xD,
      honestFitness: xH * E_hh + xD * E_hd,
      dishonestFitness: xH * E_dh + xD * E_dd,
      averageFitness: xH * (xH * E_hh + xD * E_hd) + xD * (xH * E_dh + xD * E_dd),
    });

    // Check for extinction
    if (extinctionGeneration === -1 && xD < EXTINCTION_THRESHOLD) {
      extinctionGeneration = gen;
    }

    // Replicator dynamics update (skip on last generation)
    if (gen < generations && avgF > 0) {
      xH = xH * fH / avgF;
      xD = xD * fD / avgF;

      // Normalize to handle floating-point drift
      const total = xH + xD;
      xH = xH / total;
      xD = xD / total;

      // Clamp near-zero values
      if (xH < EXTINCTION_THRESHOLD) { xH = 0; xD = 1; }
      if (xD < EXTINCTION_THRESHOLD) { xD = 0; xH = 1; }
    }
  }

  const finalHonestFraction = xH;
  const dishonestExtinct = xD < EXTINCTION_THRESHOLD;

  const formula =
    `Replicator Dynamics Simulation (${generations} generations):\n` +
    `  Initial: honest=${initialHonestFraction.toFixed(6)}, dishonest=${(1 - initialHonestFraction).toFixed(6)}\n` +
    `  Final: honest=${finalHonestFraction.toFixed(6)}, dishonest=${(1 - finalHonestFraction).toFixed(6)}\n` +
    `  Payoff matrix (shifted by ${shift} for positive fitness):\n` +
    `    E(h,h)=${E_hh}, E(h,d)=${E_hd}, E(d,h)=${E_dh}, E(d,d)=${E_dd}\n` +
    `  Dishonest strategy ${dishonestExtinct ? 'went extinct' : 'survived'}\n` +
    (extinctionGeneration >= 0
      ? `  Extinction at generation ${extinctionGeneration}`
      : `  No extinction observed within ${generations} generations`);

  return {
    trajectory,
    finalHonestFraction,
    dishonestExtinct,
    extinctionGeneration,
    formula,
  };
}

// ---------------------------------------------------------------------------
// Detection Rate Validation via Monte Carlo Simulation
// ---------------------------------------------------------------------------

/**
 * Parameters for Monte Carlo detection rate validation.
 */
export interface DetectionValidationParams {
  /** Number of agents to simulate */
  agentCount: number;
  /** Number of interactions per agent */
  interactionsPerAgent: number;
  /** Probability of a violation in each interaction, in [0, 1] */
  violationProbability: number;
  /** Number of simulation runs (higher = tighter confidence intervals) */
  simulationRuns: number;
  /**
   * Optional random seed for reproducibility.
   * Uses a simple linear congruential generator seeded from this value.
   */
  randomSeed?: number;
}

/**
 * Result of detection rate validation for a single tier.
 */
export interface DetectionValidation {
  tier: AdoptionTier;
  simulatedInteractions: number;
  totalViolations: number;
  detectedViolations: number;
  empiricalDetectionRate: number;
  confidenceInterval: [number, number]; // 95% CI
  withinClaimedRange: boolean;
  claimedRange: [number, number];
}

/**
 * Combined result across all tiers.
 */
export interface DetectionValidationResult {
  tiers: DetectionValidation[];
  overallViolations: number;
  overallDetected: number;
  formula: string;
}

/**
 * A simple seeded pseudo-random number generator (linear congruential).
 * Produces values in [0, 1). Not cryptographically secure, but sufficient
 * for Monte Carlo simulation with reproducible results.
 */
function createSeededRng(seed: number): () => number {
  // LCG parameters (Numerical Recipes)
  let state = seed >>> 0; // ensure unsigned 32-bit
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

/**
 * Validate the Kova vision's claimed detection rates via Monte Carlo simulation.
 *
 * Claimed detection rates by tier:
 *   - solo: 60-70% (single-party runtime self-verification)
 *   - bilateral: 85-95% (bilateral attestation cross-verification)
 *   - network: 99-99.9% (multi-party network verification)
 *
 * Detection model (layered):
 * Each violation passes through independent detection layers. The probability
 * of detection at each layer is calibrated to produce tier-level detection rates:
 *
 *   - Runtime layer: Catches hard constraint violations (e.g., policy breaches).
 *     Base detection probability depends on tier.
 *   - Attestation layer (bilateral & network): Cross-verification between parties.
 *     Each additional verifier provides an independent check.
 *   - Network layer (network only): Multi-party consensus verification.
 *     Detection probability = 1 - (1 - p_per_verifier)^n_verifiers
 *
 * The simulation:
 * 1. For each of `simulationRuns` runs:
 *    a. Simulate `agentCount * interactionsPerAgent` interactions
 *    b. Each interaction has `violationProbability` chance of being a violation
 *    c. Each violation passes through the detection layers for the given tier
 *    d. Record total violations and detected violations
 * 2. Aggregate across runs to compute empirical detection rate
 * 3. Compute 95% confidence interval using the Wilson score interval
 *    (better than normal approximation for rates near 0 or 1)
 * 4. Check if the confidence interval overlaps with the claimed range
 *
 * @returns Detection validation results for all three tiers
 */
export function validateDetectionRates(params: DetectionValidationParams): DetectionValidationResult {
  const { agentCount, interactionsPerAgent, violationProbability, simulationRuns, randomSeed } = params;

  if (agentCount < 1) {
    throw new Error(`agentCount must be >= 1, got ${agentCount}`);
  }
  if (interactionsPerAgent < 1) {
    throw new Error(`interactionsPerAgent must be >= 1, got ${interactionsPerAgent}`);
  }
  if (violationProbability < 0 || violationProbability > 1) {
    throw new Error(`violationProbability must be in [0, 1], got ${violationProbability}`);
  }
  if (simulationRuns < 1) {
    throw new Error(`simulationRuns must be >= 1, got ${simulationRuns}`);
  }

  const rng = createSeededRng(randomSeed ?? 42);

  // Claimed ranges for each tier
  const claimedRanges: Record<AdoptionTier, [number, number]> = {
    solo: [0.60, 0.70],
    bilateral: [0.85, 0.95],
    network: [0.99, 0.999],
  };

  // Detection layer parameters calibrated to match claimed rates:
  //   solo: runtime only at ~65% base
  //   bilateral: runtime ~50% + attestation ~70% => combined ~85%
  //     P(detect) = 1 - (1-0.50)*(1-0.70) = 1 - 0.15 = 0.85
  //   network: runtime ~50% + attestation ~60% + network(5 verifiers at ~50% each)
  //     P(network_layer) = 1 - (1-0.50)^5 = 1 - 0.03125 = 0.96875
  //     P(detect) = 1 - (1-0.50)*(1-0.60)*(1-0.96875) = 1 - 0.50*0.40*0.03125 = 1 - 0.00625 = 0.99375
  const tierDetectionConfig: Record<AdoptionTier, { runtimeProb: number; attestationProb: number; networkVerifiers: number; perVerifierProb: number }> = {
    solo: { runtimeProb: 0.65, attestationProb: 0, networkVerifiers: 0, perVerifierProb: 0 },
    bilateral: { runtimeProb: 0.50, attestationProb: 0.70, networkVerifiers: 0, perVerifierProb: 0 },
    network: { runtimeProb: 0.50, attestationProb: 0.60, networkVerifiers: 5, perVerifierProb: 0.50 },
  };

  const totalInteractions = agentCount * interactionsPerAgent;
  const tiers: DetectionValidation[] = [];
  let overallViolations = 0;
  let overallDetected = 0;

  for (const tier of ['solo', 'bilateral', 'network'] as AdoptionTier[]) {
    const config = tierDetectionConfig[tier];
    let totalViolationsForTier = 0;
    let detectedViolationsForTier = 0;

    for (let run = 0; run < simulationRuns; run++) {
      for (let i = 0; i < totalInteractions; i++) {
        // Determine if this interaction is a violation
        if (rng() < violationProbability) {
          totalViolationsForTier++;

          // Layer 1: Runtime detection
          let detected = rng() < config.runtimeProb;

          // Layer 2: Attestation detection (bilateral and network tiers)
          if (!detected && config.attestationProb > 0) {
            detected = rng() < config.attestationProb;
          }

          // Layer 3: Network verification (network tier only)
          if (!detected && config.networkVerifiers > 0) {
            // Each verifier independently checks; detection = at least one catches it
            let networkDetected = false;
            for (let v = 0; v < config.networkVerifiers; v++) {
              if (rng() < config.perVerifierProb) {
                networkDetected = true;
                break; // at least one verifier detected it
              }
            }
            detected = networkDetected;
          }

          if (detected) {
            detectedViolationsForTier++;
          }
        }
      }
    }

    // Compute empirical detection rate
    const empiricalRate = totalViolationsForTier > 0
      ? detectedViolationsForTier / totalViolationsForTier
      : 0;

    // Compute 95% confidence interval using Wilson score interval
    // This is more robust than normal approximation, especially near 0 or 1
    const n = totalViolationsForTier;
    let ci: [number, number];
    if (n === 0) {
      ci = [0, 1]; // No violations observed, cannot determine rate
    } else {
      const z = 1.96; // 95% confidence
      const pHat = empiricalRate;
      const denominator = 1 + z * z / n;
      const center = (pHat + z * z / (2 * n)) / denominator;
      const halfWidth = (z / denominator) * Math.sqrt(pHat * (1 - pHat) / n + z * z / (4 * n * n));
      ci = [
        Math.max(0, center - halfWidth),
        Math.min(1, center + halfWidth),
      ];
    }

    // Check if empirical rate's confidence interval overlaps with claimed range
    const claimed = claimedRanges[tier];
    const withinClaimedRange = ci[1] >= claimed[0] && ci[0] <= claimed[1];

    tiers.push({
      tier,
      simulatedInteractions: totalInteractions * simulationRuns,
      totalViolations: totalViolationsForTier,
      detectedViolations: detectedViolationsForTier,
      empiricalDetectionRate: empiricalRate,
      confidenceInterval: ci,
      withinClaimedRange,
      claimedRange: claimed,
    });

    overallViolations += totalViolationsForTier;
    overallDetected += detectedViolationsForTier;
  }

  const formula =
    `Monte Carlo Detection Rate Validation (${simulationRuns} runs, ${totalInteractions} interactions/run):\n` +
    `  Violation probability: ${violationProbability}\n` +
    tiers.map(t =>
      `  ${t.tier}: empirical=${(t.empiricalDetectionRate * 100).toFixed(2)}% ` +
      `CI=[${(t.confidenceInterval[0] * 100).toFixed(2)}%, ${(t.confidenceInterval[1] * 100).toFixed(2)}%] ` +
      `claimed=[${(t.claimedRange[0] * 100).toFixed(1)}%, ${(t.claimedRange[1] * 100).toFixed(1)}%] ` +
      `${t.withinClaimedRange ? 'PASS' : 'FAIL'}`
    ).join('\n') +
    `\n  Overall: ${overallDetected}/${overallViolations} violations detected`;

  return {
    tiers,
    overallViolations,
    overallDetected,
    formula,
  };
}
