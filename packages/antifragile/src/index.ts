import { generateId } from '@kervyx/crypto';
import { KervyxError, KervyxErrorCode } from '@kervyx/types';

export type {
  BreachAntibody,
  NetworkHealth,
  GovernanceProposal,
  BreachSummary,
  StressTestResult,
  AntifragilityIndexResult,
} from './types.js';

import type {
  BreachAntibody,
  NetworkHealth,
  GovernanceProposal,
  BreachSummary,
  StressTestResult,
  AntifragilityIndexResult,
} from './types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VALID_SEVERITIES = new Set<string>(['critical', 'high', 'medium', 'low']);

/**
 * Category keyword mappings ordered from most specific to most general.
 * The first matching category wins, so more specific categories appear first.
 */
const CATEGORY_KEYWORDS: Array<{ category: string; keywords: string[] }> = [
  { category: 'secrets', keywords: ['secret', 'key', 'token', 'password', 'encrypt', 'decrypt'] },
  { category: 'data-security', keywords: ['data', 'exfiltrate', 'leak', 'export', 'transfer'] },
  { category: 'file-system', keywords: ['file', 'disk', 'storage', 'directory', 'path'] },
  { category: 'access-control', keywords: ['access', 'permission', 'auth', 'login', 'credential', 'role'] },
  { category: 'rate-limiting', keywords: ['rate', 'throttle', 'quota', 'bandwidth'] },
  { category: 'network', keywords: ['network', 'connect', 'request', 'call', 'socket', 'http'] },
  { category: 'execution', keywords: ['exec', 'run', 'process', 'spawn', 'command', 'shell'] },
  { category: 'resource', keywords: ['memory', 'cpu', 'resource', 'consumption', 'usage'] },
];

// ---------------------------------------------------------------------------
// Input validation helpers
// ---------------------------------------------------------------------------

/**
 * Validate a BreachSummary, throwing on invalid inputs.
 */
function validateBreach(breach: BreachSummary): void {
  if (!breach.violatedConstraint || breach.violatedConstraint.trim().length === 0) {
    throw new KervyxError('BreachSummary.violatedConstraint must be a non-empty string', KervyxErrorCode.INVALID_INPUT);
  }
  if (!VALID_SEVERITIES.has(breach.severity)) {
    throw new KervyxError(
      `BreachSummary.severity must be one of: ${[...VALID_SEVERITIES].join(', ')}. Got: "${breach.severity}"`,
      KervyxErrorCode.INVALID_INPUT,
    );
  }
}

/**
 * Validate a BreachAntibody, throwing on invalid inputs.
 */
function validateAntibody(antibody: BreachAntibody): void {
  if (antibody.adoptionVotes < 0) {
    throw new KervyxError('BreachAntibody.adoptionVotes must be non-negative', KervyxErrorCode.INVALID_INPUT);
  }
}

// ---------------------------------------------------------------------------
// Category derivation
// ---------------------------------------------------------------------------

/**
 * Derive a category from a violated constraint string using keyword matching.
 * Scans the lowercased constraint for known domain keywords and returns the
 * first matching category. Falls back to the constraint body (without any
 * type prefix) when no keywords match.
 */
function deriveCategory(violatedConstraint: string): string {
  const lower = violatedConstraint.toLowerCase();
  for (const { category, keywords } of CATEGORY_KEYWORDS) {
    if (keywords.some(kw => lower.includes(kw))) {
      return category;
    }
  }
  // Fallback: strip prefix and return the remainder
  const withoutPrefix = violatedConstraint.replace(/^(deny|permit|require|limit):/, '');
  return withoutPrefix || violatedConstraint;
}

// ---------------------------------------------------------------------------
// Constraint generation
// ---------------------------------------------------------------------------

/**
 * Map breach severity to a constraint strength modifier.
 */
function severityStrength(severity: BreachSummary['severity']): string {
  switch (severity) {
    case 'critical': return 'strict';
    case 'high': return 'enforced';
    case 'medium': return 'standard';
    case 'low': return 'advisory';
  }
}

/**
 * Generate a CCL constraint that would prevent the class of breach described.
 *
 * Analyzes the violated constraint type and breach severity to produce an
 * appropriate countermeasure:
 *
 *  - deny bypassed   -> tighter deny with severity-based strength modifier
 *  - limit exceeded   -> propose a lower limit (reduced by severity factor)
 *  - require skipped  -> propose enforcement
 *  - permit abused    -> revoke to deny
 *  - unprefixed       -> wrap in deny with strength
 */
function generateConstraintForBreach(
  violatedConstraint: string,
  severity: BreachSummary['severity'],
): string {
  const strength = severityStrength(severity);

  if (violatedConstraint.startsWith('deny:')) {
    const pattern = violatedConstraint.slice('deny:'.length);
    return `deny ${strength} on '${pattern}'`;
  }

  if (violatedConstraint.startsWith('limit:')) {
    const pattern = violatedConstraint.slice('limit:'.length);
    const numMatch = pattern.match(/(\d+)/);
    if (numMatch) {
      const originalValue = parseInt(numMatch[1]!, 10);
      const reductionFactor =
        severity === 'critical' ? 0.25
        : severity === 'high' ? 0.5
        : severity === 'medium' ? 0.75
        : 0.9;
      const newValue = Math.floor(originalValue * reductionFactor);
      const reduced = pattern.replace(/\d+/, String(newValue));
      return `limit ${strength} ${reduced}`;
    }
    return `limit ${strength} ${pattern}`;
  }

  if (violatedConstraint.startsWith('require:')) {
    const pattern = violatedConstraint.slice('require:'.length);
    return `require ${strength} enforce '${pattern}'`;
  }

  if (violatedConstraint.startsWith('permit:')) {
    const pattern = violatedConstraint.slice('permit:'.length);
    return `deny ${strength} on '${pattern}'`;
  }

  // Unprefixed constraint
  return `deny ${strength} on '${violatedConstraint}'`;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Analyze a breach and generate a new antibody (constraint) to prevent this
 * class of breach from recurring.
 *
 * The category is derived from keyword analysis of the violated constraint
 * (or the explicit category field on the breach). The proposed constraint is
 * generated based on the violated constraint type and breach severity.
 *
 * Returns a BreachAntibody with status 'proposed', zero adoption votes,
 * and the given adoption threshold (default 3).
 */
export function generateAntibody(breach: BreachSummary, adoptionThreshold = 3): BreachAntibody {
  validateBreach(breach);

  if (adoptionThreshold < 0) {
    throw new KervyxError('adoptionThreshold must be non-negative', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
  }

  const category = breach.category ?? deriveCategory(breach.violatedConstraint);
  const proposedConstraint = generateConstraintForBreach(breach.violatedConstraint, breach.severity);

  return {
    id: generateId(),
    derivedFromBreach: breach.id,
    proposedConstraint,
    category,
    status: 'proposed',
    adoptionVotes: 0,
    adoptionThreshold,
  };
}

/**
 * Create a governance proposal from a breach antibody.
 *
 * Wraps the antibody in a GovernanceProposal structure with a unique ID,
 * timestamp, and human-readable description.
 */
export function proposeToGovernance(antibody: BreachAntibody): GovernanceProposal {
  return {
    id: generateId(),
    antibodyId: antibody.id,
    proposedAt: Date.now(),
    description: `Proposal to adopt antibody "${antibody.proposedConstraint}" ` +
      `(category: ${antibody.category}) derived from breach ${antibody.derivedFromBreach}`,
  };
}

/**
 * Compute network health metrics from antibodies and breaches.
 *
 * - resistanceScore = antibodiesAdopted / max(1, totalBreaches)
 * - vulnerableCategories = breach categories that have no adopted antibody
 */
export function networkHealth(
  antibodies: BreachAntibody[],
  breaches: BreachSummary[],
): NetworkHealth {
  const totalBreaches = breaches.length;
  const antibodiesGenerated = antibodies.length;
  const antibodiesAdopted = antibodies.filter(a => a.status === 'adopted').length;
  const resistanceScore = antibodiesAdopted / Math.max(1, totalBreaches);

  // Gather all breach categories
  const breachCategories = new Set<string>();
  for (const breach of breaches) {
    const category = breach.category ?? deriveCategory(breach.violatedConstraint);
    breachCategories.add(category);
  }

  // Gather categories that have adopted antibodies
  const adoptedCategories = new Set<string>();
  for (const antibody of antibodies) {
    if (antibody.status === 'adopted') {
      adoptedCategories.add(antibody.category);
    }
  }

  // Vulnerable = breach categories without an adopted antibody
  const vulnerableCategories = [...breachCategories].filter(
    cat => !adoptedCategories.has(cat),
  );

  return {
    totalBreaches,
    antibodiesGenerated,
    antibodiesAdopted,
    resistanceScore,
    vulnerableCategories,
  };
}

/**
 * Return a copy of the antibody with status set to 'adopted'.
 * Requires adoptionVotes >= adoptionThreshold. Throws if threshold not met.
 * Use forceAdopt() for governance override.
 */
export function adoptAntibody(antibody: BreachAntibody): BreachAntibody {
  validateAntibody(antibody);
  if (antibody.adoptionVotes < antibody.adoptionThreshold) {
    throw new KervyxError(
      `Cannot adopt antibody: ${antibody.adoptionVotes} votes < threshold ${antibody.adoptionThreshold}. ` +
      `Use forceAdopt() for governance override.`,
      KervyxErrorCode.INVALID_INPUT,
    );
  }
  return { ...antibody, status: 'adopted' };
}

/**
 * Force-adopt an antibody regardless of vote count (governance override).
 * Bypasses the adoption threshold check.
 */
export function forceAdopt(antibody: BreachAntibody): BreachAntibody {
  return { ...antibody, status: 'adopted' };
}

/**
 * Return a copy of the antibody with status set to 'rejected'.
 */
export function rejectAntibody(antibody: BreachAntibody): BreachAntibody {
  return { ...antibody, status: 'rejected' };
}

/**
 * Return a copy of the antibody with adoptionVotes incremented by 1.
 */
export function voteForAntibody(antibody: BreachAntibody): BreachAntibody {
  validateAntibody(antibody);
  return { ...antibody, adoptionVotes: antibody.adoptionVotes + 1 };
}

/**
 * Check if an antibody for a given breach already exists in the list.
 * Matches by derivedFromBreach ID or by matching category.
 */
export function antibodyExists(antibodies: BreachAntibody[], breach: BreachSummary): boolean {
  validateBreach(breach);
  const breachCategory = breach.category ?? deriveCategory(breach.violatedConstraint);
  return antibodies.some(
    ab => ab.derivedFromBreach === breach.id || ab.category === breachCategory,
  );
}

/**
 * Simulate increasing attack intensities and measure system response.
 *
 * Each round introduces a batch of breaches (increasing in severity as rounds
 * progress). After each round, antibodies are generated and automatically
 * force-adopted. The resistance score is measured at each round.
 *
 * An antifragile system should show improving resistance over time as
 * antibodies accumulate.
 *
 * @param baseBreaches - Initial set of breaches to simulate
 * @param rounds - Number of attack rounds to simulate (default: 5)
 * @param intensityMultiplier - How many breaches to add each round (default: 2)
 * @throws {Error} if rounds < 1 or intensityMultiplier < 1
 */
export function stressTest(
  baseBreaches: BreachSummary[],
  rounds = 5,
  intensityMultiplier = 2,
): StressTestResult {
  if (rounds < 1) {
    throw new KervyxError('rounds must be at least 1', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (intensityMultiplier < 1) {
    throw new KervyxError('intensityMultiplier must be at least 1', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
  }

  const severityProgression: Array<BreachSummary['severity']> = ['low', 'medium', 'high', 'critical'];
  const resistanceOverTime: number[] = [];
  const antibodiesAdoptedOverTime: number[] = [];
  const allBreaches: BreachSummary[] = [];
  const allAntibodies: BreachAntibody[] = [];

  for (let round = 0; round < rounds; round++) {
    // Generate breaches for this round with increasing severity
    const severityIdx = Math.min(round, severityProgression.length - 1);
    const severity = severityProgression[severityIdx]!;
    const breachCount = Math.max(1, Math.floor(intensityMultiplier * (round + 1)));

    for (let b = 0; b < breachCount; b++) {
      // Use base breaches cyclically, escalating severity
      const baseBreach = baseBreaches.length > 0
        ? baseBreaches[b % baseBreaches.length]!
        : { id: `stress-${round}-${b}`, violatedConstraint: `deny:stress-test-${b}`, severity, category: `stress-cat-${b % 3}` };

      const breach: BreachSummary = {
        id: `stress-${round}-${b}`,
        violatedConstraint: baseBreach.violatedConstraint,
        severity,
        category: baseBreach.category,
      };
      allBreaches.push(breach);

      // Generate and auto-adopt antibodies for novel breaches
      if (!antibodyExists(allAntibodies, breach)) {
        const antibody = generateAntibody(breach, 0);
        const adopted = forceAdopt(antibody);
        allAntibodies.push(adopted);
      }
    }

    // Measure health after this round
    const health = networkHealth(allAntibodies, allBreaches);
    resistanceOverTime.push(health.resistanceScore);
    antibodiesAdoptedOverTime.push(health.antibodiesAdopted);
  }

  const improved = resistanceOverTime.length >= 2 &&
    resistanceOverTime[resistanceOverTime.length - 1]! >= resistanceOverTime[0]!;

  return {
    rounds,
    resistanceOverTime,
    antibodiesAdoptedOverTime,
    improved,
    finalResistanceScore: resistanceOverTime[resistanceOverTime.length - 1] ?? 0,
  };
}

/**
 * Quantify how much stronger the system gets from attacks.
 *
 * Runs a stress test simulation and computes an antifragility index from the
 * trend of resistance scores across attack waves.
 *
 * - positive index -> system is antifragile (gets stronger from attacks)
 * - zero index -> system is robust (unchanged by attacks)
 * - negative index -> system is fragile (weakened by attacks)
 *
 * The index is computed as the average of consecutive resistance score
 * differences, normalized to [-1, 1].
 *
 * @param breaches - Breaches to use as attack patterns
 * @param waves - Number of attack waves to simulate (default: 5)
 * @throws {Error} if waves < 2
 */
export function antifragilityIndex(
  breaches: BreachSummary[],
  waves = 5,
): AntifragilityIndexResult {
  if (waves < 2) {
    throw new KervyxError('waves must be at least 2 to measure trend', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
  }

  const result = stressTest(breaches, waves, 2);
  const trend = result.resistanceOverTime;

  // Compute successive differences
  let totalImprovement = 0;
  for (let i = 1; i < trend.length; i++) {
    totalImprovement += trend[i]! - trend[i - 1]!;
  }

  const averageImprovement = totalImprovement / (trend.length - 1);

  // Normalize the index: clamp to [-1, 1]
  // If average improvement is positive, system is antifragile
  const rawIndex = averageImprovement * 10; // scale for meaningful range
  const index = Math.max(-1, Math.min(1, rawIndex));

  let classification: 'antifragile' | 'robust' | 'fragile';
  if (index > 0.01) {
    classification = 'antifragile';
  } else if (index < -0.01) {
    classification = 'fragile';
  } else {
    classification = 'robust';
  }

  return {
    index,
    classification,
    resistanceTrend: trend,
    averageImprovement,
  };
}

// ---------------------------------------------------------------------------
// Nonlinear Stress Response Model
// ---------------------------------------------------------------------------

/** Configuration for a stress response curve. */
export interface StressResponseConfig {
  /** Inflection point on the stress axis (0-1 range recommended). */
  inflectionPoint: number;
  /** Steepness / growth rate of the curve at the inflection point. */
  steepness: number;
  /** Maximum output saturation level (asymptote). */
  saturation: number;
}

/**
 * Nonlinear stress response model that replaces linear intensity scaling
 * with biologically-inspired response curves.
 *
 * Supports three curve types:
 * - **logistic**: S-shaped sigmoid (gradual onset, steep middle, saturation)
 * - **exponential**: Rapid initial growth that saturates
 * - **threshold**: Near-zero response below a critical threshold, then sharp rise
 */
export class StressResponseCurve {
  private readonly config: Readonly<StressResponseConfig>;

  constructor(config: StressResponseConfig) {
    if (!Number.isFinite(config.inflectionPoint)) {
      throw new KervyxError(
        'inflectionPoint must be a finite number',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!Number.isFinite(config.steepness) || config.steepness <= 0) {
      throw new KervyxError(
        'steepness must be a positive finite number',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!Number.isFinite(config.saturation) || config.saturation <= 0) {
      throw new KervyxError(
        'saturation must be a positive finite number',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.config = { ...config };
  }

  /**
   * Logistic (sigmoid) response: L / (1 + exp(-k*(x - x0)))
   * where L = saturation, k = steepness, x0 = inflection point.
   */
  logistic(stress: number): number {
    if (!Number.isFinite(stress)) {
      throw new KervyxError('stress must be a finite number', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    const { saturation: L, steepness: k, inflectionPoint: x0 } = this.config;
    return L / (1 + Math.exp(-k * (stress - x0)));
  }

  /**
   * Exponential response with saturation: L * (1 - exp(-k * x))
   * Rapid initial response that asymptotically approaches saturation.
   */
  exponential(stress: number): number {
    if (!Number.isFinite(stress)) {
      throw new KervyxError('stress must be a finite number', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    const { saturation: L, steepness: k } = this.config;
    if (stress <= 0) return 0;
    return L * (1 - Math.exp(-k * stress));
  }

  /**
   * Threshold response: near-zero below inflection point, then rises sharply.
   * Uses a smoothed step function: L * sigmoid(k * (x - x0)) where k is large.
   */
  threshold(stress: number): number {
    if (!Number.isFinite(stress)) {
      throw new KervyxError('stress must be a finite number', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    const { saturation: L, steepness: k, inflectionPoint: x0 } = this.config;
    // Use a steep sigmoid to approximate a step function
    const effectiveK = k * 10; // amplify steepness for sharper threshold
    return L / (1 + Math.exp(-effectiveK * (stress - x0)));
  }

  /**
   * Compute the derivative (sensitivity) of the logistic response at a given stress.
   * Useful for identifying the stress region where the system is most responsive.
   */
  logisticDerivative(stress: number): number {
    if (!Number.isFinite(stress)) {
      throw new KervyxError('stress must be a finite number', KervyxErrorCode.PROTOCOL_INVALID_INPUT);
    }
    const response = this.logistic(stress);
    const { saturation: L, steepness: k } = this.config;
    return k * response * (1 - response / L);
  }

  /** Return a copy of the underlying config. */
  getConfig(): StressResponseConfig {
    return { ...this.config };
  }
}

// ---------------------------------------------------------------------------
// Phase Transition Detection
// ---------------------------------------------------------------------------

/** A single timestamped metric observation. */
export interface MetricObservation {
  timestamp: number;
  value: number;
}

/** Result of a phase transition analysis. */
export interface PhaseTransitionResult {
  /** Whether a phase transition was detected. */
  detected: boolean;
  /** Index in the time series where the transition is strongest. */
  transitionIndex: number;
  /** The critical threshold value at which the transition occurs. */
  criticalThreshold: number;
  /** Variance of the metric over time (high near transitions). */
  varianceTimeSeries: number[];
  /** Autocorrelation at lag-1 over time (approaches 1 near transitions). */
  autocorrelationTimeSeries: number[];
  /** Spectral power (variance ratio) indicating transition strength. */
  spectralPower: number;
}

/**
 * Detects phase transitions in system behavior using statistical indicators.
 *
 * Phase transitions (tipping points) are preceded by:
 * 1. **Critical slowing down**: increasing autocorrelation at lag-1
 * 2. **Flickering**: increasing variance as the system oscillates
 *
 * This detector tracks these early-warning signals using rolling-window
 * variance and autocorrelation analysis.
 */
export class PhaseTransitionDetector {
  private observations: MetricObservation[] = [];
  private readonly windowSize: number;

  /**
   * @param windowSize Minimum number of observations per analysis window.
   *                   Must be >= 3 for meaningful statistics.
   */
  constructor(windowSize = 10) {
    if (!Number.isInteger(windowSize) || windowSize < 3) {
      throw new KervyxError(
        'windowSize must be an integer >= 3',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.windowSize = windowSize;
  }

  /** Record a new metric observation. */
  addObservation(obs: MetricObservation): void {
    if (!Number.isFinite(obs.value)) {
      throw new KervyxError(
        'observation value must be a finite number',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!Number.isFinite(obs.timestamp)) {
      throw new KervyxError(
        'observation timestamp must be a finite number',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.observations.push({ ...obs });
  }

  /** Add multiple observations at once. */
  addObservations(observations: MetricObservation[]): void {
    for (const obs of observations) {
      this.addObservation(obs);
    }
  }

  /** Return a copy of all recorded observations sorted by timestamp. */
  getObservations(): MetricObservation[] {
    return [...this.observations].sort((a, b) => a.timestamp - b.timestamp);
  }

  /** Reset all observations. */
  reset(): void {
    this.observations = [];
  }

  /**
   * Analyze the recorded observations for phase transitions.
   *
   * Uses rolling-window variance and autocorrelation to detect
   * critical slowing down, a hallmark of approaching phase transitions.
   *
   * @param sensitivityThreshold Variance increase ratio to flag a transition (default: 2.0).
   * @throws {KervyxError} if fewer than windowSize * 2 observations are available.
   */
  analyze(sensitivityThreshold = 2.0): PhaseTransitionResult {
    if (!Number.isFinite(sensitivityThreshold) || sensitivityThreshold <= 0) {
      throw new KervyxError(
        'sensitivityThreshold must be a positive finite number',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    const sorted = this.getObservations();
    const minRequired = this.windowSize * 2;
    if (sorted.length < minRequired) {
      throw new KervyxError(
        `Need at least ${minRequired} observations (windowSize * 2), got ${sorted.length}`,
        KervyxErrorCode.PROTOCOL_COMPUTATION_FAILED,
      );
    }

    const values = sorted.map(o => o.value);
    const varianceTimeSeries: number[] = [];
    const autocorrelationTimeSeries: number[] = [];

    // Compute rolling variance and lag-1 autocorrelation
    for (let i = 0; i <= values.length - this.windowSize; i++) {
      const window = values.slice(i, i + this.windowSize);
      varianceTimeSeries.push(PhaseTransitionDetector.variance(window));
      autocorrelationTimeSeries.push(PhaseTransitionDetector.autocorrelationLag1(window));
    }

    // Find the point of maximum variance (potential phase transition)
    let maxVariance = -Infinity;
    let transitionIndex = 0;
    for (let i = 0; i < varianceTimeSeries.length; i++) {
      if (varianceTimeSeries[i]! > maxVariance) {
        maxVariance = varianceTimeSeries[i]!;
        transitionIndex = i;
      }
    }

    // Compute baseline variance from the first quarter
    const baselineEnd = Math.max(1, Math.floor(varianceTimeSeries.length / 4));
    const baselineVariance = varianceTimeSeries
      .slice(0, baselineEnd)
      .reduce((s, v) => s + v, 0) / baselineEnd;

    // Spectral power = ratio of max variance to baseline variance
    const spectralPower = baselineVariance > 0 ? maxVariance / baselineVariance : 0;

    // Transition detected if spectral power exceeds sensitivity threshold
    const detected = spectralPower >= sensitivityThreshold;

    // Critical threshold = mean of the values in the transition window
    const transWindowStart = transitionIndex;
    const transWindowEnd = Math.min(transWindowStart + this.windowSize, values.length);
    const transWindow = values.slice(transWindowStart, transWindowEnd);
    const criticalThreshold = transWindow.reduce((s, v) => s + v, 0) / transWindow.length;

    return {
      detected,
      transitionIndex,
      criticalThreshold,
      varianceTimeSeries,
      autocorrelationTimeSeries,
      spectralPower,
    };
  }

  /** Compute the variance of a numeric array. */
  private static variance(values: number[]): number {
    if (values.length === 0) return 0;
    const mean = values.reduce((s, v) => s + v, 0) / values.length;
    return values.reduce((s, v) => s + (v - mean) ** 2, 0) / values.length;
  }

  /** Compute lag-1 autocorrelation of a numeric array. */
  private static autocorrelationLag1(values: number[]): number {
    if (values.length < 2) return 0;
    const mean = values.reduce((s, v) => s + v, 0) / values.length;
    let numerator = 0;
    let denominator = 0;
    for (let i = 0; i < values.length; i++) {
      denominator += (values[i]! - mean) ** 2;
      if (i < values.length - 1) {
        numerator += (values[i]! - mean) * (values[i + 1]! - mean);
      }
    }
    return denominator === 0 ? 0 : numerator / denominator;
  }
}

// ---------------------------------------------------------------------------
// Antibody Fitness Evolution
// ---------------------------------------------------------------------------

/** A scored antibody with fitness metadata for the evolution engine. */
export interface ScoredAntibody {
  antibody: BreachAntibody;
  /** Fitness score based on effectiveness against recent breaches. */
  fitness: number;
  /** Number of breaches this antibody has successfully addressed. */
  successCount: number;
  /** Number of breaches this antibody failed to prevent. */
  failureCount: number;
  /** Generation in which this antibody was created/mutated. */
  generation: number;
}

/** Configuration for the fitness evolution engine. */
export interface FitnessEvolutionConfig {
  /** Maximum population size before pruning (default: 50). */
  maxPopulation: number;
  /** Minimum fitness threshold; antibodies below this are candidates for pruning (default: 0.2). */
  pruneThreshold: number;
  /** Mutation rate: probability that a gene changes during mutation (default: 0.1). */
  mutationRate: number;
  /** Tournament size for selection (default: 3). */
  tournamentSize: number;
}

const DEFAULT_FITNESS_CONFIG: FitnessEvolutionConfig = {
  maxPopulation: 50,
  pruneThreshold: 0.2,
  mutationRate: 0.1,
  tournamentSize: 3,
};

/**
 * Evolutionary engine that tracks antibody effectiveness over time and
 * evolves the antibody population through selection, mutation, and crossover.
 *
 * Antibodies are scored by their success rate against incoming breaches.
 * Tournament selection promotes the fittest antibodies, while mutation and
 * crossover generate new variants. Ineffective antibodies are pruned.
 */
export class FitnessEvolution {
  private population: ScoredAntibody[] = [];
  private generation = 0;
  private readonly config: FitnessEvolutionConfig;

  constructor(config: Partial<FitnessEvolutionConfig> = {}) {
    this.config = { ...DEFAULT_FITNESS_CONFIG, ...config };
    if (this.config.maxPopulation < 2) {
      throw new KervyxError(
        'maxPopulation must be at least 2',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (this.config.pruneThreshold < 0 || this.config.pruneThreshold > 1) {
      throw new KervyxError(
        'pruneThreshold must be between 0 and 1',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (this.config.mutationRate < 0 || this.config.mutationRate > 1) {
      throw new KervyxError(
        'mutationRate must be between 0 and 1',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (this.config.tournamentSize < 2) {
      throw new KervyxError(
        'tournamentSize must be at least 2',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
  }

  /** Seed the population with initial antibodies, all starting at fitness 0.5. */
  seed(antibodies: BreachAntibody[]): void {
    if (antibodies.length === 0) {
      throw new KervyxError(
        'Must seed with at least one antibody',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    for (const ab of antibodies) {
      this.population.push({
        antibody: { ...ab },
        fitness: 0.5,
        successCount: 0,
        failureCount: 0,
        generation: this.generation,
      });
    }
  }

  /** Return a copy of the current population sorted by fitness (descending). */
  getPopulation(): ScoredAntibody[] {
    return [...this.population]
      .sort((a, b) => b.fitness - a.fitness)
      .map(s => ({ ...s, antibody: { ...s.antibody } }));
  }

  /** Return the current generation number. */
  getGeneration(): number {
    return this.generation;
  }

  /**
   * Record a breach outcome for the population.
   * If an antibody's category matches the breach's category, it receives
   * a success or failure mark depending on whether the system resisted.
   *
   * @param breach The breach that occurred.
   * @param wasResisted Whether the system successfully resisted the breach.
   */
  recordOutcome(breach: BreachSummary, wasResisted: boolean): void {
    validateBreach(breach);
    const breachCat = breach.category ?? deriveCategory(breach.violatedConstraint);
    for (const scored of this.population) {
      if (scored.antibody.category === breachCat) {
        if (wasResisted) {
          scored.successCount++;
        } else {
          scored.failureCount++;
        }
        // Update fitness as a weighted success rate with Bayesian prior
        const total = scored.successCount + scored.failureCount;
        // Bayesian: (successes + 1) / (total + 2) to avoid 0/0
        scored.fitness = (scored.successCount + 1) / (total + 2);
      }
    }
  }

  /**
   * Run one evolutionary generation:
   * 1. Prune antibodies below the fitness threshold
   * 2. Select parents via tournament selection
   * 3. Generate offspring via crossover and mutation
   * 4. Cap population at maxPopulation
   */
  evolve(): void {
    if (this.population.length === 0) {
      throw new KervyxError(
        'Cannot evolve an empty population; call seed() first',
        KervyxErrorCode.PROTOCOL_COMPUTATION_FAILED,
      );
    }

    this.generation++;

    // Step 1: Prune weak antibodies (keep at least 2)
    const survivors = this.population.filter(s => s.fitness >= this.config.pruneThreshold);
    if (survivors.length >= 2) {
      this.population = survivors;
    } else {
      // Keep the top 2 by fitness
      this.population.sort((a, b) => b.fitness - a.fitness);
      this.population = this.population.slice(0, Math.max(2, Math.min(this.population.length, 2)));
    }

    // Step 2: Generate offspring to fill up to maxPopulation
    const offspring: ScoredAntibody[] = [];
    while (this.population.length + offspring.length < this.config.maxPopulation) {
      const parent1 = this.tournamentSelect();
      const parent2 = this.tournamentSelect();
      const child = this.crossover(parent1, parent2);
      const mutated = this.mutate(child);
      offspring.push(mutated);
    }

    this.population.push(...offspring);
  }

  /**
   * Tournament selection: pick `tournamentSize` random members and return
   * the fittest.
   */
  private tournamentSelect(): ScoredAntibody {
    const size = Math.min(this.config.tournamentSize, this.population.length);
    let best: ScoredAntibody | null = null;
    const used = new Set<number>();
    for (let i = 0; i < size; i++) {
      let idx: number;
      do {
        idx = Math.floor(Math.random() * this.population.length);
      } while (used.has(idx) && used.size < this.population.length);
      used.add(idx);
      const candidate = this.population[idx]!;
      if (!best || candidate.fitness > best.fitness) {
        best = candidate;
      }
    }
    return best!;
  }

  /**
   * Crossover: combine constraints from two parents to produce an offspring.
   * Takes the category from the fitter parent and merges constraint strings.
   */
  private crossover(a: ScoredAntibody, b: ScoredAntibody): ScoredAntibody {
    const fitter = a.fitness >= b.fitness ? a : b;
    const other = a.fitness >= b.fitness ? b : a;

    // Combine constraints: take base from fitter, append modifier from other
    const baseConstraint = fitter.antibody.proposedConstraint;
    const otherCategory = other.antibody.category;
    const combinedConstraint = `${baseConstraint} [evolved:${otherCategory}]`;

    return {
      antibody: {
        id: generateId(),
        derivedFromBreach: fitter.antibody.derivedFromBreach,
        proposedConstraint: combinedConstraint,
        category: fitter.antibody.category,
        status: 'proposed',
        adoptionVotes: 0,
        adoptionThreshold: fitter.antibody.adoptionThreshold,
      },
      fitness: (a.fitness + b.fitness) / 2,
      successCount: 0,
      failureCount: 0,
      generation: this.generation,
    };
  }

  /**
   * Mutation: with probability mutationRate, alter the category suffix or
   * constraint modifier to explore new defensive strategies.
   */
  private mutate(scored: ScoredAntibody): ScoredAntibody {
    if (Math.random() >= this.config.mutationRate) {
      return scored; // no mutation
    }

    // Mutate by appending a random mutation marker and slightly varying fitness
    const mutationTag = `mut-g${this.generation}-${Math.floor(Math.random() * 1000)}`;
    const mutatedConstraint = scored.antibody.proposedConstraint.includes('[evolved:')
      ? scored.antibody.proposedConstraint.replace(/\[evolved:[^\]]*\]/, `[${mutationTag}]`)
      : `${scored.antibody.proposedConstraint} [${mutationTag}]`;

    return {
      ...scored,
      antibody: {
        ...scored.antibody,
        id: generateId(),
        proposedConstraint: mutatedConstraint,
      },
      // Small random perturbation to fitness
      fitness: Math.max(0, Math.min(1, scored.fitness + (Math.random() - 0.5) * 0.1)),
    };
  }
}

// ---------------------------------------------------------------------------
// Calibrated Antifragility Index
// ---------------------------------------------------------------------------

/** Result of the calibrated antifragility index computation. */
export interface CalibratedAntifragilityResult {
  /** The calibrated antifragility index (z-score based, unbounded). */
  index: number;
  /** Classification based on statistical significance. */
  classification: 'antifragile' | 'robust' | 'fragile';
  /** Lower bound of the 95% confidence interval for the index. */
  confidenceLower: number;
  /** Upper bound of the 95% confidence interval for the index. */
  confidenceUpper: number;
  /** Confidence level used (e.g., 0.95). */
  confidenceLevel: number;
  /** Mean of the resistance improvement deltas. */
  meanDelta: number;
  /** Standard deviation of the resistance improvement deltas. */
  stdDelta: number;
  /** Raw resistance scores from the stress test. */
  resistanceTrend: number[];
  /** P-value (two-tailed) for the hypothesis that the index differs from 0. */
  pValue: number;
}

/**
 * Compute a statistically calibrated antifragility index using z-scores
 * relative to baseline performance, with confidence intervals.
 *
 * Instead of the arbitrary 10x multiplier, this uses the standard error
 * of the mean improvement to compute a z-score. The result is statistically
 * interpretable: a z-score > 1.96 indicates significant antifragility at
 * the 95% confidence level.
 *
 * @param breaches Breaches to use as attack patterns.
 * @param waves Number of attack waves (default: 10). More waves = tighter CI.
 * @param confidenceLevel Confidence level for the interval (default: 0.95).
 * @throws {KervyxError} if waves < 3 or confidenceLevel is invalid.
 */
export function calibratedAntifragilityIndex(
  breaches: BreachSummary[],
  waves = 10,
  confidenceLevel = 0.95,
): CalibratedAntifragilityResult {
  if (waves < 3) {
    throw new KervyxError(
      'waves must be at least 3 for statistical calibration',
      KervyxErrorCode.PROTOCOL_INVALID_INPUT,
    );
  }
  if (confidenceLevel <= 0 || confidenceLevel >= 1) {
    throw new KervyxError(
      'confidenceLevel must be between 0 and 1 (exclusive)',
      KervyxErrorCode.PROTOCOL_INVALID_INPUT,
    );
  }

  const result = stressTest(breaches, waves, 2);
  const trend = result.resistanceOverTime;

  // Compute successive differences (deltas)
  const deltas: number[] = [];
  for (let i = 1; i < trend.length; i++) {
    deltas.push(trend[i]! - trend[i - 1]!);
  }

  if (deltas.length === 0) {
    throw new KervyxError(
      'Insufficient data to compute deltas',
      KervyxErrorCode.PROTOCOL_COMPUTATION_FAILED,
    );
  }

  // Mean and standard deviation of deltas
  const meanDelta = deltas.reduce((s, d) => s + d, 0) / deltas.length;
  const variance = deltas.reduce((s, d) => s + (d - meanDelta) ** 2, 0) / deltas.length;
  const stdDelta = Math.sqrt(variance);

  // Standard error of the mean
  const sem = stdDelta / Math.sqrt(deltas.length);

  // Z-score: how many standard errors the mean is from zero
  const zScore = sem > 0 ? meanDelta / sem : (meanDelta > 0 ? Infinity : meanDelta < 0 ? -Infinity : 0);

  // Approximate z-critical for the given confidence level
  // Using the rational approximation to the inverse normal CDF
  const alpha = 1 - confidenceLevel;
  const zCritical = approximateZCritical(1 - alpha / 2);

  // Confidence interval for the mean delta
  const ciHalfWidth = zCritical * sem;
  const confidenceLower = meanDelta - ciHalfWidth;
  const confidenceUpper = meanDelta + ciHalfWidth;

  // Two-tailed p-value approximation using the normal CDF
  const absZ = Math.abs(zScore);
  const pValue = 2 * (1 - approximateNormalCDF(absZ));

  // Classification: significant at the given confidence level
  let classification: 'antifragile' | 'robust' | 'fragile';
  if (zScore > zCritical) {
    classification = 'antifragile';
  } else if (zScore < -zCritical) {
    classification = 'fragile';
  } else {
    classification = 'robust';
  }

  return {
    index: zScore,
    classification,
    confidenceLower,
    confidenceUpper,
    confidenceLevel,
    meanDelta,
    stdDelta,
    resistanceTrend: trend,
    pValue,
  };
}

/**
 * Approximate the inverse normal CDF (z-critical value) for a given probability p.
 * Uses the rational approximation from Abramowitz & Stegun (26.2.23).
 * Accurate to ~4.5 x 10^-4.
 */
function approximateZCritical(p: number): number {
  if (p <= 0 || p >= 1) return p <= 0 ? -Infinity : Infinity;
  if (p < 0.5) return -approximateZCritical(1 - p);

  // Rational approximation for 0.5 < p < 1
  const t = Math.sqrt(-2 * Math.log(1 - p));
  const c0 = 2.515517;
  const c1 = 0.802853;
  const c2 = 0.010328;
  const d1 = 1.432788;
  const d2 = 0.189269;
  const d3 = 0.001308;
  return t - (c0 + c1 * t + c2 * t * t) / (1 + d1 * t + d2 * t * t + d3 * t * t * t);
}

/**
 * Approximate the normal CDF using the Horner form of the rational approximation.
 * Accurate to ~1.5 x 10^-7 for positive x.
 */
function approximateNormalCDF(x: number): number {
  if (x < 0) return 1 - approximateNormalCDF(-x);
  const a1 = 0.254829592;
  const a2 = -0.284496736;
  const a3 = 1.421413741;
  const a4 = -1.453152027;
  const a5 = 1.061405429;
  const p = 0.3275911;
  const t = 1 / (1 + p * x);
  const poly = ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t;
  return 1 - poly * Math.exp(-x * x / 2);
}
