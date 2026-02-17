import { sha256Object } from '@stele/crypto';
import { parse, matchAction, matchResource } from '@stele/ccl';
import type { Statement } from '@stele/ccl';
import { SteleError, SteleErrorCode } from '@stele/types';

export type {
  AlignmentProperty,
  AlignmentCovenant,
  AlignmentReport,
  ExecutionRecord,
  AlignmentDriftResult,
  AlignmentDecompositionResult,
  PropertyContribution,
} from './types';

import type {
  AlignmentProperty,
  AlignmentCovenant,
  AlignmentReport,
  ExecutionRecord,
  AlignmentDriftResult,
  AlignmentDecompositionResult,
  PropertyContribution,
} from './types';

/**
 * Severity weights for breach scoring.
 * Critical breaches count 4x, high 3x, medium 2x, low 1x.
 */
const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Standard HHH (Helpful, Honest, Harmless) alignment properties.
 * All constraints use valid CCL syntax (risk_level instead of reserved 'severity' keyword).
 */
export const STANDARD_ALIGNMENT_PROPERTIES: AlignmentProperty[] = [
  {
    name: 'harmlessness',
    constraints: ["deny * on '**' when risk_level = 'critical'"],
    testSuite: 'harmlessness-tests',
    coverageScore: 0,
  },
  {
    name: 'honesty',
    constraints: ["require audit_log on '**'"],
    testSuite: 'honesty-tests',
    coverageScore: 0,
  },
  {
    name: 'helpfulness',
    constraints: ["permit read on '**'"],
    testSuite: 'helpfulness-tests',
    coverageScore: 0,
  },
];

/**
 * Creates an AlignmentCovenant for an agent.
 * Validates that agentId is non-empty.
 * id = sha256 of content. constraints = union of all properties' constraints.
 */
export function defineAlignment(
  agentId: string,
  properties: AlignmentProperty[],
  verificationMethod: 'behavioral' | 'compositional' | 'adversarial' = 'behavioral',
): AlignmentCovenant {
  if (!agentId || agentId.trim() === '') {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'agentId must be a non-empty string', { hint: 'Provide a non-empty agentId string when calling defineAlignment.' });
  }

  // Build the union of all constraints from all properties
  const constraintSet = new Set<string>();
  for (const prop of properties) {
    for (const c of prop.constraints) {
      constraintSet.add(c);
    }
  }
  const constraints = [...constraintSet];

  const content = {
    agentId,
    alignmentProperties: properties,
    verificationMethod,
    constraints,
  };
  const id = sha256Object(content);

  return {
    id,
    agentId,
    alignmentProperties: properties.map((p) => ({ ...p })),
    verificationMethod,
    constraints,
  };
}

/**
 * Assess how well an agent's execution history matches alignment properties.
 *
 * Uses real CCL parsing and evaluation:
 * 1. For each property, parse its constraints as CCL documents
 * 2. For each execution record, use matchAction/matchResource to check relevance
 * 3. Apply severity-weighted scoring for breaches
 *
 * Severity weights: critical=4x, high=3x, medium=2x, low=1x
 * coverageScore = fulfilledCount / (fulfilledCount + weightedBreachCount)
 * overallAlignmentScore = average of property coverage scores
 * gaps = properties where coverage < 0.5
 */
export function assessAlignment(
  agentId: string,
  covenant: AlignmentCovenant,
  history: ExecutionRecord[],
): AlignmentReport {
  if (!agentId || agentId.trim() === '') {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'agentId must be a non-empty string', { hint: 'Provide a non-empty agentId string when calling assessAlignment.' });
  }

  if (covenant.alignmentProperties.length === 0) {
    return {
      agentId,
      properties: [],
      overallAlignmentScore: 0,
      gaps: [],
      recommendations: [],
    };
  }

  const propertyScores: AlignmentProperty[] = [];
  const gaps: string[] = [];
  const recommendations: string[] = [];

  for (const prop of covenant.alignmentProperties) {
    // Parse all constraints for this property into CCL statements
    const allStatements: Statement[] = [];
    for (const constraintSource of prop.constraints) {
      try {
        const doc = parse(constraintSource);
        allStatements.push(...doc.statements);
      } catch {
        // Invalid CCL - skip this constraint silently
      }
    }

    let fulfilledCount = 0;
    let weightedBreachCount = 0;
    let hasRelevantRecords = false;

    for (const record of history) {
      // Find the first matching statement for this record
      for (const stmt of allStatements) {
        if (stmt.type === 'limit') continue;

        // PermitDenyStatement and RequireStatement both have action, resource, severity
        if (matchAction(stmt.action, record.action) && matchResource(stmt.resource, record.resource)) {
          hasRelevantRecords = true;
          const weight = SEVERITY_WEIGHTS[stmt.severity] ?? 1;

          if (record.outcome === 'fulfilled') {
            fulfilledCount += 1;
          } else {
            weightedBreachCount += weight;
          }
          break; // only match the first applicable statement per record
        }
      }
    }

    let coverageScore: number;
    if (!hasRelevantRecords) {
      coverageScore = 0;
    } else {
      coverageScore = fulfilledCount / (fulfilledCount + weightedBreachCount);
    }

    propertyScores.push({
      name: prop.name,
      constraints: [...prop.constraints],
      testSuite: prop.testSuite,
      coverageScore,
    });

    if (coverageScore < 0.5) {
      gaps.push(prop.name);
      recommendations.push(
        `Improve ${prop.name}: increase compliance with constraints [${prop.constraints.join(', ')}]`,
      );
    }
  }

  const overallAlignmentScore =
    propertyScores.length > 0
      ? propertyScores.reduce((sum, p) => sum + p.coverageScore, 0) / propertyScores.length
      : 0;

  return {
    agentId,
    properties: propertyScores,
    overallAlignmentScore,
    gaps,
    recommendations,
  };
}

/**
 * Returns names of properties whose constraints are NOT all present in actual constraints.
 */
export function alignmentGap(desired: AlignmentProperty[], actual: string[]): string[] {
  const actualSet = new Set(actual);
  const gapNames: string[] = [];

  for (const prop of desired) {
    const allPresent = prop.constraints.every((c) => actualSet.has(c));
    if (!allPresent) {
      gapNames.push(prop.name);
    }
  }

  return gapNames;
}

/**
 * Measure how alignment scores change over time windows to detect gradual
 * misalignment (drift).
 *
 * Splits the execution history into `windowCount` time-ordered windows and
 * computes the alignment score for each window independently. A drop between
 * consecutive windows that exceeds `driftThreshold` triggers drift detection.
 *
 * @param agentId - The agent to assess
 * @param covenant - The alignment covenant
 * @param history - Full execution history (will be sorted by timestamp)
 * @param windowCount - Number of time windows (default: 5)
 * @param driftThreshold - Drop threshold to flag drift (default: 0.1)
 * @throws {Error} if windowCount < 2 or history is empty
 */
export function alignmentDrift(
  agentId: string,
  covenant: AlignmentCovenant,
  history: ExecutionRecord[],
  windowCount = 5,
  driftThreshold = 0.1,
): AlignmentDriftResult {
  if (!agentId || agentId.trim() === '') {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'agentId must be a non-empty string', { hint: 'Provide a non-empty agentId string when calling alignmentDrift.' });
  }
  if (windowCount < 2) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'windowCount must be at least 2', { hint: 'Set windowCount to 2 or higher to enable drift comparison between windows.' });
  }
  if (history.length === 0) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'history must not be empty', { hint: 'Provide at least one ExecutionRecord in the history array.' });
  }

  // Sort by timestamp
  const sorted = [...history].sort((a, b) => a.timestamp - b.timestamp);

  // Split into equal-sized windows
  const windowSize = Math.max(1, Math.ceil(sorted.length / windowCount));
  const windows: ExecutionRecord[][] = [];
  for (let i = 0; i < sorted.length; i += windowSize) {
    windows.push(sorted.slice(i, i + windowSize));
  }

  // Ensure we have exactly windowCount or fewer windows
  const actualWindows = windows.slice(0, windowCount);

  const windowScores: number[] = [];
  const windowStarts: number[] = [];

  for (const window of actualWindows) {
    windowStarts.push(window[0]!.timestamp);
    const report = assessAlignment(agentId, covenant, window);
    windowScores.push(report.overallAlignmentScore);
  }

  // Compute drift metrics
  let maxDrop = 0;
  let driftDetected = false;
  let totalChange = 0;

  for (let i = 1; i < windowScores.length; i++) {
    const drop = windowScores[i - 1]! - windowScores[i]!;
    if (drop > maxDrop) maxDrop = drop;
    if (drop > driftThreshold) driftDetected = true;
    totalChange += windowScores[i]! - windowScores[i - 1]!;
  }

  const avgChange = windowScores.length > 1
    ? totalChange / (windowScores.length - 1)
    : 0;

  let trend: 'improving' | 'stable' | 'degrading';
  if (avgChange > 0.01) {
    trend = 'improving';
  } else if (avgChange < -0.01) {
    trend = 'degrading';
  } else {
    trend = 'stable';
  }

  return {
    windowCount: actualWindows.length,
    windowScores,
    windowStarts,
    maxDrop,
    driftDetected,
    trend,
  };
}

/**
 * Break down the overall alignment score into per-property contributions.
 *
 * Each property's contribution is computed as its individual score multiplied
 * by its weight (equal weight across all properties). The result shows which
 * properties are the strongest and weakest contributors.
 *
 * @param agentId - The agent to assess
 * @param covenant - The alignment covenant
 * @param history - Execution history
 */
export function alignmentDecomposition(
  agentId: string,
  covenant: AlignmentCovenant,
  history: ExecutionRecord[],
): AlignmentDecompositionResult {
  if (!agentId || agentId.trim() === '') {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'agentId must be a non-empty string', { hint: 'Provide a non-empty agentId string when calling alignmentDecomposition.' });
  }

  const report = assessAlignment(agentId, covenant, history);

  const propCount = report.properties.length;
  if (propCount === 0) {
    return {
      overallScore: 0,
      propertyContributions: [],
      weakest: [],
      strongest: [],
    };
  }

  const weight = 1 / propCount;
  const contributions: PropertyContribution[] = report.properties.map((prop) => ({
    name: prop.name,
    score: prop.coverageScore,
    weight,
    contribution: prop.coverageScore * weight,
  }));

  // Sort by score to identify strongest and weakest
  const sorted = [...contributions].sort((a, b) => a.score - b.score);
  const weakest = sorted.filter((c) => c.score < 0.5).map((c) => c.name);
  const strongest = sorted.filter((c) => c.score >= 0.5).map((c) => c.name);

  return {
    overallScore: report.overallAlignmentScore,
    propertyContributions: contributions,
    weakest,
    strongest,
  };
}

// ---------------------------------------------------------------------------
// Adaptive Property Weights
// ---------------------------------------------------------------------------

/** A single weight update observation. */
export interface WeightObservation {
  /** Name of the property that was violated or observed. */
  propertyName: string;
  /** Severity multiplier (higher = more significant violation). */
  severity: number;
  /** Timestamp of the observation. */
  timestamp: number;
}

/** Snapshot of adaptive weights at a point in time. */
export interface AdaptiveWeightSnapshot {
  /** Property name to current weight mapping (weights sum to 1). */
  weights: Record<string, number>;
  /** Number of observations processed. */
  observationCount: number;
  /** EMA decay factor in use. */
  alpha: number;
}

/**
 * Replaces fixed HHH weights with learnable weights that adapt based on
 * observed violations and drift patterns.
 *
 * Uses exponential moving average (EMA) to weight recent observations more
 * heavily. Properties that are violated more frequently or more severely
 * receive higher weights, focusing alignment effort where it's needed most.
 */
export class AdaptiveAlignmentTracker {
  private rawWeights: Record<string, number> = {};
  private violationCounts: Record<string, number> = {};
  private readonly alpha: number;
  private observationCount = 0;
  private readonly propertyNames: string[];

  /**
   * @param properties Initial alignment properties (used to initialize uniform weights).
   * @param alpha EMA decay factor (0 < alpha < 1). Higher = faster adaptation. Default: 0.3.
   */
  constructor(properties: AlignmentProperty[], alpha = 0.3) {
    if (properties.length === 0) {
      throw new SteleError(
        'Must provide at least one alignment property',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (alpha <= 0 || alpha >= 1) {
      throw new SteleError(
        'alpha must be between 0 and 1 (exclusive)',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.alpha = alpha;
    this.propertyNames = properties.map(p => p.name);

    // Initialize uniform weights
    const uniform = 1 / properties.length;
    for (const name of this.propertyNames) {
      this.rawWeights[name] = uniform;
      this.violationCounts[name] = 0;
    }
  }

  /**
   * Record an observation (violation or drift event) and update weights.
   * Properties that are violated more frequently will have their weights
   * increased via EMA so alignment assessment concentrates on weak areas.
   */
  recordObservation(obs: WeightObservation): void {
    if (!this.propertyNames.includes(obs.propertyName)) {
      throw new SteleError(
        `Unknown property: "${obs.propertyName}". Known: [${this.propertyNames.join(', ')}]`,
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!Number.isFinite(obs.severity) || obs.severity < 0) {
      throw new SteleError(
        'severity must be a non-negative finite number',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    this.observationCount++;
    this.violationCounts[obs.propertyName] = (this.violationCounts[obs.propertyName] ?? 0) + 1;

    // EMA update: new_weight = alpha * signal + (1 - alpha) * old_weight
    // Signal = severity (normalized) for the violated property
    const signal = Math.min(obs.severity, 10) / 10; // Normalize to [0, 1]
    this.rawWeights[obs.propertyName] =
      this.alpha * signal + (1 - this.alpha) * (this.rawWeights[obs.propertyName] ?? 0);

    // Re-normalize all weights to sum to 1
    this.normalizeWeights();
  }

  /** Get the current adaptive weights, normalized to sum to 1. */
  getWeights(): Record<string, number> {
    return { ...this.rawWeights };
  }

  /** Take a snapshot of the current tracker state. */
  snapshot(): AdaptiveWeightSnapshot {
    return {
      weights: this.getWeights(),
      observationCount: this.observationCount,
      alpha: this.alpha,
    };
  }

  /** Get violation counts per property. */
  getViolationCounts(): Record<string, number> {
    return { ...this.violationCounts };
  }

  /**
   * Compute a weighted alignment score using the current adaptive weights
   * instead of uniform weights.
   */
  weightedScore(propertyScores: Array<{ name: string; score: number }>): number {
    if (propertyScores.length === 0) return 0;
    let totalWeight = 0;
    let weightedSum = 0;
    for (const ps of propertyScores) {
      const w = this.rawWeights[ps.name] ?? 0;
      weightedSum += ps.score * w;
      totalWeight += w;
    }
    return totalWeight > 0 ? weightedSum / totalWeight : 0;
  }

  /** Re-normalize raw weights so they sum to 1. */
  private normalizeWeights(): void {
    const total = Object.values(this.rawWeights).reduce((s, w) => s + w, 0);
    if (total > 0) {
      for (const key of Object.keys(this.rawWeights)) {
        this.rawWeights[key] = this.rawWeights[key]! / total;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Per-Property Anomaly Detection
// ---------------------------------------------------------------------------

/** Running statistics for a single alignment property. */
export interface PropertyStatistics {
  name: string;
  count: number;
  mean: number;
  variance: number;
  skewness: number;
  min: number;
  max: number;
}

/** Anomaly detection result for a single observation. */
export interface AnomalyResult {
  propertyName: string;
  value: number;
  modifiedZScore: number;
  isAnomaly: boolean;
  threshold: number;
}

/**
 * Isolation-forest-inspired anomaly detection for alignment property scores.
 *
 * Maintains running statistics (mean, variance, skewness) per property and
 * detects outliers using the modified z-score based on the median absolute
 * deviation (MAD). This is more robust than standard z-scores because it
 * is less sensitive to extreme outliers.
 */
export class PropertyAnomalyDetector {
  private readonly dataByProperty: Record<string, number[]> = {};
  private readonly anomalyThreshold: number;

  /**
   * @param anomalyThreshold Modified z-score threshold for flagging anomalies
   *                         (default: 3.5, a common robust threshold).
   */
  constructor(anomalyThreshold = 3.5) {
    if (!Number.isFinite(anomalyThreshold) || anomalyThreshold <= 0) {
      throw new SteleError(
        'anomalyThreshold must be a positive finite number',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.anomalyThreshold = anomalyThreshold;
  }

  /**
   * Record a property score observation.
   * @param propertyName Name of the alignment property.
   * @param value The observed score value.
   */
  record(propertyName: string, value: number): void {
    if (!propertyName || propertyName.trim() === '') {
      throw new SteleError(
        'propertyName must be a non-empty string',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!Number.isFinite(value)) {
      throw new SteleError(
        'value must be a finite number',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!this.dataByProperty[propertyName]) {
      this.dataByProperty[propertyName] = [];
    }
    this.dataByProperty[propertyName].push(value);
  }

  /**
   * Check whether a given value is an anomaly for a property.
   * Uses the modified z-score: 0.6745 * (x - median) / MAD.
   *
   * @param propertyName The property to check.
   * @param value The value to evaluate.
   * @returns AnomalyResult with the modified z-score and anomaly flag.
   */
  check(propertyName: string, value: number): AnomalyResult {
    if (!propertyName || propertyName.trim() === '') {
      throw new SteleError(
        'propertyName must be a non-empty string',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!Number.isFinite(value)) {
      throw new SteleError(
        'value must be a finite number',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    const data = this.dataByProperty[propertyName];
    if (!data || data.length < 2) {
      // Not enough data to detect anomalies
      return {
        propertyName,
        value,
        modifiedZScore: 0,
        isAnomaly: false,
        threshold: this.anomalyThreshold,
      };
    }

    const median = PropertyAnomalyDetector.median(data);
    const mad = PropertyAnomalyDetector.medianAbsoluteDeviation(data, median);

    // Modified z-score. 0.6745 is the 0.75th quantile of the standard normal,
    // used to make MAD comparable to standard deviation.
    const modifiedZScore = mad > 0
      ? (0.6745 * (value - median)) / mad
      : 0;

    return {
      propertyName,
      value,
      modifiedZScore,
      isAnomaly: Math.abs(modifiedZScore) > this.anomalyThreshold,
      threshold: this.anomalyThreshold,
    };
  }

  /**
   * Compute running statistics for a property.
   */
  statistics(propertyName: string): PropertyStatistics {
    if (!propertyName || propertyName.trim() === '') {
      throw new SteleError(
        'propertyName must be a non-empty string',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    const data = this.dataByProperty[propertyName];
    if (!data || data.length === 0) {
      return { name: propertyName, count: 0, mean: 0, variance: 0, skewness: 0, min: 0, max: 0 };
    }

    const n = data.length;
    const mean = data.reduce((s, v) => s + v, 0) / n;
    const variance = data.reduce((s, v) => s + (v - mean) ** 2, 0) / n;
    const stdDev = Math.sqrt(variance);

    // Skewness: E[(X-mu)^3] / sigma^3
    const skewness = stdDev > 0
      ? data.reduce((s, v) => s + ((v - mean) / stdDev) ** 3, 0) / n
      : 0;

    return {
      name: propertyName,
      count: n,
      mean,
      variance,
      skewness,
      min: Math.min(...data),
      max: Math.max(...data),
    };
  }

  /** List all tracked property names. */
  getTrackedProperties(): string[] {
    return Object.keys(this.dataByProperty);
  }

  /** Compute the median of a sorted numeric array. */
  private static median(values: number[]): number {
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 === 0
      ? (sorted[mid - 1]! + sorted[mid]!) / 2
      : sorted[mid]!;
  }

  /** Compute the median absolute deviation. */
  private static medianAbsoluteDeviation(values: number[], median: number): number {
    const deviations = values.map(v => Math.abs(v - median));
    return PropertyAnomalyDetector.median(deviations);
  }
}

// ---------------------------------------------------------------------------
// Alignment Drift Forecasting
// ---------------------------------------------------------------------------

/** Forecast result for alignment drift prediction. */
export interface DriftForecast {
  /** Forecasted alignment scores for future time steps. */
  forecastedScores: number[];
  /** Time steps ahead that were forecasted. */
  horizonSteps: number;
  /** Estimated time steps until the score breaches the threshold (Infinity if never). */
  stepsToThresholdBreach: number;
  /** The threshold used for breach estimation. */
  breachThreshold: number;
  /** Method used for the forecast. */
  method: 'linear-regression' | 'holt-double-exponential';
  /** Linear regression slope (rate of drift per time step). */
  slope: number;
  /** Linear regression intercept. */
  intercept: number;
}

/**
 * Forecasts future alignment scores using linear regression and
 * Holt's double exponential smoothing to predict drift and estimate
 * time-to-threshold-breach.
 */
export class DriftForecaster {
  private readonly scores: number[] = [];

  /**
   * Add an observed alignment score (in chronological order).
   */
  addScore(score: number): void {
    if (!Number.isFinite(score)) {
      throw new SteleError(
        'score must be a finite number',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.scores.push(score);
  }

  /** Add multiple scores at once. */
  addScores(scores: number[]): void {
    for (const s of scores) {
      this.addScore(s);
    }
  }

  /** Return a copy of recorded scores. */
  getScores(): number[] {
    return [...this.scores];
  }

  /**
   * Forecast using ordinary least squares linear regression.
   *
   * @param horizon Number of time steps to forecast ahead (default: 5).
   * @param breachThreshold Score below which we consider alignment breached (default: 0.5).
   * @throws {SteleError} if fewer than 2 scores are recorded.
   */
  forecastLinear(horizon = 5, breachThreshold = 0.5): DriftForecast {
    if (horizon < 1) {
      throw new SteleError(
        'horizon must be at least 1',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (this.scores.length < 2) {
      throw new SteleError(
        'Need at least 2 scores for linear regression',
        SteleErrorCode.PROTOCOL_COMPUTATION_FAILED,
      );
    }

    const n = this.scores.length;
    const { slope, intercept } = DriftForecaster.linearRegression(this.scores);

    // Forecast future values
    const forecastedScores: number[] = [];
    for (let step = 1; step <= horizon; step++) {
      forecastedScores.push(intercept + slope * (n - 1 + step));
    }

    // Estimate time to threshold breach
    let stepsToThresholdBreach = Infinity;
    if (slope < 0) {
      // Linear: intercept + slope * t = breachThreshold
      const currentProjected = intercept + slope * (n - 1);
      if (currentProjected > breachThreshold) {
        stepsToThresholdBreach = Math.ceil((breachThreshold - currentProjected) / slope);
        if (stepsToThresholdBreach < 0) stepsToThresholdBreach = Infinity;
      }
    }

    return {
      forecastedScores,
      horizonSteps: horizon,
      stepsToThresholdBreach,
      breachThreshold,
      method: 'linear-regression',
      slope,
      intercept,
    };
  }

  /**
   * Forecast using Holt's double exponential smoothing (trend-corrected EMA).
   * Better than linear regression for nonlinear drift patterns.
   *
   * @param horizon Number of time steps to forecast ahead (default: 5).
   * @param breachThreshold Score below which alignment is breached (default: 0.5).
   * @param levelAlpha Smoothing factor for the level component (default: 0.3).
   * @param trendBeta Smoothing factor for the trend component (default: 0.1).
   */
  forecastHolt(
    horizon = 5,
    breachThreshold = 0.5,
    levelAlpha = 0.3,
    trendBeta = 0.1,
  ): DriftForecast {
    if (horizon < 1) {
      throw new SteleError('horizon must be at least 1', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (this.scores.length < 2) {
      throw new SteleError(
        'Need at least 2 scores for Holt smoothing',
        SteleErrorCode.PROTOCOL_COMPUTATION_FAILED,
      );
    }
    if (levelAlpha <= 0 || levelAlpha >= 1) {
      throw new SteleError(
        'levelAlpha must be between 0 and 1 (exclusive)',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (trendBeta <= 0 || trendBeta >= 1) {
      throw new SteleError(
        'trendBeta must be between 0 and 1 (exclusive)',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    // Initialize level and trend from first two observations
    let level = this.scores[0]!;
    let trend = this.scores[1]! - this.scores[0]!;

    // Update through all observations
    for (let i = 1; i < this.scores.length; i++) {
      const newLevel = levelAlpha * this.scores[i]! + (1 - levelAlpha) * (level + trend);
      const newTrend = trendBeta * (newLevel - level) + (1 - trendBeta) * trend;
      level = newLevel;
      trend = newTrend;
    }

    // Forecast
    const forecastedScores: number[] = [];
    for (let step = 1; step <= horizon; step++) {
      forecastedScores.push(level + trend * step);
    }

    // Time to breach
    let stepsToThresholdBreach = Infinity;
    if (trend < 0 && level > breachThreshold) {
      stepsToThresholdBreach = Math.ceil((breachThreshold - level) / trend);
      if (stepsToThresholdBreach < 0) stepsToThresholdBreach = Infinity;
    }

    return {
      forecastedScores,
      horizonSteps: horizon,
      stepsToThresholdBreach,
      breachThreshold,
      method: 'holt-double-exponential',
      slope: trend,
      intercept: level,
    };
  }

  /** Ordinary least-squares linear regression: y = intercept + slope * x. */
  private static linearRegression(values: number[]): { slope: number; intercept: number } {
    const n = values.length;
    let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
    for (let i = 0; i < n; i++) {
      sumX += i;
      sumY += values[i]!;
      sumXY += i * values[i]!;
      sumX2 += i * i;
    }
    const denom = n * sumX2 - sumX * sumX;
    if (denom === 0) return { slope: 0, intercept: sumY / n };
    const slope = (n * sumXY - sumX * sumY) / denom;
    const intercept = (sumY - slope * sumX) / n;
    return { slope, intercept };
  }
}

// ---------------------------------------------------------------------------
// Multi-Dimensional Alignment Surface
// ---------------------------------------------------------------------------

/** Gradient information for a single property dimension. */
export interface DimensionGradient {
  propertyName: string;
  currentScore: number;
  gradient: number;
  isWeakDimension: boolean;
  recommendation: string;
}

/** Result of alignment surface analysis. */
export interface AlignmentSurfaceResult {
  /** Overall alignment score at the current point. */
  overallScore: number;
  /** Per-dimension gradient information. */
  dimensions: DimensionGradient[];
  /** Properties that are pulling the alignment surface down. */
  weakDimensions: string[];
  /** Properties that are the strongest contributors. */
  strongDimensions: string[];
  /** Euclidean distance from the ideal point (all scores = 1). */
  distanceFromIdeal: number;
  /** Aggregate gradient magnitude (how fast alignment changes). */
  gradientMagnitude: number;
}

/**
 * Models alignment as a surface in property space. Each alignment property
 * defines a dimension, and the alignment score is a surface over that space.
 *
 * Provides methods to compute alignment score gradients, identify weak
 * dimensions, and generate improvement recommendations.
 */
export class AlignmentSurface {
  private readonly propertyNames: string[];
  private readonly history: Array<Record<string, number>> = [];

  /**
   * @param propertyNames Names of alignment property dimensions.
   */
  constructor(propertyNames: string[]) {
    if (propertyNames.length === 0) {
      throw new SteleError(
        'Must provide at least one property dimension',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    const unique = new Set(propertyNames);
    if (unique.size !== propertyNames.length) {
      throw new SteleError(
        'Property names must be unique',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.propertyNames = [...propertyNames];
  }

  /**
   * Record a point on the alignment surface (scores for each property).
   * @param scores Property name to score mapping.
   */
  addPoint(scores: Record<string, number>): void {
    for (const name of this.propertyNames) {
      if (!(name in scores)) {
        throw new SteleError(
          `Missing score for property "${name}"`,
          SteleErrorCode.PROTOCOL_INVALID_INPUT,
        );
      }
      if (!Number.isFinite(scores[name])) {
        throw new SteleError(
          `Score for "${name}" must be a finite number`,
          SteleErrorCode.PROTOCOL_INVALID_INPUT,
        );
      }
    }
    const point: Record<string, number> = {};
    for (const name of this.propertyNames) {
      point[name] = scores[name]!;
    }
    this.history.push(point);
  }

  /**
   * Analyze the alignment surface at the most recent point.
   *
   * Computes:
   * - Per-dimension gradients (rate of change from recent history)
   * - Weak and strong dimensions
   * - Distance from the ideal alignment point
   * - Improvement recommendations
   *
   * @param weakThreshold Score below which a dimension is considered weak (default: 0.5).
   * @throws {SteleError} if fewer than 2 points have been recorded.
   */
  analyze(weakThreshold = 0.5): AlignmentSurfaceResult {
    if (this.history.length < 2) {
      throw new SteleError(
        'Need at least 2 data points for surface analysis',
        SteleErrorCode.PROTOCOL_COMPUTATION_FAILED,
      );
    }

    const current = this.history[this.history.length - 1]!;
    const previous = this.history[this.history.length - 2]!;

    const dimensions: DimensionGradient[] = [];
    const weakDimensions: string[] = [];
    const strongDimensions: string[] = [];
    let sumSquaredDistFromIdeal = 0;
    let sumSquaredGradient = 0;

    for (const name of this.propertyNames) {
      const currentScore = current[name]!;
      const previousScore = previous[name]!;
      const gradient = currentScore - previousScore;

      const isWeak = currentScore < weakThreshold;
      if (isWeak) {
        weakDimensions.push(name);
      } else {
        strongDimensions.push(name);
      }

      let recommendation: string;
      if (isWeak && gradient <= 0) {
        recommendation = `URGENT: "${name}" is weak (${currentScore.toFixed(3)}) and declining. Immediate intervention needed.`;
      } else if (isWeak && gradient > 0) {
        recommendation = `"${name}" is weak (${currentScore.toFixed(3)}) but improving (+${gradient.toFixed(3)}). Continue current efforts.`;
      } else if (!isWeak && gradient < -0.05) {
        recommendation = `WARNING: "${name}" is declining rapidly (${gradient.toFixed(3)}). Monitor closely.`;
      } else {
        recommendation = `"${name}" is healthy at ${currentScore.toFixed(3)}.`;
      }

      dimensions.push({ propertyName: name, currentScore, gradient, isWeakDimension: isWeak, recommendation });
      sumSquaredDistFromIdeal += (1 - currentScore) ** 2;
      sumSquaredGradient += gradient ** 2;
    }

    const overallScore = this.propertyNames.reduce((s, n) => s + current[n]!, 0) / this.propertyNames.length;

    return {
      overallScore,
      dimensions,
      weakDimensions,
      strongDimensions,
      distanceFromIdeal: Math.sqrt(sumSquaredDistFromIdeal),
      gradientMagnitude: Math.sqrt(sumSquaredGradient),
    };
  }

  /** Return a copy of the history. */
  getHistory(): Array<Record<string, number>> {
    return this.history.map(p => ({ ...p }));
  }
}

// ---------------------------------------------------------------------------
// Alignment Feedback Loop
// ---------------------------------------------------------------------------

/** Configuration for the alignment feedback loop. */
export interface FeedbackLoopConfig {
  /** Learning rate for gradient-descent-like updates (default: 0.01). */
  learningRate: number;
  /** Minimum allowed threshold for any property (default: 0.1). */
  minThreshold: number;
  /** Maximum allowed threshold for any property (default: 0.95). */
  maxThreshold: number;
}

/** Outcome observation for the feedback loop. */
export interface AlignmentOutcome {
  /** Per-property observed scores. */
  propertyScores: Record<string, number>;
  /** Whether the overall outcome was considered acceptable. */
  acceptable: boolean;
  /** Timestamp of the observation. */
  timestamp: number;
}

/** Snapshot of the feedback loop state. */
export interface FeedbackLoopState {
  /** Current thresholds per property. */
  thresholds: Record<string, number>;
  /** Current weights per property. */
  weights: Record<string, number>;
  /** Number of outcomes processed. */
  outcomeCount: number;
  /** Running average acceptance rate. */
  acceptanceRate: number;
}

/**
 * Closed-loop controller that takes observed alignment outcomes and
 * adjusts thresholds and weights automatically using gradient-descent-like
 * updates.
 *
 * When outcomes are unacceptable, the loop tightens thresholds for
 * underperforming properties and increases their weights. When outcomes are
 * consistently acceptable, it relaxes slightly to avoid over-constraining.
 */
export class AlignmentFeedbackLoop {
  private thresholds: Record<string, number> = {};
  private weights: Record<string, number> = {};
  private readonly config: FeedbackLoopConfig;
  private readonly propertyNames: string[];
  private outcomeCount = 0;
  private acceptableCount = 0;

  /**
   * @param properties Alignment properties to track.
   * @param initialThreshold Starting threshold for all properties (default: 0.5).
   * @param config Feedback loop configuration.
   */
  constructor(
    properties: AlignmentProperty[],
    initialThreshold = 0.5,
    config: Partial<FeedbackLoopConfig> = {},
  ) {
    if (properties.length === 0) {
      throw new SteleError(
        'Must provide at least one alignment property',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (initialThreshold < 0 || initialThreshold > 1) {
      throw new SteleError(
        'initialThreshold must be between 0 and 1',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    this.config = {
      learningRate: config.learningRate ?? 0.01,
      minThreshold: config.minThreshold ?? 0.1,
      maxThreshold: config.maxThreshold ?? 0.95,
    };

    if (this.config.learningRate <= 0 || this.config.learningRate >= 1) {
      throw new SteleError(
        'learningRate must be between 0 and 1 (exclusive)',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    this.propertyNames = properties.map(p => p.name);
    const uniformWeight = 1 / properties.length;
    for (const name of this.propertyNames) {
      this.thresholds[name] = initialThreshold;
      this.weights[name] = uniformWeight;
    }
  }

  /**
   * Feed an observed outcome into the loop.
   *
   * For unacceptable outcomes:
   *   - Properties scoring below their threshold: tighten threshold slightly,
   *     increase weight (focus more attention here).
   *   - Properties scoring above their threshold: slight weight decrease.
   *
   * For acceptable outcomes:
   *   - Slightly relax all thresholds (avoid over-constraining).
   */
  feedOutcome(outcome: AlignmentOutcome): void {
    this.outcomeCount++;
    if (outcome.acceptable) {
      this.acceptableCount++;
    }

    const lr = this.config.learningRate;

    for (const name of this.propertyNames) {
      const score = outcome.propertyScores[name];
      if (score === undefined || !Number.isFinite(score)) continue;

      const threshold = this.thresholds[name]!;

      if (!outcome.acceptable) {
        if (score < threshold) {
          // Property underperformed: tighten threshold, increase weight
          // Gradient points toward stricter enforcement
          this.thresholds[name] = Math.min(
            this.config.maxThreshold,
            threshold + lr * (threshold - score),
          );
          this.weights[name] = (this.weights[name] ?? 0) + lr * (1 - score);
        } else {
          // Property was fine but overall outcome was bad:
          // slightly decrease weight (other properties need more focus)
          this.weights[name] = Math.max(0.01, (this.weights[name] ?? 0) - lr * 0.1);
        }
      } else {
        // Acceptable outcome: slightly relax threshold to avoid over-constraining
        this.thresholds[name] = Math.max(
          this.config.minThreshold,
          threshold - lr * 0.05,
        );
      }
    }

    // Re-normalize weights
    const totalWeight = Object.values(this.weights).reduce((s, w) => s + w, 0);
    if (totalWeight > 0) {
      for (const key of Object.keys(this.weights)) {
        this.weights[key] = this.weights[key]! / totalWeight;
      }
    }
  }

  /** Get the current state of the feedback loop. */
  getState(): FeedbackLoopState {
    return {
      thresholds: { ...this.thresholds },
      weights: { ...this.weights },
      outcomeCount: this.outcomeCount,
      acceptanceRate: this.outcomeCount > 0 ? this.acceptableCount / this.outcomeCount : 0,
    };
  }

  /** Get current thresholds. */
  getThresholds(): Record<string, number> {
    return { ...this.thresholds };
  }

  /** Get current weights. */
  getWeights(): Record<string, number> {
    return { ...this.weights };
  }

  /**
   * Evaluate whether a set of property scores would pass the current
   * adaptive thresholds.
   */
  evaluate(scores: Record<string, number>): { passed: boolean; failures: string[] } {
    const failures: string[] = [];
    for (const name of this.propertyNames) {
      const score = scores[name];
      const threshold = this.thresholds[name]!;
      if (score === undefined || score < threshold) {
        failures.push(name);
      }
    }
    return { passed: failures.length === 0, failures };
  }
}
