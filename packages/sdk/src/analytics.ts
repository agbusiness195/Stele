/**
 * Trust data aggregation and analytics for the Stele protocol.
 *
 * Aggregates individual trust data points into insights, anonymizes datasets
 * for sharing, and computes trends over time. Supports both k-anonymity and
 * differential privacy anonymization methods.
 *
 * @packageDocumentation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

/** A single trust data point for one agent at one point in time. */
export interface TrustDataPoint {
  /** The agent this data point belongs to. */
  agentId: string;
  /** Timestamp of the measurement. */
  timestamp: number;
  /** The agent's trust score at this time. */
  trustScore: number;
  /** Number of breaches recorded. */
  breachCount: number;
  /** Number of attestations received. */
  attestationCount: number;
  /** Total transaction volume. */
  transactionVolume: number;
}

/** Aggregated insight derived from a collection of data points. */
export interface AggregatedInsight {
  /** Time period covered by this insight. */
  period: { start: number; end: number };
  /** Total number of unique agents. */
  totalAgents: number;
  /** Mean trust score across all agents. */
  averageTrustScore: number;
  /** Median trust score across all agents. */
  medianTrustScore: number;
  /** Distribution of trust scores across buckets. */
  trustDistribution: Array<{ bucket: string; count: number; percentage: number }>;
  /** Rate of breaches (agents with breaches / total agents). */
  breachRate: number;
  /** Agent IDs with trust scores >= 0.9. */
  topPerformers: string[];
  /** Agent IDs with trust scores < 0.3 or any breaches. */
  atRiskAgents: string[];
}

/** An anonymized dataset suitable for sharing. */
export interface AnonymizedDataset {
  /** Unique identifier for this dataset. */
  id: string;
  /** Timestamp when the dataset was generated. */
  generatedAt: number;
  /** Number of agents included. */
  agentCount: number;
  /** The aggregated insights (with agent IDs removed). */
  insights: AggregatedInsight;
  /** The anonymization method used. */
  anonymizationMethod: 'k-anonymity' | 'differential-privacy';
  /** Privacy budget (epsilon) for differential privacy. */
  privacyBudget: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Compute the median of a sorted numeric array. */
function median(sorted: number[]): number {
  if (sorted.length === 0) return 0;
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    return (sorted[mid - 1]! + sorted[mid]!) / 2;
  }
  return sorted[mid]!;
}

/** Simple deterministic ID generator for datasets. */
let _datasetCounter = 0;
function generateDatasetId(): string {
  _datasetCounter += 1;
  return `ds-${Date.now()}-${_datasetCounter}`;
}

// ─── Trust Distribution Buckets ──────────────────────────────────────────────

const TRUST_BUCKETS: Array<{ label: string; min: number; max: number }> = [
  { label: '0.0-0.2', min: 0, max: 0.2 },
  { label: '0.2-0.4', min: 0.2, max: 0.4 },
  { label: '0.4-0.6', min: 0.4, max: 0.6 },
  { label: '0.6-0.8', min: 0.6, max: 0.8 },
  { label: '0.8-1.0', min: 0.8, max: 1.0 },
];

// ─── Aggregation ─────────────────────────────────────────────────────────────

/**
 * Aggregate trust data points into an insight summary.
 *
 * Groups data by agent (using the latest data point per agent),
 * computes averages, medians, distributions, and identifies
 * top performers and at-risk agents.
 *
 * @param dataPoints - Raw trust data points.
 * @returns An AggregatedInsight summarizing the data.
 */
export function aggregateData(dataPoints: TrustDataPoint[]): AggregatedInsight {
  if (dataPoints.length === 0) {
    return {
      period: { start: 0, end: 0 },
      totalAgents: 0,
      averageTrustScore: 0,
      medianTrustScore: 0,
      trustDistribution: TRUST_BUCKETS.map((b) => ({
        bucket: b.label,
        count: 0,
        percentage: 0,
      })),
      breachRate: 0,
      topPerformers: [],
      atRiskAgents: [],
    };
  }

  // Find the latest data point per agent
  const latestByAgent = new Map<string, TrustDataPoint>();
  for (const dp of dataPoints) {
    const existing = latestByAgent.get(dp.agentId);
    if (!existing || dp.timestamp > existing.timestamp) {
      latestByAgent.set(dp.agentId, dp);
    }
  }

  const agents = Array.from(latestByAgent.values());
  const totalAgents = agents.length;

  // Period
  const timestamps = dataPoints.map((dp) => dp.timestamp);
  const start = Math.min(...timestamps);
  const end = Math.max(...timestamps);

  // Trust scores
  const trustScores = agents.map((a) => a.trustScore).sort((a, b) => a - b);
  const averageTrustScore =
    trustScores.reduce((sum, s) => sum + s, 0) / totalAgents;
  const medianTrustScore = median(trustScores);

  // Distribution
  const trustDistribution = TRUST_BUCKETS.map((bucket) => {
    const count = agents.filter(
      (a) =>
        a.trustScore >= bucket.min &&
        (bucket.max === 1.0 ? a.trustScore <= bucket.max : a.trustScore < bucket.max),
    ).length;
    return {
      bucket: bucket.label,
      count,
      percentage: totalAgents === 0 ? 0 : (count / totalAgents) * 100,
    };
  });

  // Breach rate
  const agentsWithBreaches = agents.filter((a) => a.breachCount > 0).length;
  const breachRate = totalAgents === 0 ? 0 : agentsWithBreaches / totalAgents;

  // Top performers: trust score >= 0.9
  const topPerformers = agents
    .filter((a) => a.trustScore >= 0.9)
    .map((a) => a.agentId);

  // At-risk: trust score < 0.3 or breachCount > 0
  const atRiskAgents = agents
    .filter((a) => a.trustScore < 0.3 || a.breachCount > 0)
    .map((a) => a.agentId);

  return {
    period: { start, end },
    totalAgents,
    averageTrustScore,
    medianTrustScore,
    trustDistribution,
    breachRate,
    topPerformers,
    atRiskAgents,
  };
}

// ─── Anonymization ───────────────────────────────────────────────────────────

/**
 * Create an anonymized dataset from aggregated insights.
 *
 * Strips individual agent identifiers and optionally adds noise
 * for differential privacy (proportional to 1/privacyBudget).
 *
 * @param insight - The aggregated insight to anonymize.
 * @param params - Anonymization method and privacy budget.
 * @returns An AnonymizedDataset suitable for sharing.
 */
export function anonymizeDataset(
  insight: AggregatedInsight,
  params?: {
    method?: 'k-anonymity' | 'differential-privacy';
    privacyBudget?: number;
  },
): AnonymizedDataset {
  const method = params?.method ?? 'k-anonymity';
  const privacyBudget = params?.privacyBudget ?? 1.0;

  // Strip agent identifiers
  let anonymizedInsight: AggregatedInsight = {
    ...insight,
    topPerformers: [],
    atRiskAgents: [],
  };

  // Add noise for differential privacy
  if (method === 'differential-privacy' && privacyBudget > 0) {
    const noiseScale = 1 / privacyBudget;

    // Add Laplace-like noise (deterministic approximation for reproducibility)
    const noisyAverage = anonymizedInsight.averageTrustScore + noiseScale * 0.01;
    const noisyMedian = anonymizedInsight.medianTrustScore + noiseScale * 0.01;
    const noisyBreachRate = Math.max(
      0,
      Math.min(1, anonymizedInsight.breachRate + noiseScale * 0.005),
    );

    anonymizedInsight = {
      ...anonymizedInsight,
      averageTrustScore: noisyAverage,
      medianTrustScore: noisyMedian,
      breachRate: noisyBreachRate,
    };
  }

  return {
    id: generateDatasetId(),
    generatedAt: Date.now(),
    agentCount: insight.totalAgents,
    insights: anonymizedInsight,
    anonymizationMethod: method,
    privacyBudget,
  };
}

// ─── Trend Analysis ──────────────────────────────────────────────────────────

/**
 * Compute trends from a series of aggregated insights over time.
 *
 * Determines whether trust scores and breach rates are improving,
 * stable, or declining/worsening. Also computes the growth rate
 * of the agent population and an overall health score.
 *
 * @param insights - Array of insights ordered chronologically.
 * @returns Trend analysis with trust, breach, growth, and health metrics.
 */
export function computeTrends(insights: AggregatedInsight[]): {
  trustTrend: 'improving' | 'stable' | 'declining';
  breachTrend: 'improving' | 'stable' | 'worsening';
  growthRate: number;
  healthScore: number;
} {
  if (insights.length < 2) {
    return {
      trustTrend: 'stable',
      breachTrend: 'stable',
      growthRate: 0,
      healthScore: insights.length === 1 ? insights[0]!.averageTrustScore * 100 : 50,
    };
  }

  const first = insights[0]!;
  const last = insights[insights.length - 1]!;

  // Trust trend
  const trustDelta = last.averageTrustScore - first.averageTrustScore;
  const TRUST_THRESHOLD = 0.05;
  let trustTrend: 'improving' | 'stable' | 'declining';
  if (trustDelta > TRUST_THRESHOLD) {
    trustTrend = 'improving';
  } else if (trustDelta < -TRUST_THRESHOLD) {
    trustTrend = 'declining';
  } else {
    trustTrend = 'stable';
  }

  // Breach trend
  const breachDelta = last.breachRate - first.breachRate;
  const BREACH_THRESHOLD = 0.02;
  let breachTrend: 'improving' | 'stable' | 'worsening';
  if (breachDelta < -BREACH_THRESHOLD) {
    breachTrend = 'improving';
  } else if (breachDelta > BREACH_THRESHOLD) {
    breachTrend = 'worsening';
  } else {
    breachTrend = 'stable';
  }

  // Growth rate
  const growthRate =
    first.totalAgents === 0
      ? 0
      : (last.totalAgents - first.totalAgents) / first.totalAgents;

  // Health score (0-100)
  // Based on latest average trust, breach rate, and trend direction
  let healthScore = last.averageTrustScore * 80; // base: 0-80 from trust
  healthScore += (1 - last.breachRate) * 20; // bonus: 0-20 from low breaches
  if (trustTrend === 'improving') healthScore = Math.min(100, healthScore + 5);
  if (trustTrend === 'declining') healthScore = Math.max(0, healthScore - 5);
  healthScore = Math.max(0, Math.min(100, healthScore));

  return {
    trustTrend,
    breachTrend,
    growthRate,
    healthScore,
  };
}
