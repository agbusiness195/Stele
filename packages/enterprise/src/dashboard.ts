/**
 * Metrics Dashboard data model for the Kova protocol.
 *
 * Provides a structured data model for building monitoring dashboards
 * with metric series, panels, aggregation, and retention policies.
 * Includes a pre-built standard dashboard with panels for trust,
 * enforcement, performance, and business metrics.
 *
 * @packageDocumentation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

/** Configuration for a metrics dashboard. */
export interface DashboardConfig {
  /** How often the dashboard refreshes, in milliseconds. */
  refreshIntervalMs: number;
  /** How long data points are retained, in milliseconds. */
  retentionPeriodMs: number;
  /** Maximum number of data points per metric series. */
  maxDataPoints: number;
}

/** A single data point in a metric series. */
export interface MetricPoint {
  /** Timestamp of the data point (ms since epoch). */
  timestamp: number;
  /** Numeric value of the data point. */
  value: number;
  /** Labels for dimensionality (e.g. { agentId: 'abc', method: 'read' }). */
  labels: Record<string, string>;
}

/** A time series of metric data points with aggregation metadata. */
export interface MetricSeries {
  /** Name of the metric (e.g. 'trust_resolutions_total'). */
  name: string;
  /** Unit of the metric (e.g. 'count', 'ms', 'percent'). */
  unit: string;
  /** The data points in the series. */
  points: MetricPoint[];
  /** How to aggregate points within time windows. */
  aggregation: 'sum' | 'avg' | 'max' | 'min' | 'count' | 'p99';
}

/** A dashboard panel containing one or more metric series. */
export interface DashboardPanel {
  /** Unique panel identifier. */
  id: string;
  /** Human-readable panel title. */
  title: string;
  /** Metric series displayed in this panel. */
  metrics: MetricSeries[];
  /** Visualization type for the panel. */
  visualization: 'line' | 'bar' | 'gauge' | 'table' | 'heatmap';
}

/** A complete dashboard with panels and configuration. */
export interface Dashboard {
  /** Dashboard configuration. */
  config: DashboardConfig;
  /** Panels in the dashboard. */
  panels: DashboardPanel[];
  /** Timestamp of the last data update (ms since epoch). */
  lastUpdated: number;
}

// ─── Constants ───────────────────────────────────────────────────────────────

/** Standard metrics tracked by the Kova protocol. */
export const STANDARD_METRICS: string[] = [
  'trust_resolutions_total',
  'enforcement_decisions_total',
  'covenant_evaluations_total',
  'attestation_verifications_total',
  'average_trust_score',
  'breach_count',
  'api_latency_ms',
  'active_agents',
  'certificate_count',
  'fee_revenue',
];

/** Default dashboard configuration values. */
const DEFAULT_CONFIG: DashboardConfig = {
  refreshIntervalMs: 30_000,
  retentionPeriodMs: 86_400_000 * 7, // 7 days
  maxDataPoints: 10_000,
};

// ─── Functions ───────────────────────────────────────────────────────────────

/**
 * Create a new empty dashboard with the given configuration.
 *
 * @param config - Optional partial configuration overrides.
 * @returns A new Dashboard with no panels.
 */
export function createDashboard(config?: Partial<DashboardConfig>): Dashboard {
  return {
    config: {
      refreshIntervalMs: config?.refreshIntervalMs ?? DEFAULT_CONFIG.refreshIntervalMs,
      retentionPeriodMs: config?.retentionPeriodMs ?? DEFAULT_CONFIG.retentionPeriodMs,
      maxDataPoints: config?.maxDataPoints ?? DEFAULT_CONFIG.maxDataPoints,
    },
    panels: [],
    lastUpdated: Date.now(),
  };
}

/**
 * Add a metric data point to a dashboard.
 *
 * If the target panel does not exist, it is created with a 'line' visualization.
 * If the metric series does not exist within the panel, it is created with 'count'
 * aggregation. Returns a new Dashboard object (does not mutate the original).
 *
 * @param dashboard - The dashboard to add the metric to.
 * @param params - Metric parameters.
 * @returns A new Dashboard with the data point added.
 */
export function addMetric(
  dashboard: Dashboard,
  params: {
    panel: string;
    metric: string;
    value: number;
    labels?: Record<string, string>;
    unit?: string;
  },
): Dashboard {
  const now = Date.now();
  const point: MetricPoint = {
    timestamp: now,
    value: params.value,
    labels: params.labels ?? {},
  };

  // Deep clone panels
  const panels = dashboard.panels.map((p) => ({
    ...p,
    metrics: p.metrics.map((m) => ({
      ...m,
      points: [...m.points],
    })),
  }));

  // Find or create the panel
  let panel = panels.find((p) => p.id === params.panel);
  if (!panel) {
    panel = {
      id: params.panel,
      title: params.panel,
      metrics: [],
      visualization: 'line',
    };
    panels.push(panel);
  }

  // Find or create the metric series
  let series = panel.metrics.find((m) => m.name === params.metric);
  if (!series) {
    series = {
      name: params.metric,
      unit: params.unit ?? 'count',
      points: [],
      aggregation: 'count',
    };
    panel.metrics.push(series);
  }

  // Add the point and enforce maxDataPoints
  series.points.push(point);
  if (series.points.length > dashboard.config.maxDataPoints) {
    series.points = series.points.slice(
      series.points.length - dashboard.config.maxDataPoints,
    );
  }

  return {
    config: { ...dashboard.config },
    panels,
    lastUpdated: now,
  };
}

/**
 * Create a pre-built standard dashboard with panels for the Kova protocol.
 *
 * Includes four panels:
 * 1. "Trust Overview" -- trust score gauge, resolutions line chart
 * 2. "Enforcement" -- decisions bar chart, breach count
 * 3. "Performance" -- latency line chart, throughput
 * 4. "Business" -- revenue line chart, active agents gauge
 *
 * @returns A Dashboard with standard panels and empty metric series.
 */
export function createStandardDashboard(): Dashboard {
  const dashboard = createDashboard();

  dashboard.panels = [
    {
      id: 'trust-overview',
      title: 'Trust Overview',
      metrics: [
        { name: 'average_trust_score', unit: 'score', points: [], aggregation: 'avg' },
        { name: 'trust_resolutions_total', unit: 'count', points: [], aggregation: 'sum' },
      ],
      visualization: 'gauge',
    },
    {
      id: 'enforcement',
      title: 'Enforcement',
      metrics: [
        { name: 'enforcement_decisions_total', unit: 'count', points: [], aggregation: 'sum' },
        { name: 'breach_count', unit: 'count', points: [], aggregation: 'sum' },
      ],
      visualization: 'bar',
    },
    {
      id: 'performance',
      title: 'Performance',
      metrics: [
        { name: 'api_latency_ms', unit: 'ms', points: [], aggregation: 'p99' },
        { name: 'covenant_evaluations_total', unit: 'count', points: [], aggregation: 'sum' },
        { name: 'attestation_verifications_total', unit: 'count', points: [], aggregation: 'sum' },
      ],
      visualization: 'line',
    },
    {
      id: 'business',
      title: 'Business',
      metrics: [
        { name: 'fee_revenue', unit: 'usd', points: [], aggregation: 'sum' },
        { name: 'active_agents', unit: 'count', points: [], aggregation: 'max' },
        { name: 'certificate_count', unit: 'count', points: [], aggregation: 'max' },
      ],
      visualization: 'line',
    },
  ];

  return dashboard;
}

/**
 * Aggregate data points within time windows based on the series' aggregation type.
 *
 * Groups points into buckets of `windowMs` duration and applies the series'
 * aggregation function to each bucket. Returns one aggregated point per bucket.
 *
 * @param series - The metric series to aggregate.
 * @param windowMs - The time window size in milliseconds.
 * @returns An array of aggregated MetricPoints, one per window.
 */
export function aggregateMetric(series: MetricSeries, windowMs: number): MetricPoint[] {
  if (series.points.length === 0 || windowMs <= 0) {
    return [];
  }

  // Group points by time window
  const buckets = new Map<number, MetricPoint[]>();

  for (const point of series.points) {
    const bucketStart = Math.floor(point.timestamp / windowMs) * windowMs;
    let bucket = buckets.get(bucketStart);
    if (!bucket) {
      bucket = [];
      buckets.set(bucketStart, bucket);
    }
    bucket.push(point);
  }

  // Aggregate each bucket
  const result: MetricPoint[] = [];
  const sortedKeys = Array.from(buckets.keys()).sort((a, b) => a - b);

  for (const bucketStart of sortedKeys) {
    const points = buckets.get(bucketStart)!;
    const values = points.map((p) => p.value);
    let aggregatedValue: number;

    switch (series.aggregation) {
      case 'sum':
        aggregatedValue = values.reduce((a, b) => a + b, 0);
        break;
      case 'avg':
        aggregatedValue = values.reduce((a, b) => a + b, 0) / values.length;
        break;
      case 'max':
        aggregatedValue = Math.max(...values);
        break;
      case 'min':
        aggregatedValue = Math.min(...values);
        break;
      case 'count':
        aggregatedValue = values.length;
        break;
      case 'p99': {
        const sorted = [...values].sort((a, b) => a - b);
        const index = Math.ceil(sorted.length * 0.99) - 1;
        aggregatedValue = sorted[Math.max(0, index)]!;
        break;
      }
      default:
        aggregatedValue = values.reduce((a, b) => a + b, 0);
    }

    result.push({
      timestamp: bucketStart,
      value: aggregatedValue,
      labels: {},
    });
  }

  return result;
}

/**
 * Remove data points older than the dashboard's retention period.
 *
 * Returns a new Dashboard with old data points pruned from all metric series.
 * Does not mutate the original dashboard.
 *
 * @param dashboard - The dashboard to prune.
 * @returns A new Dashboard with old data removed.
 */
export function pruneOldData(dashboard: Dashboard): Dashboard {
  const cutoff = Date.now() - dashboard.config.retentionPeriodMs;

  const panels = dashboard.panels.map((panel) => ({
    ...panel,
    metrics: panel.metrics.map((series) => ({
      ...series,
      points: series.points.filter((p) => p.timestamp >= cutoff),
    })),
  }));

  return {
    config: { ...dashboard.config },
    panels,
    lastUpdated: dashboard.lastUpdated,
  };
}
