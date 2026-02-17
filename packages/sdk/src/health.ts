/**
 * Health check and readiness probe utilities for production deployments.
 *
 * Provides liveness, readiness, and deep-health checks that can be
 * wired into HTTP health endpoints, Kubernetes probes, or monitoring
 * systems.
 *
 * @packageDocumentation
 */

import type { CovenantStore } from '@stele/store';

// ─── Types ───────────────────────────────────────────────────────────────────

/** Status of an individual health check component. */
export type ComponentStatus = 'healthy' | 'degraded' | 'unhealthy';

/** Result of a single health check component. */
export interface ComponentCheck {
  /** Component name. */
  name: string;
  /** Current status. */
  status: ComponentStatus;
  /** Optional human-readable detail. */
  message?: string;
  /** Time taken to run this check in milliseconds. */
  latencyMs: number;
}

/** Aggregated health report. */
export interface HealthReport {
  /** Overall status (worst of all component statuses). */
  status: ComponentStatus;
  /** ISO 8601 timestamp of the check. */
  timestamp: string;
  /** Stele SDK version. */
  version: string;
  /** Uptime of the process in seconds. */
  uptimeSeconds: number;
  /** Individual component checks. */
  components: ComponentCheck[];
}

/** Configuration for the health checker. */
export interface HealthCheckConfig {
  /** The covenant store to check connectivity for. */
  store?: CovenantStore;
  /** Application version string. */
  version?: string;
  /** Latency threshold (ms) above which a store check is "degraded". */
  storeLatencyThresholdMs?: number;
  /** Custom check functions to run as part of the health report. */
  customChecks?: Array<{
    name: string;
    check: () => Promise<{ status: ComponentStatus; message?: string }>;
  }>;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const DEFAULT_VERSION = '0.2.1';
const DEFAULT_STORE_LATENCY_THRESHOLD_MS = 500;

// ─── Status helpers ──────────────────────────────────────────────────────────

const STATUS_PRIORITY: Record<ComponentStatus, number> = {
  healthy: 0,
  degraded: 1,
  unhealthy: 2,
};

function worstStatus(statuses: ComponentStatus[]): ComponentStatus {
  let worst: ComponentStatus = 'healthy';
  for (const s of statuses) {
    if (STATUS_PRIORITY[s] > STATUS_PRIORITY[worst]) {
      worst = s;
    }
  }
  return worst;
}

// ─── Health check functions ──────────────────────────────────────────────────

/**
 * Simple liveness check. Returns true if the process is running.
 * Wire this into a `/healthz` or Kubernetes liveness probe.
 */
export function liveness(): { alive: boolean } {
  return { alive: true };
}

/**
 * Readiness check. Verifies the store is accessible and responsive.
 * Wire this into a `/readyz` or Kubernetes readiness probe.
 *
 * @param store - The covenant store to check.
 * @returns An object with `ready` status and optional latency.
 */
export async function readiness(store: CovenantStore): Promise<{
  ready: boolean;
  latencyMs: number;
}> {
  const start = performance.now();
  try {
    await store.count();
    const latencyMs = Math.round(performance.now() - start);
    return { ready: true, latencyMs };
  } catch {
    const latencyMs = Math.round(performance.now() - start);
    return { ready: false, latencyMs };
  }
}

/**
 * Deep health check that runs all component checks and produces
 * an aggregated {@link HealthReport}.
 *
 * @param config - Health check configuration.
 * @returns A complete health report.
 *
 * @example
 * ```ts
 * import { deepHealth } from '@stele/sdk';
 *
 * const report = await deepHealth({ store, version: '1.0.0' });
 * if (report.status === 'unhealthy') {
 *   console.error('System unhealthy:', report.components);
 * }
 * ```
 */
export async function deepHealth(config: HealthCheckConfig = {}): Promise<HealthReport> {
  const version = config.version ?? DEFAULT_VERSION;
  const threshold = config.storeLatencyThresholdMs ?? DEFAULT_STORE_LATENCY_THRESHOLD_MS;
  const components: ComponentCheck[] = [];

  // Runtime check
  components.push({
    name: 'runtime',
    status: 'healthy',
    message: `Node.js ${process.version}`,
    latencyMs: 0,
  });

  // Memory check
  const memStart = performance.now();
  const mem = process.memoryUsage();
  const heapUsedMb = Math.round(mem.heapUsed / 1024 / 1024);
  const heapTotalMb = Math.round(mem.heapTotal / 1024 / 1024);
  const heapPercent = Math.round((mem.heapUsed / mem.heapTotal) * 100);
  const memStatus: ComponentStatus = heapPercent > 95 ? 'unhealthy' : heapPercent > 80 ? 'degraded' : 'healthy';
  components.push({
    name: 'memory',
    status: memStatus,
    message: `${heapUsedMb}/${heapTotalMb} MB (${heapPercent}%)`,
    latencyMs: Math.round(performance.now() - memStart),
  });

  // Store check
  if (config.store) {
    const storeStart = performance.now();
    try {
      const count = await config.store.count();
      const latencyMs = Math.round(performance.now() - storeStart);
      const storeStatus: ComponentStatus = latencyMs > threshold ? 'degraded' : 'healthy';
      components.push({
        name: 'store',
        status: storeStatus,
        message: `${count} documents, ${latencyMs}ms`,
        latencyMs,
      });
    } catch (err) {
      const latencyMs = Math.round(performance.now() - storeStart);
      components.push({
        name: 'store',
        status: 'unhealthy',
        message: err instanceof Error ? err.message : String(err),
        latencyMs,
      });
    }
  }

  // Custom checks
  if (config.customChecks) {
    for (const custom of config.customChecks) {
      const customStart = performance.now();
      try {
        const result = await custom.check();
        components.push({
          name: custom.name,
          status: result.status,
          message: result.message,
          latencyMs: Math.round(performance.now() - customStart),
        });
      } catch (err) {
        components.push({
          name: custom.name,
          status: 'unhealthy',
          message: err instanceof Error ? err.message : String(err),
          latencyMs: Math.round(performance.now() - customStart),
        });
      }
    }
  }

  return {
    status: worstStatus(components.map((c) => c.status)),
    timestamp: new Date().toISOString(),
    version,
    uptimeSeconds: Math.round(process.uptime()),
    components,
  };
}
