/**
 * API gateway for the Stele protocol.
 *
 * Drop-in middleware that requires covenants before granting API access.
 * Enforces identity verification, covenant presence, trust score minimums,
 * resource access control, and rate limiting.
 *
 * @packageDocumentation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

/** Configuration for the API gateway. */
export interface GatewayConfig {
  /** Whether a covenant is required for access. Default: true */
  requireCovenant: boolean;
  /** Whether identity verification is required. Default: true */
  requireIdentity: boolean;
  /** Minimum trust score required for access. Default: 0.0 (no minimum) */
  requireMinimumTrust: number;
  /** Whether to log all requests. Default: true */
  logAllRequests: boolean;
  /** Maximum requests per minute. Default: 60 */
  rateLimitPerMinute: number;
  /** Allowed resource patterns. Default: ['*'] (all) */
  allowedResources: string[];
  /** Blocked resource patterns. Default: [] */
  blockedResources: string[];
}

/** An incoming gateway request. */
export interface GatewayRequest {
  /** The requesting agent's identifier. */
  agentId: string;
  /** The target resource path. */
  resource: string;
  /** The requested action. */
  action: string;
  /** The agent's trust score, if available. */
  trustScore?: number;
  /** Whether the agent has an active covenant. */
  hasCovenant: boolean;
  /** Whether the agent has verified identity. */
  hasIdentity: boolean;
  /** Timestamp of the request. */
  timestamp: number;
}

/** The gateway's response to a request. */
export interface GatewayResponse {
  /** Whether the request was allowed. */
  allowed: boolean;
  /** Human-readable reason for the decision. */
  reason: string;
  /** Unique identifier for this request. */
  requestId: string;
  /** Processing latency in milliseconds. */
  latencyMs: number;
  /** List of rules that were evaluated. */
  appliedRules: string[];
}

/** Aggregated gateway metrics from response history. */
export interface GatewayMetrics {
  /** Total number of requests processed. */
  totalRequests: number;
  /** Number of requests that were allowed. */
  allowedRequests: number;
  /** Number of requests that were denied. */
  deniedRequests: number;
  /** Average processing latency in milliseconds. */
  averageLatencyMs: number;
  /** Count of denials grouped by reason. */
  topDenialReasons: Record<string, number>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

let _requestCounter = 0;

function generateRequestId(): string {
  _requestCounter += 1;
  return `gw-${Date.now()}-${_requestCounter}`;
}

// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Create a gateway configuration with sensible defaults.
 *
 * @param config - Optional partial configuration overrides.
 * @returns A complete GatewayConfig.
 */
export function createGateway(config?: Partial<GatewayConfig>): GatewayConfig {
  return {
    requireCovenant: config?.requireCovenant ?? true,
    requireIdentity: config?.requireIdentity ?? true,
    requireMinimumTrust: config?.requireMinimumTrust ?? 0.0,
    logAllRequests: config?.logAllRequests ?? true,
    rateLimitPerMinute: config?.rateLimitPerMinute ?? 60,
    allowedResources: config?.allowedResources ?? ['*'],
    blockedResources: config?.blockedResources ?? [],
  };
}

// ─── Resource Matching ───────────────────────────────────────────────────────

/**
 * Check whether a resource is allowed by the gateway configuration.
 *
 * Blocked resources take precedence over allowed resources. A wildcard
 * `'*'` in the allowed list permits all resources not explicitly blocked.
 *
 * @param gateway - The gateway configuration.
 * @param resource - The resource path to check.
 * @returns `true` if the resource is allowed, `false` otherwise.
 */
export function isResourceAllowed(gateway: GatewayConfig, resource: string): boolean {
  // Blocked takes precedence
  for (const blocked of gateway.blockedResources) {
    if (resource === blocked || resource.startsWith(blocked + '/')) {
      return false;
    }
  }

  // Check allowed
  if (gateway.allowedResources.includes('*')) {
    return true;
  }

  for (const allowed of gateway.allowedResources) {
    if (resource === allowed || resource.startsWith(allowed + '/')) {
      return true;
    }
  }

  return false;
}

// ─── Request Processing ──────────────────────────────────────────────────────

/**
 * Process a gateway request by checking all configured rules in order.
 *
 * Checks are applied in this order:
 * 1. Identity verification
 * 2. Covenant presence
 * 3. Trust score minimum
 * 4. Resource access control
 *
 * The first check that fails causes immediate denial. If all checks pass,
 * the request is allowed.
 *
 * @param gateway - The gateway configuration.
 * @param request - The incoming request to process.
 * @returns A GatewayResponse with the decision and metadata.
 */
export function processRequest(
  gateway: GatewayConfig,
  request: GatewayRequest,
): GatewayResponse {
  const appliedRules: string[] = [];
  const requestId = generateRequestId();
  const now = Date.now();

  // 1. Identity check
  if (gateway.requireIdentity) {
    appliedRules.push('identity-required');
    if (!request.hasIdentity) {
      return {
        allowed: false,
        reason: 'Identity verification required but not provided',
        requestId,
        latencyMs: now - request.timestamp,
        appliedRules,
      };
    }
  }

  // 2. Covenant check
  if (gateway.requireCovenant) {
    appliedRules.push('covenant-required');
    if (!request.hasCovenant) {
      return {
        allowed: false,
        reason: 'Active covenant required but not provided',
        requestId,
        latencyMs: now - request.timestamp,
        appliedRules,
      };
    }
  }

  // 3. Trust score check
  if (gateway.requireMinimumTrust > 0) {
    appliedRules.push('trust-score-minimum');
    const trustScore = request.trustScore ?? 0;
    if (trustScore < gateway.requireMinimumTrust) {
      return {
        allowed: false,
        reason: `Trust score ${trustScore} below minimum ${gateway.requireMinimumTrust}`,
        requestId,
        latencyMs: now - request.timestamp,
        appliedRules,
      };
    }
  }

  // 4. Resource access check
  appliedRules.push('resource-access');
  if (!isResourceAllowed(gateway, request.resource)) {
    return {
      allowed: false,
      reason: `Resource ${request.resource} is not allowed`,
      requestId,
      latencyMs: now - request.timestamp,
      appliedRules,
    };
  }

  // All checks passed
  return {
    allowed: true,
    reason: 'All gateway checks passed',
    requestId,
    latencyMs: now - request.timestamp,
    appliedRules,
  };
}

// ─── Metrics ─────────────────────────────────────────────────────────────────

/**
 * Aggregate metrics from a collection of gateway responses.
 *
 * @param responses - Array of gateway responses to aggregate.
 * @returns A GatewayMetrics summary.
 */
export function aggregateMetrics(responses: GatewayResponse[]): GatewayMetrics {
  const totalRequests = responses.length;
  const allowedRequests = responses.filter((r) => r.allowed).length;
  const deniedRequests = totalRequests - allowedRequests;

  const totalLatency = responses.reduce((sum, r) => sum + r.latencyMs, 0);
  const averageLatencyMs = totalRequests === 0 ? 0 : totalLatency / totalRequests;

  const topDenialReasons: Record<string, number> = {};
  for (const response of responses) {
    if (!response.allowed) {
      topDenialReasons[response.reason] = (topDenialReasons[response.reason] ?? 0) + 1;
    }
  }

  return {
    totalRequests,
    allowedRequests,
    deniedRequests,
    averageLatencyMs,
    topDenialReasons,
  };
}
