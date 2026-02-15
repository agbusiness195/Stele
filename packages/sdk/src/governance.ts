/**
 * Internal agent governance for organizations running multiple agents.
 *
 * Provides policy management, agent health tracking, compliance monitoring,
 * quarantine capabilities, and dashboard views for multi-agent organizations.
 *
 * @packageDocumentation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

/** Governance policy for an organization's agent fleet. */
export interface GovernancePolicy {
  /** Unique identifier for the organization. */
  organizationId: string;
  /** Maximum number of agents allowed. */
  maxAgents: number;
  /** CCL rules that all agents must follow. */
  globalConstraints: string[];
  /** Level of monitoring detail. */
  monitoringLevel: 'basic' | 'standard' | 'comprehensive';
  /** Notification recipients for alerts. */
  alertRecipients: string[];
  /** Whether automatic remediation is enabled. */
  autoRemediationEnabled: boolean;
}

/** Status of a single agent within the organization. */
export interface AgentStatus {
  /** Unique identifier for the agent. */
  agentId: string;
  /** Whether the agent is considered healthy. */
  healthy: boolean;
  /** Timestamp of the agent's last check-in. */
  lastCheckIn: number;
  /** Compliance score (0-1). */
  complianceScore: number;
  /** Total number of violations recorded. */
  violations: number;
  /** Whether the agent is currently quarantined. */
  quarantined: boolean;
}

/** Aggregated governance dashboard for an organization. */
export interface GovernanceDashboard {
  /** The organization's governance policy. */
  policy: GovernancePolicy;
  /** Status of all registered agents. */
  agents: AgentStatus[];
  /** Overall health of the agent fleet (0-1). */
  overallHealth: number;
  /** Total active violations across all agents. */
  activeViolations: number;
  /** Number of agents currently quarantined. */
  quarantinedCount: number;
  /** Actionable recommendation based on fleet status. */
  recommendation: string;
}

// ─── Policy Factory ──────────────────────────────────────────────────────────

/**
 * Create a governance policy with sensible defaults.
 *
 * @param params - Required organization ID and optional overrides.
 * @returns A complete GovernancePolicy.
 */
export function createGovernancePolicy(params: {
  organizationId: string;
  maxAgents?: number;
  globalConstraints?: string[];
  monitoringLevel?: GovernancePolicy['monitoringLevel'];
}): GovernancePolicy {
  return {
    organizationId: params.organizationId,
    maxAgents: params.maxAgents ?? 100,
    globalConstraints: params.globalConstraints ?? [],
    monitoringLevel: params.monitoringLevel ?? 'standard',
    alertRecipients: [],
    autoRemediationEnabled: false,
  };
}

// ─── Agent Management ────────────────────────────────────────────────────────

/**
 * Register a new agent within a governance policy.
 *
 * The agent starts with full compliance, zero violations, and a healthy status.
 *
 * @param _policy - The governance policy (used for context; agent limits checked externally).
 * @param agentId - The unique identifier for the new agent.
 * @returns An initial AgentStatus for the registered agent.
 */
export function registerAgent(_policy: GovernancePolicy, agentId: string): AgentStatus {
  return {
    agentId,
    healthy: true,
    lastCheckIn: Date.now(),
    complianceScore: 1.0,
    violations: 0,
    quarantined: false,
  };
}

/**
 * Update an agent's status with new compliance data.
 *
 * If the compliance score drops below 0.3, the agent is automatically
 * quarantined. An agent is considered healthy if its compliance score
 * is at least 0.5 and it is not quarantined.
 *
 * @param status - The current agent status.
 * @param params - Updated values for compliance score and/or violations.
 * @returns A new AgentStatus reflecting the updates.
 */
export function updateAgentStatus(
  status: AgentStatus,
  params: {
    complianceScore?: number;
    violations?: number;
  },
): AgentStatus {
  const complianceScore = params.complianceScore ?? status.complianceScore;
  const violations = params.violations ?? status.violations;

  // Auto-quarantine if compliance is critically low
  const quarantined = complianceScore < 0.3 ? true : status.quarantined;

  // Health is determined by compliance threshold and quarantine status
  const healthy = complianceScore >= 0.5 && !quarantined;

  return {
    ...status,
    complianceScore,
    violations,
    quarantined,
    healthy,
    lastCheckIn: Date.now(),
  };
}

/**
 * Quarantine an agent, preventing it from operating.
 *
 * @param status - The current agent status.
 * @param _reason - Reason for quarantine (for logging/audit purposes).
 * @returns A new AgentStatus with the agent quarantined.
 */
export function quarantineAgent(status: AgentStatus, _reason: string): AgentStatus {
  return {
    ...status,
    quarantined: true,
    healthy: false,
  };
}

/**
 * Remove an agent from quarantine, allowing it to resume operations.
 *
 * Health status is recalculated based on the current compliance score.
 *
 * @param status - The current agent status.
 * @returns A new AgentStatus with quarantine removed.
 */
export function unquarantineAgent(status: AgentStatus): AgentStatus {
  return {
    ...status,
    quarantined: false,
    healthy: status.complianceScore >= 0.5,
  };
}

// ─── Dashboard ───────────────────────────────────────────────────────────────

/**
 * Build an aggregated governance dashboard from policy and agent statuses.
 *
 * @param policy - The organization's governance policy.
 * @param agents - Array of current agent statuses.
 * @returns A GovernanceDashboard with health metrics and recommendations.
 */
export function buildDashboard(
  policy: GovernancePolicy,
  agents: AgentStatus[],
): GovernanceDashboard {
  const quarantinedCount = agents.filter((a) => a.quarantined).length;
  const nonQuarantined = agents.filter((a) => !a.quarantined);

  const overallHealth =
    nonQuarantined.length === 0
      ? 0
      : nonQuarantined.reduce((sum, a) => sum + a.complianceScore, 0) /
        nonQuarantined.length;

  const activeViolations = agents.reduce((sum, a) => sum + a.violations, 0);

  // Generate recommendation based on worst issues
  let recommendation: string;
  if (quarantinedCount > agents.length * 0.5) {
    recommendation =
      'Critical: More than half of agents are quarantined. Investigate systemic compliance issues immediately.';
  } else if (quarantinedCount > 0) {
    recommendation = `Warning: ${quarantinedCount} agent(s) quarantined. Review quarantined agents and remediate violations.`;
  } else if (overallHealth < 0.5) {
    recommendation =
      'Warning: Overall fleet health is below 50%. Review agent compliance scores and address violations.';
  } else if (activeViolations > 0) {
    recommendation = `Advisory: ${activeViolations} active violation(s) detected. Monitor and address as needed.`;
  } else {
    recommendation = 'All agents are healthy and compliant. No action required.';
  }

  return {
    policy,
    agents,
    overallHealth,
    activeViolations,
    quarantinedCount,
    recommendation,
  };
}
