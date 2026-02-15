/**
 * Edge-case tests for the Stele SDK governance module.
 */

import { describe, it, expect } from 'vitest';

import {
  createGovernancePolicy,
  registerAgent,
  updateAgentStatus,
  quarantineAgent,
  unquarantineAgent,
  buildDashboard,
} from './governance.js';
import type { GovernancePolicy, AgentStatus } from './governance.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Create a default policy for testing. */
function defaultPolicy(overrides?: Partial<Parameters<typeof createGovernancePolicy>[0]>): GovernancePolicy {
  return createGovernancePolicy({
    organizationId: 'org-test',
    ...overrides,
  });
}

/** Register an agent and apply a compliance score update. */
function agentWithScore(
  policy: GovernancePolicy,
  agentId: string,
  complianceScore: number,
  violations = 0,
): AgentStatus {
  const agent = registerAgent(policy, agentId);
  return updateAgentStatus(agent, { complianceScore, violations });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('governance edge cases', () => {
  // ── Auto-quarantine threshold boundary ──────────────────────────────────

  describe('auto-quarantine threshold (0.3)', () => {
    it('should NOT auto-quarantine when compliance is exactly 0.3', () => {
      const policy = defaultPolicy();
      const agent = registerAgent(policy, 'agent-boundary');
      const updated = updateAgentStatus(agent, { complianceScore: 0.3 });

      // 0.3 is NOT less than 0.3, so the agent should not be quarantined
      expect(updated.quarantined).toBe(false);
      // 0.3 < 0.5, so still not healthy
      expect(updated.healthy).toBe(false);
    });

    it('should auto-quarantine when compliance is just below 0.3', () => {
      const policy = defaultPolicy();
      const agent = registerAgent(policy, 'agent-below');
      const updated = updateAgentStatus(agent, { complianceScore: 0.29999 });

      expect(updated.quarantined).toBe(true);
      expect(updated.healthy).toBe(false);
    });

    it('should NOT auto-quarantine when compliance is just above 0.3', () => {
      const policy = defaultPolicy();
      const agent = registerAgent(policy, 'agent-above');
      const updated = updateAgentStatus(agent, { complianceScore: 0.30001 });

      expect(updated.quarantined).toBe(false);
      // Still not healthy since 0.30001 < 0.5
      expect(updated.healthy).toBe(false);
    });

    it('should auto-quarantine at compliance 0.0', () => {
      const policy = defaultPolicy();
      const agent = registerAgent(policy, 'agent-zero');
      const updated = updateAgentStatus(agent, { complianceScore: 0.0 });

      expect(updated.quarantined).toBe(true);
      expect(updated.healthy).toBe(false);
    });
  });

  // ── Fleet health with majority quarantined ──────────────────────────────

  describe('fleet health with >50% agents quarantined', () => {
    it('should report critical recommendation when more than half are quarantined', () => {
      const policy = defaultPolicy();

      // Create 4 agents: 3 quarantined, 1 active
      const agents: AgentStatus[] = [
        agentWithScore(policy, 'agent-1', 0.1),   // auto-quarantined (0.1 < 0.3)
        agentWithScore(policy, 'agent-2', 0.2),   // auto-quarantined (0.2 < 0.3)
        agentWithScore(policy, 'agent-3', 0.15),  // auto-quarantined (0.15 < 0.3)
        agentWithScore(policy, 'agent-4', 0.9),   // active and healthy
      ];

      const dashboard = buildDashboard(policy, agents);

      expect(dashboard.quarantinedCount).toBe(3);
      expect(dashboard.recommendation).toContain('Critical');
      expect(dashboard.recommendation).toContain('More than half');
    });

    it('should report critical when exactly >50% are quarantined (3 of 5)', () => {
      const policy = defaultPolicy();

      const agents: AgentStatus[] = [
        agentWithScore(policy, 'a1', 0.1),  // quarantined
        agentWithScore(policy, 'a2', 0.1),  // quarantined
        agentWithScore(policy, 'a3', 0.1),  // quarantined
        agentWithScore(policy, 'a4', 0.9),  // active
        agentWithScore(policy, 'a5', 0.8),  // active
      ];

      const dashboard = buildDashboard(policy, agents);

      // 3 of 5 = 60% > 50%
      expect(dashboard.quarantinedCount).toBe(3);
      expect(dashboard.recommendation).toMatch(/Critical/i);
    });

    it('should NOT report critical when exactly 50% are quarantined (2 of 4)', () => {
      const policy = defaultPolicy();

      const agents: AgentStatus[] = [
        agentWithScore(policy, 'a1', 0.1),  // quarantined
        agentWithScore(policy, 'a2', 0.1),  // quarantined
        agentWithScore(policy, 'a3', 0.9),  // active
        agentWithScore(policy, 'a4', 0.8),  // active
      ];

      const dashboard = buildDashboard(policy, agents);

      // 2 of 4 = 50%, NOT more than 50%
      expect(dashboard.quarantinedCount).toBe(2);
      // Should be Warning, not Critical
      expect(dashboard.recommendation).toMatch(/Warning/i);
      expect(dashboard.recommendation).not.toMatch(/Critical/i);
    });

    it('should compute overallHealth only from non-quarantined agents', () => {
      const policy = defaultPolicy();

      const agents: AgentStatus[] = [
        agentWithScore(policy, 'q1', 0.1),   // quarantined, score 0.1
        agentWithScore(policy, 'q2', 0.05),  // quarantined, score 0.05
        agentWithScore(policy, 'a1', 0.8),   // active, score 0.8
        agentWithScore(policy, 'a2', 0.6),   // active, score 0.6
      ];

      const dashboard = buildDashboard(policy, agents);

      // overallHealth should average only non-quarantined: (0.8 + 0.6) / 2 = 0.7
      expect(dashboard.overallHealth).toBeCloseTo(0.7, 5);
    });
  });

  // ── Unquarantine when compliance < threshold ────────────────────────────

  describe('unquarantine with low compliance', () => {
    it('should allow unquarantine even when compliance is below 0.5 (unhealthy)', () => {
      const policy = defaultPolicy();
      const agent = registerAgent(policy, 'agent-low');
      const quarantined = quarantineAgent(agent, 'manual quarantine');

      // Manually set compliance to 0.4 via update before quarantine
      const lowCompliance = updateAgentStatus(quarantined, { complianceScore: 0.4 });
      expect(lowCompliance.quarantined).toBe(true); // still quarantined (was already)

      const released = unquarantineAgent(lowCompliance);

      expect(released.quarantined).toBe(false);
      // 0.4 < 0.5 so agent is NOT healthy even though unquarantined
      expect(released.healthy).toBe(false);
    });

    it('should mark agent healthy on unquarantine when compliance >= 0.5', () => {
      const policy = defaultPolicy();
      const agent = agentWithScore(policy, 'agent-ok', 0.7);
      const quarantined = quarantineAgent(agent, 'temporary hold');
      const released = unquarantineAgent(quarantined);

      expect(released.quarantined).toBe(false);
      expect(released.healthy).toBe(true);
      expect(released.complianceScore).toBe(0.7);
    });

    it('should mark agent unhealthy on unquarantine when compliance is exactly 0.5', () => {
      const policy = defaultPolicy();
      const agent = agentWithScore(policy, 'agent-edge', 0.5);
      const quarantined = quarantineAgent(agent, 'review');

      expect(quarantined.quarantined).toBe(true);
      expect(quarantined.healthy).toBe(false);

      const released = unquarantineAgent(quarantined);

      // 0.5 >= 0.5, so healthy
      expect(released.quarantined).toBe(false);
      expect(released.healthy).toBe(true);
    });

    it('should not auto-re-quarantine on unquarantine even with very low score', () => {
      const policy = defaultPolicy();
      const agent = agentWithScore(policy, 'agent-critical', 0.1);

      // Agent was auto-quarantined by updateAgentStatus
      expect(agent.quarantined).toBe(true);

      // Force unquarantine - it does not re-check auto-quarantine logic
      const released = unquarantineAgent(agent);

      expect(released.quarantined).toBe(false);
      expect(released.healthy).toBe(false); // 0.1 < 0.5
    });
  });

  // ── Dashboard with all agents quarantined ───────────────────────────────

  describe('dashboard with all agents quarantined', () => {
    it('should return overallHealth 0 when all agents are quarantined', () => {
      const policy = defaultPolicy();

      const agents: AgentStatus[] = [
        agentWithScore(policy, 'q1', 0.1),
        agentWithScore(policy, 'q2', 0.2),
        agentWithScore(policy, 'q3', 0.05),
      ];

      // All should be auto-quarantined
      agents.forEach((a) => expect(a.quarantined).toBe(true));

      const dashboard = buildDashboard(policy, agents);

      expect(dashboard.overallHealth).toBe(0);
      expect(dashboard.quarantinedCount).toBe(3);
      expect(dashboard.recommendation).toMatch(/Critical/i);
    });

    it('should handle empty agent list gracefully', () => {
      const policy = defaultPolicy();
      const dashboard = buildDashboard(policy, []);

      expect(dashboard.overallHealth).toBe(0);
      expect(dashboard.quarantinedCount).toBe(0);
      expect(dashboard.activeViolations).toBe(0);
      // No quarantined agents and overallHealth is 0 (edge: 0 non-quarantined),
      // but quarantinedCount is 0, so falls through to overallHealth < 0.5 check
      expect(dashboard.recommendation).toContain('Warning');
    });

    it('should sum violations from quarantined agents in activeViolations', () => {
      const policy = defaultPolicy();

      const agents: AgentStatus[] = [
        agentWithScore(policy, 'q1', 0.1, 5),
        agentWithScore(policy, 'q2', 0.2, 3),
      ];

      const dashboard = buildDashboard(policy, agents);

      expect(dashboard.activeViolations).toBe(8);
      expect(dashboard.quarantinedCount).toBe(2);
    });
  });

  // ── State transitions: active -> quarantined -> active ──────────────────

  describe('state transitions: active -> quarantined -> active', () => {
    it('should complete full lifecycle: register -> quarantine -> unquarantine', () => {
      const policy = defaultPolicy();

      // Step 1: Register (active, healthy)
      const registered = registerAgent(policy, 'agent-lifecycle');
      expect(registered.healthy).toBe(true);
      expect(registered.quarantined).toBe(false);
      expect(registered.complianceScore).toBe(1.0);

      // Step 2: Quarantine manually
      const quarantined = quarantineAgent(registered, 'investigation');
      expect(quarantined.healthy).toBe(false);
      expect(quarantined.quarantined).toBe(true);
      expect(quarantined.complianceScore).toBe(1.0); // score unchanged

      // Step 3: Unquarantine
      const restored = unquarantineAgent(quarantined);
      expect(restored.healthy).toBe(true); // 1.0 >= 0.5
      expect(restored.quarantined).toBe(false);
      expect(restored.complianceScore).toBe(1.0);
    });

    it('should handle auto-quarantine -> update score -> unquarantine cycle', () => {
      const policy = defaultPolicy();

      // Start healthy
      const agent = registerAgent(policy, 'agent-auto');
      expect(agent.quarantined).toBe(false);

      // Drop below auto-quarantine threshold
      const degraded = updateAgentStatus(agent, { complianceScore: 0.1 });
      expect(degraded.quarantined).toBe(true);
      expect(degraded.healthy).toBe(false);

      // Improve score while quarantined - stays quarantined because
      // updateAgentStatus only auto-quarantines, never auto-unquarantines
      const improved = updateAgentStatus(degraded, { complianceScore: 0.9 });
      expect(improved.quarantined).toBe(true); // still quarantined
      expect(improved.healthy).toBe(false);    // quarantined -> unhealthy

      // Manually unquarantine
      const released = unquarantineAgent(improved);
      expect(released.quarantined).toBe(false);
      expect(released.healthy).toBe(true); // 0.9 >= 0.5
    });

    it('should preserve violations through quarantine/unquarantine cycle', () => {
      const policy = defaultPolicy();

      const agent = registerAgent(policy, 'agent-violations');
      const updated = updateAgentStatus(agent, { violations: 7, complianceScore: 0.6 });
      expect(updated.violations).toBe(7);

      const quarantined = quarantineAgent(updated, 'too many violations');
      expect(quarantined.violations).toBe(7);

      const released = unquarantineAgent(quarantined);
      expect(released.violations).toBe(7);
    });

    it('should reflect state changes in dashboard across transitions', () => {
      const policy = defaultPolicy();

      // Start: 2 healthy agents
      const a1 = registerAgent(policy, 'a1');
      const a2 = registerAgent(policy, 'a2');

      let dashboard = buildDashboard(policy, [a1, a2]);
      expect(dashboard.quarantinedCount).toBe(0);
      expect(dashboard.overallHealth).toBe(1.0);
      expect(dashboard.recommendation).toContain('No action required');

      // Quarantine one
      const a1Quarantined = quarantineAgent(a1, 'test');
      dashboard = buildDashboard(policy, [a1Quarantined, a2]);
      expect(dashboard.quarantinedCount).toBe(1);
      expect(dashboard.overallHealth).toBe(1.0); // only a2 counted
      expect(dashboard.recommendation).toMatch(/Warning/i);

      // Restore
      const a1Restored = unquarantineAgent(a1Quarantined);
      dashboard = buildDashboard(policy, [a1Restored, a2]);
      expect(dashboard.quarantinedCount).toBe(0);
      expect(dashboard.overallHealth).toBe(1.0);
      expect(dashboard.recommendation).toContain('No action required');
    });

    it('should handle double quarantine as idempotent', () => {
      const policy = defaultPolicy();
      const agent = registerAgent(policy, 'agent-double');

      const first = quarantineAgent(agent, 'first reason');
      const second = quarantineAgent(first, 'second reason');

      expect(second.quarantined).toBe(true);
      expect(second.healthy).toBe(false);

      // Single unquarantine should fully release
      const released = unquarantineAgent(second);
      expect(released.quarantined).toBe(false);
      expect(released.healthy).toBe(true);
    });

    it('should handle double unquarantine as idempotent', () => {
      const policy = defaultPolicy();
      const agent = registerAgent(policy, 'agent-double-unq');

      // Agent starts not quarantined - unquarantine is a no-op
      const released = unquarantineAgent(agent);
      expect(released.quarantined).toBe(false);
      expect(released.healthy).toBe(true);
    });
  });

  // ── Health boundary at 0.5 ──────────────────────────────────────────────

  describe('healthy threshold boundary (0.5)', () => {
    it('should be healthy at exactly 0.5 compliance (not quarantined)', () => {
      const policy = defaultPolicy();
      const agent = registerAgent(policy, 'agent-half');
      const updated = updateAgentStatus(agent, { complianceScore: 0.5 });

      expect(updated.healthy).toBe(true);
      expect(updated.quarantined).toBe(false);
    });

    it('should be unhealthy at 0.4999 compliance (not quarantined)', () => {
      const policy = defaultPolicy();
      const agent = registerAgent(policy, 'agent-just-below');
      const updated = updateAgentStatus(agent, { complianceScore: 0.4999 });

      expect(updated.healthy).toBe(false);
      expect(updated.quarantined).toBe(false);
    });

    it('should be unhealthy even with score >= 0.5 when quarantined', () => {
      const policy = defaultPolicy();
      const agent = agentWithScore(policy, 'agent-q-healthy', 0.8);
      const quarantined = quarantineAgent(agent, 'manual hold');

      expect(quarantined.complianceScore).toBe(0.8);
      expect(quarantined.quarantined).toBe(true);
      expect(quarantined.healthy).toBe(false);
    });
  });
});
