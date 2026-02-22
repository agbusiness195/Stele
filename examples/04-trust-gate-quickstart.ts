/**
 * Nobulex Trust-Gated Access Quickstart
 *
 * Shows how to gate API access based on trust scores.
 * Agents with higher trust scores get better access tiers.
 *
 * Run: npx tsx examples/04-trust-gate-quickstart.ts
 */

import {
  createTrustGate,
  evaluateAccess,
} from '../packages/sdk/src/trust-gate';

function main() {
  console.log('========================================');
  console.log('  Nobulex Trust-Gated Access Quickstart');
  console.log('========================================\n');

  // ── Step 1: Create a trust gate with default thresholds ─────────────
  // minimumTrustScore: 0.5, premiumThreshold: 0.9, gracePeriodMs: 24h

  const gate = createTrustGate();
  console.log('--- Step 1: Trust Gate Created ---');
  console.log('  Minimum trust score:', gate.minimumTrustScore);
  console.log('  Premium threshold:  ', gate.premiumThreshold);
  console.log('  Grace period:       ', gate.gracePeriodMs / 3600000, 'hours\n');

  // ── Step 2: Evaluate agents at different trust levels ───────────────

  console.log('--- Step 2: Evaluate Agent Access ---\n');

  // High-trust agent gets premium access
  const premium = evaluateAccess(gate, {
    agentId: 'agent:data-pipeline-v3',
    trustScore: 0.95,
  });
  console.log(`  ${premium.agentId}`);
  console.log(`    Access: ${premium.accessLevel} | Rate limit: ${premium.rateLimit}/min`);
  console.log(`    Reason: ${premium.reason}\n`);

  // Medium-trust agent gets standard access
  const standard = evaluateAccess(gate, {
    agentId: 'agent:report-generator',
    trustScore: 0.75,
  });
  console.log(`  ${standard.agentId}`);
  console.log(`    Access: ${standard.accessLevel} | Rate limit: ${standard.rateLimit}/min`);
  console.log(`    Reason: ${standard.reason}\n`);

  // Low-trust agent gets denied
  const denied = evaluateAccess(gate, {
    agentId: 'agent:unknown-scraper',
    trustScore: 0.2,
  });
  console.log(`  ${denied.agentId}`);
  console.log(`    Access: ${denied.accessLevel} | Rate limit: ${denied.rateLimit}/min`);
  console.log(`    Reason: ${denied.reason}\n`);

  // ── Step 3: New agent with grace period ─────────────────────────────
  // New agents get basic access during the grace period even with low trust.

  console.log('--- Step 3: Grace Period for New Agents ---\n');

  const newAgent = evaluateAccess(gate, {
    agentId: 'agent:just-registered',
    trustScore: 0.3,
    registeredAt: Date.now() - 3600000, // Registered 1 hour ago
  });
  console.log(`  ${newAgent.agentId} (registered 1 hour ago)`);
  console.log(`    Access: ${newAgent.accessLevel} | Rate limit: ${newAgent.rateLimit}/min`);
  console.log(`    Reason: ${newAgent.reason}`);

  console.log('\n========================================');
  console.log('  Example complete!');
  console.log('========================================');
}

main();
