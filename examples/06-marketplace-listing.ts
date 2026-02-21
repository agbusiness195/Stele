/**
 * Grith Marketplace Example
 *
 * Shows agent discovery and trust-gated marketplace interactions.
 * Agents are listed, searched, and evaluated for marketplace access.
 *
 * Run: npx tsx examples/06-marketplace-listing.ts
 */

import {
  createTrustGate,
  evaluateAccess,
  calculateRevenueLift,
} from '../packages/sdk/src/trust-gate';
import {
  createServerProfile,
  evaluateServer,
  generateTrustReport,
} from '../packages/mcp-server/src/certification';
import type { CertificationCriteria } from '../packages/mcp-server/src/certification';

// ── Simulated agent registry ──────────────────────────────────────────────

interface MarketplaceAgent {
  id: string;
  name: string;
  description: string;
  trustScore: number;
  tags: string[];
}

const AGENTS: MarketplaceAgent[] = [
  { id: 'agent:code-review', name: 'Code Review Agent', description: 'Automated PR review', trustScore: 0.92, tags: ['code', 'review', 'security'] },
  { id: 'agent:data-etl', name: 'Data ETL Agent', description: 'Data pipeline orchestration', trustScore: 0.85, tags: ['data', 'etl', 'pipeline'] },
  { id: 'agent:chatbot', name: 'Customer Support Bot', description: 'Natural language support', trustScore: 0.6, tags: ['chat', 'support', 'nlp'] },
  { id: 'agent:scraper', name: 'Web Scraper', description: 'Web data extraction', trustScore: 0.35, tags: ['scraping', 'data'] },
];

function main() {
  console.log('========================================');
  console.log('  Grith Marketplace Example');
  console.log('========================================\n');

  // ── Step 1: List available agents ────────────────────────────────────

  console.log('--- Step 1: Marketplace Listing ---\n');

  for (const agent of AGENTS) {
    console.log(`  ${agent.name} (${agent.id})`);
    console.log(`    ${agent.description}`);
    console.log(`    Trust: ${agent.trustScore} | Tags: ${agent.tags.join(', ')}\n`);
  }

  // ── Step 2: Search by tag ───────────────────────────────────────────

  console.log('--- Step 2: Search by Tag "data" ---\n');

  const dataAgents = AGENTS.filter((a) => a.tags.includes('data'));
  for (const agent of dataAgents) {
    console.log(`  ${agent.name} (trust: ${agent.trustScore})`);
  }

  // ── Step 3: Trust-gated access ──────────────────────────────────────

  console.log('\n--- Step 3: Trust-Gated Marketplace Access ---\n');

  const gate = createTrustGate({ minimumTrustScore: 0.5, premiumThreshold: 0.9 });

  for (const agent of AGENTS) {
    const decision = evaluateAccess(gate, {
      agentId: agent.id,
      trustScore: agent.trustScore,
    });
    const tier = decision.accessLevel.toUpperCase().padEnd(8);
    console.log(`  [${tier}] ${agent.name} (score: ${agent.trustScore})`);
  }

  // ── Step 4: Revenue projection ──────────────────────────────────────

  console.log('\n--- Step 4: Revenue Projection ---\n');

  const revenue = calculateRevenueLift({
    totalAgents: 1000,
    grithAdoptionRate: 0.6,
    premiumRate: 0.3,
    premiumPriceMultiplier: 5,
  });

  console.log(`  Total agents:    1000`);
  console.log(`  Grith adoption:   60%`);
  console.log(`  Total revenue:   $${revenue.totalRevenue.toFixed(0)}`);
  console.log(`  Grith revenue:    $${revenue.grithRevenue.toFixed(0)}`);
  console.log(`  Revenue lift:    ${revenue.liftPercentage.toFixed(1)}%`);

  console.log('\n========================================');
  console.log('  Example complete!');
  console.log('========================================');
}

main();
