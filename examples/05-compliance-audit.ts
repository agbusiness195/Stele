/**
 * Grith Compliance Audit Example
 *
 * Shows how to run a compliance audit using the certification system
 * and generate actionable findings for MCP servers.
 *
 * Run: npx tsx examples/05-compliance-audit.ts
 */

import {
  createServerProfile,
  evaluateServer,
  generateTrustReport,
  renewCertification,
} from '../packages/mcp-server/src/certification';
import type { CertificationCriteria } from '../packages/mcp-server/src/certification';

function main() {
  console.log('========================================');
  console.log('  Grith Compliance Audit Example');
  console.log('========================================\n');

  // ── Step 1: Register servers ────────────────────────────────────────

  console.log('--- Step 1: Register Servers ---\n');

  const prodServer = createServerProfile({
    serverId: 'mcp:prod-analytics',
    serverName: 'Production Analytics Server',
    version: '2.1.0',
    capabilities: ['create_covenant', 'evaluate_action', 'verify_covenant'],
  });
  console.log(`  Registered: ${prodServer.serverName} (${prodServer.serverId})`);

  const devServer = createServerProfile({
    serverId: 'mcp:dev-sandbox',
    serverName: 'Development Sandbox',
    version: '0.9.0',
    capabilities: ['create_covenant', 'parse_ccl'],
  });
  console.log(`  Registered: ${devServer.serverName} (${devServer.serverId})`);

  // ── Step 2: Run certifications ──────────────────────────────────────

  console.log('\n--- Step 2: Run Certifications ---\n');

  const prodCriteria: CertificationCriteria = {
    covenantDefined: true,
    identityVerified: true,
    attestationEnabled: true,
    enforcementMode: 'enforce',
    uptimePercentage: 99.95,
    responseTimeP95Ms: 85,
    securityAuditPassed: true,
    documentationComplete: true,
  };

  const prodCert = evaluateServer(prodServer, prodCriteria);
  console.log(`  ${prodCert.profile.serverName}: ${prodCert.badge.toUpperCase()} (${prodCert.score}/100)`);

  const devCriteria: CertificationCriteria = {
    covenantDefined: true,
    identityVerified: false,
    attestationEnabled: false,
    enforcementMode: 'audit',
    uptimePercentage: 97.5,
    responseTimeP95Ms: 350,
    securityAuditPassed: false,
    documentationComplete: false,
  };

  const devCert = evaluateServer(devServer, devCriteria);
  console.log(`  ${devCert.profile.serverName}: ${devCert.badge.toUpperCase()} (${devCert.score}/100)`);

  // ── Step 3: Trust report ────────────────────────────────────────────

  console.log('\n--- Step 3: Trust Report ---\n');

  const report = generateTrustReport([prodCert, devCert]);
  console.log(`  Total servers:     ${report.totalServers}`);
  console.log(`  Certified servers: ${report.certifiedServers}`);
  console.log(`  Average score:     ${report.averageScore}`);
  console.log(`  Badge distribution:`);
  for (const [badge, count] of Object.entries(report.badgeDistribution)) {
    if (count > 0) console.log(`    ${badge}: ${count}`);
  }

  console.log('\n  Recommendations:');
  for (const rec of report.recommendations) {
    console.log(`    - ${rec}`);
  }

  // ── Step 4: Renew after improvements ────────────────────────────────

  console.log('\n--- Step 4: Renew After Improvements ---\n');

  const improvedCriteria: CertificationCriteria = {
    ...devCriteria,
    identityVerified: true,
    attestationEnabled: true,
    enforcementMode: 'enforce',
  };

  const renewed = renewCertification(devCert, improvedCriteria);
  console.log(`  ${renewed.profile.serverName}: ${renewed.badge.toUpperCase()} (${renewed.score}/100)`);
  console.log(`  Improved from ${devCert.badge} to ${renewed.badge}`);

  console.log('\n========================================');
  console.log('  Example complete!');
  console.log('========================================');
}

main();
