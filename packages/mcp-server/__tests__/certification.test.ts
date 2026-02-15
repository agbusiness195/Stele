/**
 * Tests for MCP Server Certification system.
 *
 * Covers server profile creation, scoring, badge assignment,
 * trust report generation, and certification renewal.
 */
import { describe, it, expect } from 'vitest';
import {
  createServerProfile,
  evaluateServer,
  generateTrustReport,
  renewCertification,
} from '../src/certification';
import type {
  BadgeLevel,
  MCPServerProfile,
  CertificationCriteria,
  ServerCertification,
} from '../src/certification';

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Create a full-score criteria object (all checks passing, best values). */
function perfectCriteria(): CertificationCriteria {
  return {
    covenantDefined: true,
    identityVerified: true,
    attestationEnabled: true,
    enforcementMode: 'enforce',
    uptimePercentage: 99.99,
    responseTimeP95Ms: 50,
    securityAuditPassed: true,
    documentationComplete: true,
  };
}

/** Create a minimal-score criteria object (all checks failing). */
function minimalCriteria(): CertificationCriteria {
  return {
    covenantDefined: false,
    identityVerified: false,
    attestationEnabled: false,
    enforcementMode: 'none',
    uptimePercentage: 90,
    responseTimeP95Ms: 1000,
    securityAuditPassed: false,
    documentationComplete: false,
  };
}

/** Create a test server profile. */
function testProfile(overrides?: Partial<MCPServerProfile>): MCPServerProfile {
  return createServerProfile({
    serverId: overrides?.serverId ?? 'mcp:test-server',
    serverName: overrides?.serverName ?? 'Test Server',
    version: overrides?.version ?? '1.0.0',
    capabilities: overrides?.capabilities ?? ['create_covenant', 'verify_covenant'],
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// createServerProfile
// ═══════════════════════════════════════════════════════════════════════════

describe('createServerProfile', () => {
  it('creates a profile with the given parameters', () => {
    const profile = createServerProfile({
      serverId: 'mcp:analytics',
      serverName: 'Analytics Server',
      version: '2.0.0',
      capabilities: ['parse_ccl', 'evaluate_action'],
    });

    expect(profile.serverId).toBe('mcp:analytics');
    expect(profile.serverName).toBe('Analytics Server');
    expect(profile.version).toBe('2.0.0');
    expect(profile.capabilities).toEqual(['parse_ccl', 'evaluate_action']);
  });

  it('sets registeredAt and lastAuditedAt to current time', () => {
    const before = Date.now();
    const profile = createServerProfile({
      serverId: 'mcp:test',
      serverName: 'Test',
      version: '1.0.0',
      capabilities: [],
    });
    const after = Date.now();

    expect(profile.registeredAt).toBeGreaterThanOrEqual(before);
    expect(profile.registeredAt).toBeLessThanOrEqual(after);
    expect(profile.lastAuditedAt).toBeGreaterThanOrEqual(before);
    expect(profile.lastAuditedAt).toBeLessThanOrEqual(after);
  });

  it('creates a defensive copy of capabilities', () => {
    const caps = ['a', 'b'];
    const profile = createServerProfile({
      serverId: 'mcp:test',
      serverName: 'Test',
      version: '1.0.0',
      capabilities: caps,
    });
    caps.push('c');
    expect(profile.capabilities).toEqual(['a', 'b']);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evaluateServer -- scoring
// ═══════════════════════════════════════════════════════════════════════════

describe('evaluateServer', () => {
  describe('scoring', () => {
    it('awards 100 for perfect criteria', () => {
      const cert = evaluateServer(testProfile(), perfectCriteria());
      expect(cert.score).toBe(100);
    });

    it('awards 0 for minimal criteria', () => {
      const cert = evaluateServer(testProfile(), minimalCriteria());
      expect(cert.score).toBe(0);
    });

    it('awards +20 for covenantDefined', () => {
      const base = minimalCriteria();
      const withCovenant = { ...base, covenantDefined: true };
      const baseCert = evaluateServer(testProfile(), base);
      const withCert = evaluateServer(testProfile(), withCovenant);
      expect(withCert.score - baseCert.score).toBe(20);
    });

    it('awards +15 for identityVerified', () => {
      const base = minimalCriteria();
      const with_ = { ...base, identityVerified: true };
      expect(evaluateServer(testProfile(), with_).score - evaluateServer(testProfile(), base).score).toBe(15);
    });

    it('awards +15 for attestationEnabled', () => {
      const base = minimalCriteria();
      const with_ = { ...base, attestationEnabled: true };
      expect(evaluateServer(testProfile(), with_).score - evaluateServer(testProfile(), base).score).toBe(15);
    });

    it('awards +20 for enforce mode, +10 for audit mode', () => {
      const base = minimalCriteria();
      const enforce = { ...base, enforcementMode: 'enforce' as const };
      const audit = { ...base, enforcementMode: 'audit' as const };
      expect(evaluateServer(testProfile(), enforce).score).toBe(20);
      expect(evaluateServer(testProfile(), audit).score).toBe(10);
    });

    it('awards +10 for uptime >= 99.9, +5 for >= 99', () => {
      const base = minimalCriteria();
      const high = { ...base, uptimePercentage: 99.95 };
      const mid = { ...base, uptimePercentage: 99.5 };
      const low = { ...base, uptimePercentage: 98 };
      expect(evaluateServer(testProfile(), high).score).toBe(10);
      expect(evaluateServer(testProfile(), mid).score).toBe(5);
      expect(evaluateServer(testProfile(), low).score).toBe(0);
    });

    it('awards +10 for responseTime <= 100ms, +5 for <= 500ms', () => {
      const base = minimalCriteria();
      const fast = { ...base, responseTimeP95Ms: 80 };
      const mid = { ...base, responseTimeP95Ms: 300 };
      const slow = { ...base, responseTimeP95Ms: 800 };
      expect(evaluateServer(testProfile(), fast).score).toBe(10);
      expect(evaluateServer(testProfile(), mid).score).toBe(5);
      expect(evaluateServer(testProfile(), slow).score).toBe(0);
    });

    it('awards +5 for securityAuditPassed', () => {
      const base = minimalCriteria();
      const with_ = { ...base, securityAuditPassed: true };
      expect(evaluateServer(testProfile(), with_).score).toBe(5);
    });

    it('awards +5 for documentationComplete', () => {
      const base = minimalCriteria();
      const with_ = { ...base, documentationComplete: true };
      expect(evaluateServer(testProfile(), with_).score).toBe(5);
    });
  });

  describe('badge assignment', () => {
    it('assigns platinum for score >= 90', () => {
      const cert = evaluateServer(testProfile(), perfectCriteria());
      expect(cert.badge).toBe('platinum');
      expect(cert.score).toBeGreaterThanOrEqual(90);
    });

    it('assigns gold for score >= 75', () => {
      // covenant(20) + identity(15) + attestation(15) + enforce(20) + uptime(5) = 75
      const criteria: CertificationCriteria = {
        covenantDefined: true,
        identityVerified: true,
        attestationEnabled: true,
        enforcementMode: 'enforce',
        uptimePercentage: 99.0,
        responseTimeP95Ms: 1000,
        securityAuditPassed: false,
        documentationComplete: false,
      };
      const cert = evaluateServer(testProfile(), criteria);
      expect(cert.score).toBe(75);
      expect(cert.badge).toBe('gold');
    });

    it('assigns silver for score >= 60', () => {
      // covenant(20) + identity(15) + attestation(15) + audit(10) = 60
      const criteria: CertificationCriteria = {
        covenantDefined: true,
        identityVerified: true,
        attestationEnabled: true,
        enforcementMode: 'audit',
        uptimePercentage: 90,
        responseTimeP95Ms: 1000,
        securityAuditPassed: false,
        documentationComplete: false,
      };
      const cert = evaluateServer(testProfile(), criteria);
      expect(cert.score).toBe(60);
      expect(cert.badge).toBe('silver');
    });

    it('assigns bronze for score >= 40', () => {
      // covenant(20) + enforce(20) = 40
      const criteria: CertificationCriteria = {
        covenantDefined: true,
        identityVerified: false,
        attestationEnabled: false,
        enforcementMode: 'enforce',
        uptimePercentage: 90,
        responseTimeP95Ms: 1000,
        securityAuditPassed: false,
        documentationComplete: false,
      };
      const cert = evaluateServer(testProfile(), criteria);
      expect(cert.score).toBe(40);
      expect(cert.badge).toBe('bronze');
    });

    it('assigns none for score < 40', () => {
      const cert = evaluateServer(testProfile(), minimalCriteria());
      expect(cert.score).toBeLessThan(40);
      expect(cert.badge).toBe('none');
    });
  });

  describe('certification structure', () => {
    it('includes profile, criteria, badge, score, report, and timestamps', () => {
      const profile = testProfile();
      const criteria = perfectCriteria();
      const cert = evaluateServer(profile, criteria);

      expect(cert.profile).toBe(profile);
      expect(cert.criteria).toBe(criteria);
      expect(cert.badge).toBe('platinum');
      expect(cert.score).toBe(100);
      expect(typeof cert.report).toBe('string');
      expect(cert.report.length).toBeGreaterThan(0);
      expect(cert.certifiedAt).toBeGreaterThan(0);
      expect(cert.expiresAt).toBeGreaterThan(cert.certifiedAt);
    });

    it('sets expiresAt to certifiedAt + 90 days', () => {
      const cert = evaluateServer(testProfile(), perfectCriteria());
      const ninetyDaysMs = 90 * 24 * 60 * 60 * 1000;
      expect(cert.expiresAt - cert.certifiedAt).toBe(ninetyDaysMs);
    });

    it('generates a human-readable report', () => {
      const cert = evaluateServer(testProfile(), perfectCriteria());
      expect(cert.report).toContain('Trust Report');
      expect(cert.report).toContain('PLATINUM');
      expect(cert.report).toContain('100/100');
      expect(cert.report).toContain('PASS');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// generateTrustReport
// ═══════════════════════════════════════════════════════════════════════════

describe('generateTrustReport', () => {
  it('handles empty certification list', () => {
    const report = generateTrustReport([]);
    expect(report.totalServers).toBe(0);
    expect(report.certifiedServers).toBe(0);
    expect(report.averageScore).toBe(0);
    expect(report.topServers).toEqual([]);
  });

  it('computes correct totals and averages', () => {
    const cert1 = evaluateServer(testProfile({ serverId: 'mcp:a' }), perfectCriteria());
    const cert2 = evaluateServer(testProfile({ serverId: 'mcp:b' }), minimalCriteria());

    const report = generateTrustReport([cert1, cert2]);
    expect(report.totalServers).toBe(2);
    expect(report.certifiedServers).toBe(1); // only cert1 has a non-none badge
    expect(report.averageScore).toBe(50); // (100 + 0) / 2
  });

  it('computes badge distribution', () => {
    const platinum = evaluateServer(testProfile({ serverId: 'mcp:a' }), perfectCriteria());
    const none = evaluateServer(testProfile({ serverId: 'mcp:b' }), minimalCriteria());

    const report = generateTrustReport([platinum, none]);
    expect(report.badgeDistribution.platinum).toBe(1);
    expect(report.badgeDistribution.none).toBe(1);
    expect(report.badgeDistribution.gold).toBe(0);
    expect(report.badgeDistribution.silver).toBe(0);
    expect(report.badgeDistribution.bronze).toBe(0);
  });

  it('sorts top servers by score descending', () => {
    const cert1 = evaluateServer(testProfile({ serverId: 'mcp:low' }), minimalCriteria());
    const cert2 = evaluateServer(testProfile({ serverId: 'mcp:high' }), perfectCriteria());

    const report = generateTrustReport([cert1, cert2]);
    expect(report.topServers[0]!.serverId).toBe('mcp:high');
    expect(report.topServers[1]!.serverId).toBe('mcp:low');
  });

  it('limits top servers to 10', () => {
    const certs: ServerCertification[] = [];
    for (let i = 0; i < 15; i++) {
      certs.push(evaluateServer(testProfile({ serverId: `mcp:server-${i}` }), perfectCriteria()));
    }
    const report = generateTrustReport(certs);
    expect(report.topServers).toHaveLength(10);
  });

  it('generates recommendations for servers with no badge', () => {
    const none = evaluateServer(testProfile({ serverId: 'mcp:bad' }), minimalCriteria());
    const report = generateTrustReport([none]);
    expect(report.recommendations.length).toBeGreaterThan(0);
    expect(report.recommendations.some((r) => r.includes('no badge'))).toBe(true);
  });

  it('generates recommendations for enforcement disabled', () => {
    const criteria = { ...perfectCriteria(), enforcementMode: 'none' as const };
    const cert = evaluateServer(testProfile(), criteria);
    const report = generateTrustReport([cert]);
    expect(report.recommendations.some((r) => r.includes('enforcement disabled'))).toBe(true);
  });

  it('generates recommendations for missing attestation', () => {
    const criteria = { ...perfectCriteria(), attestationEnabled: false };
    const cert = evaluateServer(testProfile(), criteria);
    const report = generateTrustReport([cert]);
    expect(report.recommendations.some((r) => r.includes('attestation'))).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// renewCertification
// ═══════════════════════════════════════════════════════════════════════════

describe('renewCertification', () => {
  it('re-evaluates with new criteria', () => {
    const cert = evaluateServer(testProfile(), minimalCriteria());
    expect(cert.badge).toBe('none');

    const renewed = renewCertification(cert, perfectCriteria());
    expect(renewed.badge).toBe('platinum');
    expect(renewed.score).toBe(100);
  });

  it('updates timestamps on renewal', () => {
    const cert = evaluateServer(testProfile(), perfectCriteria());
    const renewed = renewCertification(cert, perfectCriteria());

    expect(renewed.certifiedAt).toBeGreaterThanOrEqual(cert.certifiedAt);
    expect(renewed.profile.lastAuditedAt).toBeGreaterThanOrEqual(cert.profile.lastAuditedAt);
  });

  it('preserves server profile identity', () => {
    const profile = testProfile({ serverId: 'mcp:my-server', serverName: 'My Server' });
    const cert = evaluateServer(profile, minimalCriteria());
    const renewed = renewCertification(cert, perfectCriteria());

    expect(renewed.profile.serverId).toBe('mcp:my-server');
    expect(renewed.profile.serverName).toBe('My Server');
  });
});
