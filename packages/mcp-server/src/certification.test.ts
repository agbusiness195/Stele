import { describe, it, expect } from 'vitest';
import {
  createServerProfile,
  evaluateServer,
  generateTrustReport,
  renewCertification,
} from './certification';
import type {
  MCPServerProfile,
  CertificationCriteria,
  ServerCertification,
  BadgeLevel,
} from './certification';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeProfile(overrides?: Partial<MCPServerProfile>): MCPServerProfile {
  return {
    serverId: 'srv-1',
    serverName: 'TestServer',
    version: '1.0.0',
    capabilities: ['tools', 'resources'],
    registeredAt: Date.now(),
    lastAuditedAt: Date.now(),
    ...overrides,
  };
}

function makeCriteria(overrides?: Partial<CertificationCriteria>): CertificationCriteria {
  return {
    covenantDefined: false,
    identityVerified: false,
    attestationEnabled: false,
    enforcementMode: 'none',
    uptimePercentage: 95,
    responseTimeP95Ms: 600,
    securityAuditPassed: false,
    documentationComplete: false,
    ...overrides,
  };
}

/** All criteria enabled: score = 100, badge = platinum */
function makePerfectCriteria(): CertificationCriteria {
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

function makeCert(
  badge: BadgeLevel,
  score: number,
  criteria?: Partial<CertificationCriteria>,
): ServerCertification {
  const profile = makeProfile({ serverId: `srv-${badge}-${score}` });
  const fullCriteria = makeCriteria(criteria);
  return {
    profile,
    criteria: fullCriteria,
    badge,
    score,
    report: '',
    certifiedAt: Date.now(),
    expiresAt: Date.now() + 90 * 24 * 60 * 60 * 1000,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('MCP Server Certification', () => {
  // ──────────────────────────────────────────
  // createServerProfile
  // ──────────────────────────────────────────
  describe('createServerProfile', () => {
    it('creates a profile with provided params', () => {
      const profile = createServerProfile({
        serverId: 'srv-abc',
        serverName: 'MyServer',
        version: '2.0.0',
        capabilities: ['tools'],
      });

      expect(profile.serverId).toBe('srv-abc');
      expect(profile.serverName).toBe('MyServer');
      expect(profile.version).toBe('2.0.0');
      expect(profile.capabilities).toEqual(['tools']);
    });

    it('sets registeredAt and lastAuditedAt to the same timestamp', () => {
      const profile = createServerProfile({
        serverId: 'srv-time',
        serverName: 'TimeServer',
        version: '1.0.0',
        capabilities: [],
      });

      expect(profile.registeredAt).toBe(profile.lastAuditedAt);
      expect(profile.registeredAt).toBeGreaterThan(0);
    });

    it('defensively copies capabilities array', () => {
      const caps = ['a', 'b'];
      const profile = createServerProfile({
        serverId: 'srv-copy',
        serverName: 'CopyServer',
        version: '1.0.0',
        capabilities: caps,
      });

      caps.push('c');
      expect(profile.capabilities).toEqual(['a', 'b']);
    });

    it('handles empty capabilities', () => {
      const profile = createServerProfile({
        serverId: 'srv-empty',
        serverName: 'EmptyServer',
        version: '0.0.1',
        capabilities: [],
      });

      expect(profile.capabilities).toEqual([]);
    });
  });

  // ──────────────────────────────────────────
  // Score computation and badge determination
  // ──────────────────────────────────────────
  describe('scoring', () => {
    it('all criteria disabled yields score 0 and badge none', () => {
      const cert = evaluateServer(makeProfile(), makeCriteria());
      expect(cert.score).toBe(0);
      expect(cert.badge).toBe('none');
    });

    it('all criteria enabled yields score 100 and badge platinum', () => {
      const cert = evaluateServer(makeProfile(), makePerfectCriteria());
      expect(cert.score).toBe(100);
      expect(cert.badge).toBe('platinum');
    });

    it('covenantDefined adds 20 points', () => {
      const cert = evaluateServer(
        makeProfile(),
        makeCriteria({ covenantDefined: true }),
      );
      expect(cert.score).toBe(20);
    });

    it('identityVerified adds 15 points', () => {
      const cert = evaluateServer(
        makeProfile(),
        makeCriteria({ identityVerified: true }),
      );
      expect(cert.score).toBe(15);
    });

    it('attestationEnabled adds 15 points', () => {
      const cert = evaluateServer(
        makeProfile(),
        makeCriteria({ attestationEnabled: true }),
      );
      expect(cert.score).toBe(15);
    });

    it('enforcement enforce adds 20, audit adds 10, none adds 0', () => {
      const enforce = evaluateServer(
        makeProfile(),
        makeCriteria({ enforcementMode: 'enforce' }),
      );
      expect(enforce.score).toBe(20);

      const audit = evaluateServer(
        makeProfile(),
        makeCriteria({ enforcementMode: 'audit' }),
      );
      expect(audit.score).toBe(10);

      const none = evaluateServer(
        makeProfile(),
        makeCriteria({ enforcementMode: 'none' }),
      );
      expect(none.score).toBe(0);
    });

    it('uptime >= 99.9 adds 10, >= 99 adds 5, below adds 0', () => {
      const high = evaluateServer(
        makeProfile(),
        makeCriteria({ uptimePercentage: 99.9 }),
      );
      expect(high.score).toBe(10);

      const mid = evaluateServer(
        makeProfile(),
        makeCriteria({ uptimePercentage: 99.5 }),
      );
      expect(mid.score).toBe(5);

      const exact99 = evaluateServer(
        makeProfile(),
        makeCriteria({ uptimePercentage: 99 }),
      );
      expect(exact99.score).toBe(5);

      const low = evaluateServer(
        makeProfile(),
        makeCriteria({ uptimePercentage: 98.9 }),
      );
      expect(low.score).toBe(0);
    });

    it('responseTimeP95Ms <= 100 adds 10, <= 500 adds 5, above adds 0', () => {
      const fast = evaluateServer(
        makeProfile(),
        makeCriteria({ responseTimeP95Ms: 50 }),
      );
      expect(fast.score).toBe(10);

      const exactFast = evaluateServer(
        makeProfile(),
        makeCriteria({ responseTimeP95Ms: 100 }),
      );
      expect(exactFast.score).toBe(10);

      const moderate = evaluateServer(
        makeProfile(),
        makeCriteria({ responseTimeP95Ms: 250 }),
      );
      expect(moderate.score).toBe(5);

      const exactModerate = evaluateServer(
        makeProfile(),
        makeCriteria({ responseTimeP95Ms: 500 }),
      );
      expect(exactModerate.score).toBe(5);

      const slow = evaluateServer(
        makeProfile(),
        makeCriteria({ responseTimeP95Ms: 501 }),
      );
      expect(slow.score).toBe(0);
    });

    it('securityAuditPassed adds 5', () => {
      const cert = evaluateServer(
        makeProfile(),
        makeCriteria({ securityAuditPassed: true }),
      );
      expect(cert.score).toBe(5);
    });

    it('documentationComplete adds 5', () => {
      const cert = evaluateServer(
        makeProfile(),
        makeCriteria({ documentationComplete: true }),
      );
      expect(cert.score).toBe(5);
    });
  });

  // ──────────────────────────────────────────
  // Badge thresholds
  // ──────────────────────────────────────────
  describe('badge thresholds', () => {
    it('score exactly 90 yields platinum', () => {
      // covenant(20) + identity(15) + attestation(15) + enforce(20) + uptime99.9(10) + fast(10)
      const cert = evaluateServer(
        makeProfile(),
        makeCriteria({
          covenantDefined: true,
          identityVerified: true,
          attestationEnabled: true,
          enforcementMode: 'enforce',
          uptimePercentage: 99.9,
          responseTimeP95Ms: 100,
        }),
      );
      expect(cert.score).toBe(90);
      expect(cert.badge).toBe('platinum');
    });

    it('score exactly 75 yields gold', () => {
      // covenant(20) + identity(15) + attestation(15) + enforce(20) + securityAudit(5)
      const cert = evaluateServer(
        makeProfile(),
        makeCriteria({
          covenantDefined: true,
          identityVerified: true,
          attestationEnabled: true,
          enforcementMode: 'enforce',
          securityAuditPassed: true,
        }),
      );
      expect(cert.score).toBe(75);
      expect(cert.badge).toBe('gold');
    });

    it('score exactly 60 yields silver', () => {
      // covenant(20) + identity(15) + attestation(15) + uptime99.9(10)
      const cert = evaluateServer(
        makeProfile(),
        makeCriteria({
          covenantDefined: true,
          identityVerified: true,
          attestationEnabled: true,
          uptimePercentage: 99.9,
        }),
      );
      expect(cert.score).toBe(60);
      expect(cert.badge).toBe('silver');
    });

    it('score exactly 40 yields bronze', () => {
      // covenant(20) + enforce(20)
      const cert = evaluateServer(
        makeProfile(),
        makeCriteria({
          covenantDefined: true,
          enforcementMode: 'enforce',
        }),
      );
      expect(cert.score).toBe(40);
      expect(cert.badge).toBe('bronze');
    });

    it('score 39 yields none', () => {
      // covenant(20) + identity(15) + docs(5) = 40... need less
      // covenant(20) + audit(10) + security(5) = 35
      const cert = evaluateServer(
        makeProfile(),
        makeCriteria({
          covenantDefined: true,
          enforcementMode: 'audit',
          securityAuditPassed: true,
        }),
      );
      expect(cert.score).toBe(35);
      expect(cert.badge).toBe('none');
    });
  });

  // ──────────────────────────────────────────
  // evaluateServer
  // ──────────────────────────────────────────
  describe('evaluateServer', () => {
    it('returns a valid certification with all fields', () => {
      const profile = makeProfile();
      const criteria = makePerfectCriteria();
      const cert = evaluateServer(profile, criteria);

      expect(cert.profile).toBe(profile);
      expect(cert.criteria).toBe(criteria);
      expect(cert.badge).toBe('platinum');
      expect(cert.score).toBe(100);
      expect(cert.report).toContain('Trust Report for TestServer');
      expect(cert.certifiedAt).toBeGreaterThan(0);
      expect(cert.expiresAt).toBeGreaterThan(cert.certifiedAt);
    });

    it('certification expires after 90 days', () => {
      const cert = evaluateServer(makeProfile(), makePerfectCriteria());
      const ninetyDaysMs = 90 * 24 * 60 * 60 * 1000;
      expect(cert.expiresAt - cert.certifiedAt).toBe(ninetyDaysMs);
    });

    it('report includes all criteria results', () => {
      const cert = evaluateServer(makeProfile(), makePerfectCriteria());
      expect(cert.report).toContain('Covenant Defined');
      expect(cert.report).toContain('Identity Verified');
      expect(cert.report).toContain('Attestation Enabled');
      expect(cert.report).toContain('Enforcement Mode');
      expect(cert.report).toContain('Uptime');
      expect(cert.report).toContain('Response Time');
      expect(cert.report).toContain('Security Audit');
      expect(cert.report).toContain('Documentation');
    });

    it('report includes badge and score', () => {
      const cert = evaluateServer(makeProfile(), makePerfectCriteria());
      expect(cert.report).toContain('PLATINUM');
      expect(cert.report).toContain('100/100');
    });

    it('report shows PASS/FAIL correctly', () => {
      const mixed = evaluateServer(
        makeProfile(),
        makeCriteria({
          covenantDefined: true,
          identityVerified: false,
          securityAuditPassed: true,
        }),
      );
      expect(mixed.report).toContain('Covenant Defined:      PASS (+20)');
      expect(mixed.report).toContain('Identity Verified:     FAIL (+0)');
      expect(mixed.report).toContain('Security Audit:        PASS (+5)');
    });
  });

  // ──────────────────────────────────────────
  // generateTrustReport
  // ──────────────────────────────────────────
  describe('generateTrustReport', () => {
    it('handles empty certifications array', () => {
      const report = generateTrustReport([]);
      expect(report.totalServers).toBe(0);
      expect(report.certifiedServers).toBe(0);
      expect(report.averageScore).toBe(0);
      expect(report.topServers).toEqual([]);
      expect(report.badgeDistribution).toEqual({
        none: 0,
        bronze: 0,
        silver: 0,
        gold: 0,
        platinum: 0,
      });
    });

    it('counts badge distribution correctly', () => {
      const certs = [
        makeCert('platinum', 95),
        makeCert('gold', 80),
        makeCert('gold', 78),
        makeCert('silver', 65),
        makeCert('none', 30),
      ];
      const report = generateTrustReport(certs);
      expect(report.badgeDistribution.platinum).toBe(1);
      expect(report.badgeDistribution.gold).toBe(2);
      expect(report.badgeDistribution.silver).toBe(1);
      expect(report.badgeDistribution.bronze).toBe(0);
      expect(report.badgeDistribution.none).toBe(1);
    });

    it('calculates average score correctly', () => {
      const certs = [
        makeCert('platinum', 100),
        makeCert('gold', 80),
        makeCert('silver', 60),
      ];
      const report = generateTrustReport(certs);
      expect(report.averageScore).toBe(80);
    });

    it('certified count excludes "none" badge servers', () => {
      const certs = [
        makeCert('platinum', 95),
        makeCert('none', 20),
        makeCert('bronze', 45),
        makeCert('none', 10),
      ];
      const report = generateTrustReport(certs);
      expect(report.totalServers).toBe(4);
      expect(report.certifiedServers).toBe(2);
    });

    it('top servers are sorted by score descending, limited to 10', () => {
      const certs = Array.from({ length: 15 }, (_, i) =>
        makeCert('bronze', 40 + i, { covenantDefined: true, enforcementMode: 'enforce' }),
      );
      const report = generateTrustReport(certs);
      expect(report.topServers.length).toBe(10);
      expect(report.topServers[0]!.score).toBeGreaterThanOrEqual(report.topServers[9]!.score);
    });

    it('generates recommendation for uncertified servers', () => {
      const certs = [makeCert('none', 20)];
      const report = generateTrustReport(certs);
      expect(report.recommendations.some((r) => r.includes('no badge'))).toBe(true);
    });

    it('generates recommendation for disabled enforcement', () => {
      const certs = [makeCert('bronze', 40, { enforcementMode: 'none' })];
      const report = generateTrustReport(certs);
      expect(report.recommendations.some((r) => r.includes('enforcement disabled'))).toBe(true);
    });

    it('generates recommendation for missing attestation', () => {
      const certs = [makeCert('bronze', 40, { attestationEnabled: false })];
      const report = generateTrustReport(certs);
      expect(report.recommendations.some((r) => r.includes('attestation'))).toBe(true);
    });

    it('generates recommendation for low uptime', () => {
      const certs = [makeCert('bronze', 40, { uptimePercentage: 95 })];
      const report = generateTrustReport(certs);
      expect(report.recommendations.some((r) => r.includes('uptime below 99%'))).toBe(true);
    });

    it('generates recommendation for slow servers', () => {
      const certs = [makeCert('bronze', 40, { responseTimeP95Ms: 600 })];
      const report = generateTrustReport(certs);
      expect(report.recommendations.some((r) => r.includes('P95 response time above 500ms'))).toBe(true);
    });

    it('generates healthy fleet recommendation when score >= 75 and no issues', () => {
      const certs = [
        makeCert('platinum', 100, {
          covenantDefined: true,
          identityVerified: true,
          attestationEnabled: true,
          enforcementMode: 'enforce',
          uptimePercentage: 99.99,
          responseTimeP95Ms: 50,
          securityAuditPassed: true,
          documentationComplete: true,
        }),
      ];
      // Override badge since makeCert doesn't re-compute
      certs[0]!.badge = 'platinum';
      const report = generateTrustReport(certs);
      expect(report.recommendations.some((r) => r.includes('good health'))).toBe(true);
    });

    it('single server reports correctly', () => {
      const cert = evaluateServer(makeProfile(), makePerfectCriteria());
      const report = generateTrustReport([cert]);
      expect(report.totalServers).toBe(1);
      expect(report.certifiedServers).toBe(1);
      expect(report.averageScore).toBe(100);
      expect(report.topServers.length).toBe(1);
    });
  });

  // ──────────────────────────────────────────
  // renewCertification
  // ──────────────────────────────────────────
  describe('renewCertification', () => {
    it('renews with new criteria and fresh timestamps', () => {
      const original = evaluateServer(makeProfile(), makeCriteria({ covenantDefined: true }));
      const improved = makePerfectCriteria();
      const renewed = renewCertification(original, improved);

      expect(renewed.score).toBe(100);
      expect(renewed.badge).toBe('platinum');
      expect(renewed.certifiedAt).toBeGreaterThanOrEqual(original.certifiedAt);
    });

    it('updates lastAuditedAt on renewal', () => {
      const profile = makeProfile({ lastAuditedAt: 1000 });
      const original = evaluateServer(profile, makeCriteria());
      const renewed = renewCertification(original, makeCriteria());

      expect(renewed.profile.lastAuditedAt).toBeGreaterThan(1000);
    });

    it('preserves original serverId and serverName', () => {
      const original = evaluateServer(
        makeProfile({ serverId: 'unique-id', serverName: 'UniqueName' }),
        makeCriteria(),
      );
      const renewed = renewCertification(original, makePerfectCriteria());

      expect(renewed.profile.serverId).toBe('unique-id');
      expect(renewed.profile.serverName).toBe('UniqueName');
    });

    it('badge can improve on renewal', () => {
      const original = evaluateServer(makeProfile(), makeCriteria());
      expect(original.badge).toBe('none');

      const renewed = renewCertification(original, makePerfectCriteria());
      expect(renewed.badge).toBe('platinum');
    });

    it('badge can degrade on renewal', () => {
      const original = evaluateServer(makeProfile(), makePerfectCriteria());
      expect(original.badge).toBe('platinum');

      const renewed = renewCertification(original, makeCriteria());
      expect(renewed.badge).toBe('none');
    });
  });
});
