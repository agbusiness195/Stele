import { describe, it, expect } from 'vitest';
import {
  runAudit,
  generateAuditSummary,
  suggestFixes,
} from './audit';
import type { AuditReport, AuditFinding } from './audit';

// ---------------------------------------------------------------------------
// runAudit
// ---------------------------------------------------------------------------

describe('runAudit', () => {
  it('returns critical finding when no covenants configured', () => {
    const report = runAudit({ covenantCount: 0 });
    const critical = report.findings.find(f => f.severity === 'critical');
    expect(critical).toBeDefined();
    expect(critical!.category).toBe('coverage');
    expect(critical!.title).toContain('No covenants');
  });

  it('returns no critical covenant finding when covenants are present', () => {
    const report = runAudit({ covenantCount: 5 });
    const covenantCritical = report.findings.find(
      f => f.severity === 'critical' && f.category === 'coverage',
    );
    expect(covenantCritical).toBeUndefined();
  });

  it('returns warning when enforcement mode is not enforce', () => {
    const report = runAudit({ enforcementMode: 'audit' });
    const warning = report.findings.find(
      f => f.severity === 'warning' && f.category === 'enforcement',
    );
    expect(warning).toBeDefined();
    expect(warning!.title).toContain('Enforcement');
  });

  it('returns no enforcement warning when enforcement is enforce', () => {
    const report = runAudit({ enforcementMode: 'enforce' });
    const warning = report.findings.find(
      f => f.category === 'enforcement',
    );
    expect(warning).toBeUndefined();
  });

  it('returns error when attestation coverage is below 0.2', () => {
    const report = runAudit({ attestationCoverage: 0.1 });
    const error = report.findings.find(
      f => f.severity === 'error' && f.category === 'attestation',
    );
    expect(error).toBeDefined();
    expect(error!.title).toContain('critically low');
  });

  it('returns warning when attestation coverage is between 0.2 and 0.5', () => {
    const report = runAudit({ attestationCoverage: 0.3 });
    const warning = report.findings.find(
      f => f.severity === 'warning' && f.category === 'attestation',
    );
    expect(warning).toBeDefined();
    expect(warning!.title).toContain('below recommended');
  });

  it('returns no attestation finding when coverage is 0.5 or above', () => {
    const report = runAudit({ attestationCoverage: 0.5 });
    const attestation = report.findings.find(f => f.category === 'attestation');
    expect(attestation).toBeUndefined();
  });

  it('returns error when identity is not verified', () => {
    const report = runAudit({ identityVerified: false });
    const error = report.findings.find(
      f => f.severity === 'error' && f.category === 'identity',
    );
    expect(error).toBeDefined();
    expect(error!.title).toContain('Identity not verified');
  });

  it('returns no identity finding when identity is verified', () => {
    const report = runAudit({ identityVerified: true });
    const identity = report.findings.find(f => f.category === 'identity');
    expect(identity).toBeUndefined();
  });

  it('returns info findings for missing compliance frameworks', () => {
    const report = runAudit({ complianceFrameworks: ['SOC2'] });
    const infoFindings = report.findings.filter(
      f => f.severity === 'info' && f.category === 'compliance',
    );
    // Should have info for all frameworks except SOC2
    expect(infoFindings.length).toBeGreaterThan(0);
    expect(infoFindings.some(f => f.title.includes('SOC2'))).toBe(false);
  });

  it('returns no compliance info when all known frameworks are configured', () => {
    const allFrameworks = ['SOC2', 'ISO27001', 'GDPR', 'CCPA', 'HIPAA', 'EU_AI_ACT'];
    const report = runAudit({ complianceFrameworks: allFrameworks });
    const complianceInfos = report.findings.filter(
      f => f.category === 'compliance' && f.severity === 'info',
    );
    expect(complianceInfos).toHaveLength(0);
  });

  it('score calculation: 100 with perfect audit', () => {
    const report = runAudit({
      covenantCount: 10,
      enforcementMode: 'enforce',
      attestationCoverage: 0.9,
      identityVerified: true,
      complianceFrameworks: ['SOC2', 'ISO27001', 'GDPR', 'CCPA', 'HIPAA', 'EU_AI_ACT'],
    });
    expect(report.score).toBe(100);
    expect(report.grade).toBe('A');
  });

  it('score deducts 25 per critical finding', () => {
    const report = runAudit({
      covenantCount: 0, // critical
      enforcementMode: 'enforce',
      attestationCoverage: 0.9,
      identityVerified: true,
      complianceFrameworks: ['SOC2', 'ISO27001', 'GDPR', 'CCPA', 'HIPAA', 'EU_AI_ACT'],
    });
    expect(report.score).toBe(75);
    expect(report.grade).toBe('C');
  });

  it('score deducts 15 per error finding', () => {
    const report = runAudit({
      covenantCount: 10,
      enforcementMode: 'enforce',
      attestationCoverage: 0.9,
      identityVerified: false, // error
      complianceFrameworks: ['SOC2', 'ISO27001', 'GDPR', 'CCPA', 'HIPAA', 'EU_AI_ACT'],
    });
    expect(report.score).toBe(85);
    expect(report.grade).toBe('B');
  });

  it('score deducts 5 per warning finding', () => {
    const report = runAudit({
      covenantCount: 10,
      enforcementMode: 'audit', // warning
      attestationCoverage: 0.9,
      identityVerified: true,
      complianceFrameworks: ['SOC2', 'ISO27001', 'GDPR', 'CCPA', 'HIPAA', 'EU_AI_ACT'],
    });
    expect(report.score).toBe(95);
    expect(report.grade).toBe('A');
  });

  it('score deducts 1 per info finding', () => {
    const report = runAudit({
      covenantCount: 10,
      enforcementMode: 'enforce',
      attestationCoverage: 0.9,
      identityVerified: true,
      complianceFrameworks: [], // 6 info findings for missing frameworks
    });
    expect(report.score).toBe(94);
    expect(report.grade).toBe('A');
  });

  it('grade A for score >= 90', () => {
    const report = runAudit({
      covenantCount: 10,
      enforcementMode: 'enforce',
      attestationCoverage: 0.9,
      identityVerified: true,
      complianceFrameworks: ['SOC2', 'ISO27001', 'GDPR', 'CCPA', 'HIPAA', 'EU_AI_ACT'],
    });
    expect(report.grade).toBe('A');
  });

  it('grade F for score < 60', () => {
    const report = runAudit({
      covenantCount: 0, // -25
      enforcementMode: 'none', // -5
      attestationCoverage: 0.1, // -15
      identityVerified: false, // -15
      complianceFrameworks: [], // -6
    });
    // 100 - 25 - 5 - 15 - 15 - 6 = 34
    expect(report.score).toBe(34);
    expect(report.grade).toBe('F');
  });

  it('score is clamped to minimum 0', () => {
    // Create a scenario where deductions would exceed 100
    const report = runAudit({
      covenantCount: 0, // -25 critical
      enforcementMode: 'none', // -5 warning
      attestationCoverage: 0.0, // -15 error (below 0.2)
      identityVerified: false, // -15 error
      complianceFrameworks: [], // -6 info
    });
    expect(report.score).toBeGreaterThanOrEqual(0);
  });

  it('report has a recent timestamp', () => {
    const before = Date.now();
    const report = runAudit({});
    const after = Date.now();
    expect(report.timestamp).toBeGreaterThanOrEqual(before);
    expect(report.timestamp).toBeLessThanOrEqual(after);
  });

  it('report summary includes score and grade', () => {
    const report = runAudit({ covenantCount: 5 });
    expect(report.summary).toContain(`${report.score}/100`);
    expect(report.summary).toContain(`Grade: ${report.grade}`);
  });

  it('coverageGaps includes entries for identified gaps', () => {
    const report = runAudit({ covenantCount: 0 });
    expect(report.coverageGaps).toContain('No covenants configured');
  });

  it('complianceStatus tracks configured and unconfigured frameworks', () => {
    const report = runAudit({ complianceFrameworks: ['SOC2', 'GDPR'] });
    expect(report.complianceStatus['SOC2']).toBe(true);
    expect(report.complianceStatus['GDPR']).toBe(true);
    expect(report.complianceStatus['HIPAA']).toBe(false);
  });

  it('defaults all parameters when nothing is provided', () => {
    const report = runAudit({});
    // covenantCount=0 (critical), enforcementMode='none' (warning),
    // attestationCoverage=0 (error), identityVerified=false (error),
    // no frameworks (info * 6)
    expect(report.findings.length).toBeGreaterThan(0);
    const severities = report.findings.map(f => f.severity);
    expect(severities).toContain('critical');
    expect(severities).toContain('error');
    expect(severities).toContain('warning');
    expect(severities).toContain('info');
  });

  it('all findings have unique ids', () => {
    const report = runAudit({});
    const ids = report.findings.map(f => f.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it('all findings have non-empty recommendations', () => {
    const report = runAudit({});
    for (const finding of report.findings) {
      expect(finding.recommendation.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// generateAuditSummary
// ---------------------------------------------------------------------------

describe('generateAuditSummary', () => {
  it('generates summary for report with findings', () => {
    const report = runAudit({ covenantCount: 0 });
    const summary = generateAuditSummary(report);
    expect(summary).toContain('Compliance Audit Report');
    expect(summary).toContain(`Score: ${report.score}/100`);
    expect(summary).toContain(`Grade: ${report.grade}`);
  });

  it('generates summary with no findings message for perfect audit', () => {
    const report = runAudit({
      covenantCount: 10,
      enforcementMode: 'enforce',
      attestationCoverage: 0.9,
      identityVerified: true,
      complianceFrameworks: ['SOC2', 'ISO27001', 'GDPR', 'CCPA', 'HIPAA', 'EU_AI_ACT'],
    });
    const summary = generateAuditSummary(report);
    expect(summary).toContain('No findings');
    expect(summary).toContain('fully compliant');
  });

  it('groups findings by severity in summary', () => {
    const report = runAudit({
      covenantCount: 0,
      identityVerified: false,
    });
    const summary = generateAuditSummary(report);
    expect(summary).toContain('[CRITICAL]');
    expect(summary).toContain('[ERROR]');
  });

  it('includes coverage gaps in summary', () => {
    const report = runAudit({ covenantCount: 0 });
    const summary = generateAuditSummary(report);
    expect(summary).toContain('Coverage Gaps');
    expect(summary).toContain('No covenants configured');
  });

  it('returns a non-empty string', () => {
    const report = runAudit({});
    const summary = generateAuditSummary(report);
    expect(summary.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// suggestFixes
// ---------------------------------------------------------------------------

describe('suggestFixes', () => {
  it('returns fixes sorted by priority (critical first)', () => {
    const report = runAudit({
      covenantCount: 0, // critical
      identityVerified: false, // error
      enforcementMode: 'none', // warning
    });
    const fixes = suggestFixes(report);
    expect(fixes.length).toBeGreaterThan(0);

    // Check that priorities are non-decreasing
    for (let i = 1; i < fixes.length; i++) {
      expect(fixes[i]!.priority).toBeGreaterThanOrEqual(fixes[i - 1]!.priority);
    }
  });

  it('critical findings have priority 1', () => {
    const report = runAudit({ covenantCount: 0 });
    const fixes = suggestFixes(report);
    const criticalFixes = fixes.filter(f => f.finding.severity === 'critical');
    for (const fix of criticalFixes) {
      expect(fix.priority).toBe(1);
    }
  });

  it('error findings have priority 2', () => {
    const report = runAudit({ identityVerified: false });
    const fixes = suggestFixes(report);
    const errorFixes = fixes.filter(f => f.finding.severity === 'error');
    for (const fix of errorFixes) {
      expect(fix.priority).toBe(2);
    }
  });

  it('warning findings have priority 3', () => {
    const report = runAudit({ enforcementMode: 'none' });
    const fixes = suggestFixes(report);
    const warningFixes = fixes.filter(f => f.finding.severity === 'warning');
    for (const fix of warningFixes) {
      expect(fix.priority).toBe(3);
    }
  });

  it('info findings have priority 4', () => {
    const report = runAudit({
      covenantCount: 10,
      enforcementMode: 'enforce',
      attestationCoverage: 0.9,
      identityVerified: true,
      complianceFrameworks: ['SOC2'], // Missing other frameworks = info
    });
    const fixes = suggestFixes(report);
    const infoFixes = fixes.filter(f => f.finding.severity === 'info');
    for (const fix of infoFixes) {
      expect(fix.priority).toBe(4);
    }
  });

  it('fix text matches finding recommendation', () => {
    const report = runAudit({});
    const fixes = suggestFixes(report);
    for (const fix of fixes) {
      expect(fix.fix).toBe(fix.finding.recommendation);
    }
  });

  it('returns empty array for perfect audit', () => {
    const report = runAudit({
      covenantCount: 10,
      enforcementMode: 'enforce',
      attestationCoverage: 0.9,
      identityVerified: true,
      complianceFrameworks: ['SOC2', 'ISO27001', 'GDPR', 'CCPA', 'HIPAA', 'EU_AI_ACT'],
    });
    const fixes = suggestFixes(report);
    expect(fixes).toHaveLength(0);
  });

  it('number of fixes matches number of findings', () => {
    const report = runAudit({});
    const fixes = suggestFixes(report);
    expect(fixes.length).toBe(report.findings.length);
  });
});

// ---------------------------------------------------------------------------
// CLI integration: audit command through run()
// ---------------------------------------------------------------------------

import { run } from './index';
import { setColorsEnabled, stripAnsi } from './format';
import { afterEach } from 'vitest';

afterEach(() => {
  setColorsEnabled(true);
});

describe('nobulex audit command', () => {
  it('shows help with --help', async () => {
    const r = await run(['audit', '--help']);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('nobulex audit');
    expect(r.stdout).toContain('compliance audit');
  });

  it('runs audit with default params (no flags)', async () => {
    const r = await run(['audit', '--no-color']);
    // Should produce output with findings
    expect(r.stdout).toContain('Compliance Audit');
    // Default params have critical issues, so grade should be F
    expect(r.exitCode).toBe(1); // F grade exits with 1
  });

  it('runs audit with --json flag', async () => {
    const r = await run(['audit', '--json']);
    expect(r.exitCode).toBe(1); // F grade with defaults
    const parsed = JSON.parse(r.stdout);
    expect(parsed.report).toBeDefined();
    expect(parsed.report.score).toBeDefined();
    expect(parsed.report.grade).toBeDefined();
    expect(parsed.report.findings).toBeDefined();
    expect(parsed.fixes).toBeDefined();
  });

  it('runs perfect audit with all flags', async () => {
    const r = await run([
      'audit',
      '--covenants', '10',
      '--enforcement', 'enforce',
      '--attestation', '0.9',
      '--identity-verified',
      '--frameworks', 'SOC2,ISO27001,GDPR,CCPA,HIPAA,EU_AI_ACT',
      '--json',
    ]);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.report.score).toBe(100);
    expect(parsed.report.grade).toBe('A');
    expect(r.exitCode).toBe(0);
  });

  it('audit command appears in help text', async () => {
    const r = await run([]);
    expect(r.stdout).toContain('audit');
  });

  it('shows score and grade in text output', async () => {
    const r = await run(['audit', '--no-color', '--covenants', '10']);
    const plain = stripAnsi(r.stdout);
    expect(plain).toContain('/100');
    expect(plain).toContain('Grade:');
  });
});
