/**
 * @usekova/cli audit command.
 *
 * Provides compliance audit functionality that inspects covenant coverage,
 * enforcement configuration, attestation coverage, identity verification,
 * and compliance framework alignment. Generates findings with actionable
 * recommendations and an overall compliance grade.
 *
 * @packageDocumentation
 */

// ─── Types ────────────────────────────────────────────────────────────────────

/** A single finding from the compliance audit. */
export interface AuditFinding {
  id: string;
  category: 'coverage' | 'enforcement' | 'attestation' | 'identity' | 'compliance';
  severity: 'info' | 'warning' | 'error' | 'critical';
  title: string;
  description: string;
  recommendation: string;
  autoFixable: boolean;
}

/** The complete audit report with findings, score, and grade. */
export interface AuditReport {
  timestamp: number;
  findings: AuditFinding[];
  score: number; // 0-100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  summary: string;
  coverageGaps: string[];
  complianceStatus: Record<string, boolean>;
}

// ─── Core audit logic ─────────────────────────────────────────────────────────

/**
 * Run a compliance audit based on provided parameters.
 *
 * Generates findings based on inputs:
 * - No covenants: critical finding
 * - enforcementMode !== 'enforce': warning
 * - attestationCoverage < 0.5: warning, < 0.2: error
 * - !identityVerified: error
 * - Missing compliance frameworks: info per framework
 *
 * Score = 100 - (criticals*25 + errors*15 + warnings*5 + infos*1)
 * Grade: A >= 90, B >= 80, C >= 70, D >= 60, F < 60
 *
 * @param params - Audit parameters describing the current system state.
 * @returns A complete audit report with findings, score, and grade.
 */
export function runAudit(params: {
  covenantCount?: number;
  enforcementMode?: string;
  attestationCoverage?: number;
  identityVerified?: boolean;
  complianceFrameworks?: string[];
}): AuditReport {
  const findings: AuditFinding[] = [];
  const coverageGaps: string[] = [];
  const complianceStatus: Record<string, boolean> = {};
  let findingCounter = 0;

  // Check covenant coverage
  const covenantCount = params.covenantCount ?? 0;
  if (covenantCount === 0) {
    findings.push({
      id: `audit-${++findingCounter}`,
      category: 'coverage',
      severity: 'critical',
      title: 'No covenants configured',
      description: 'No covenants have been configured. Without covenants, agent behavior is unconstrained.',
      recommendation: 'Create at least one covenant with appropriate constraints using "kova create".',
      autoFixable: false,
    });
    coverageGaps.push('No covenants configured');
  }

  // Check enforcement mode
  const enforcementMode = params.enforcementMode ?? 'none';
  if (enforcementMode !== 'enforce') {
    findings.push({
      id: `audit-${++findingCounter}`,
      category: 'enforcement',
      severity: 'warning',
      title: 'Enforcement not active',
      description: `Enforcement mode is "${enforcementMode}" instead of "enforce". Covenant violations may not be blocked.`,
      recommendation: 'Set enforcement mode to "enforce" to actively prevent covenant violations.',
      autoFixable: true,
    });
    coverageGaps.push('Enforcement not active');
  }

  // Check attestation coverage
  const attestationCoverage = params.attestationCoverage ?? 0;
  if (attestationCoverage < 0.2) {
    findings.push({
      id: `audit-${++findingCounter}`,
      category: 'attestation',
      severity: 'error',
      title: 'Attestation coverage critically low',
      description: `Attestation coverage is ${(attestationCoverage * 100).toFixed(1)}%, well below the recommended minimum of 50%.`,
      recommendation: 'Increase attestation coverage by enabling attestation for more agent interactions.',
      autoFixable: false,
    });
    coverageGaps.push('Attestation coverage below 20%');
  } else if (attestationCoverage < 0.5) {
    findings.push({
      id: `audit-${++findingCounter}`,
      category: 'attestation',
      severity: 'warning',
      title: 'Attestation coverage below recommended',
      description: `Attestation coverage is ${(attestationCoverage * 100).toFixed(1)}%, below the recommended minimum of 50%.`,
      recommendation: 'Increase attestation coverage to at least 50% for better compliance posture.',
      autoFixable: false,
    });
    coverageGaps.push('Attestation coverage below 50%');
  }

  // Check identity verification
  const identityVerified = params.identityVerified ?? false;
  if (!identityVerified) {
    findings.push({
      id: `audit-${++findingCounter}`,
      category: 'identity',
      severity: 'error',
      title: 'Identity not verified',
      description: 'Agent identity has not been verified. This is required for compliance and trust establishment.',
      recommendation: 'Complete identity verification using "kova init" and register with a discovery server.',
      autoFixable: false,
    });
    coverageGaps.push('Identity not verified');
  }

  // Check compliance frameworks
  const knownFrameworks = ['SOC2', 'ISO27001', 'GDPR', 'CCPA', 'HIPAA', 'EU_AI_ACT'];
  const configuredFrameworks = params.complianceFrameworks ?? [];

  for (const framework of knownFrameworks) {
    const isConfigured = configuredFrameworks.includes(framework);
    complianceStatus[framework] = isConfigured;

    if (!isConfigured) {
      findings.push({
        id: `audit-${++findingCounter}`,
        category: 'compliance',
        severity: 'info',
        title: `${framework} compliance not configured`,
        description: `The ${framework} compliance framework is not configured. Consider enabling it if applicable to your operations.`,
        recommendation: `Add "${framework}" to your compliance frameworks configuration if it applies to your jurisdiction.`,
        autoFixable: true,
      });
    }
  }

  // Calculate score
  let score = 100;
  for (const finding of findings) {
    switch (finding.severity) {
      case 'critical':
        score -= 25;
        break;
      case 'error':
        score -= 15;
        break;
      case 'warning':
        score -= 5;
        break;
      case 'info':
        score -= 1;
        break;
    }
  }
  score = Math.max(0, score);

  // Calculate grade
  let grade: AuditReport['grade'];
  if (score >= 90) {
    grade = 'A';
  } else if (score >= 80) {
    grade = 'B';
  } else if (score >= 70) {
    grade = 'C';
  } else if (score >= 60) {
    grade = 'D';
  } else {
    grade = 'F';
  }

  // Generate summary
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const errorCount = findings.filter(f => f.severity === 'error').length;
  const warningCount = findings.filter(f => f.severity === 'warning').length;
  const infoCount = findings.filter(f => f.severity === 'info').length;

  const summaryParts: string[] = [];
  summaryParts.push(`Audit completed with score ${score}/100 (Grade: ${grade}).`);
  if (criticalCount > 0) summaryParts.push(`${criticalCount} critical issue(s).`);
  if (errorCount > 0) summaryParts.push(`${errorCount} error(s).`);
  if (warningCount > 0) summaryParts.push(`${warningCount} warning(s).`);
  if (infoCount > 0) summaryParts.push(`${infoCount} informational finding(s).`);

  return {
    timestamp: Date.now(),
    findings,
    score,
    grade,
    summary: summaryParts.join(' '),
    coverageGaps,
    complianceStatus,
  };
}

/**
 * Generate a human-readable summary of audit findings.
 *
 * @param report - The audit report to summarize.
 * @returns A formatted string summarizing the audit.
 */
export function generateAuditSummary(report: AuditReport): string {
  const lines: string[] = [];

  lines.push(`Compliance Audit Report`);
  lines.push(`Score: ${report.score}/100 | Grade: ${report.grade}`);
  lines.push('');

  if (report.findings.length === 0) {
    lines.push('No findings. System is fully compliant.');
    return lines.join('\n');
  }

  // Group by severity
  const severityOrder: AuditFinding['severity'][] = ['critical', 'error', 'warning', 'info'];

  for (const severity of severityOrder) {
    const severityFindings = report.findings.filter(f => f.severity === severity);
    if (severityFindings.length === 0) continue;

    lines.push(`[${severity.toUpperCase()}]`);
    for (const finding of severityFindings) {
      lines.push(`  - ${finding.title}: ${finding.description}`);
    }
    lines.push('');
  }

  if (report.coverageGaps.length > 0) {
    lines.push('Coverage Gaps:');
    for (const gap of report.coverageGaps) {
      lines.push(`  - ${gap}`);
    }
    lines.push('');
  }

  lines.push(report.summary);

  return lines.join('\n');
}

/**
 * Suggest actionable fixes for audit findings, sorted by priority.
 *
 * Critical findings are prioritized first, followed by errors, warnings,
 * and informational findings.
 *
 * @param report - The audit report to generate fixes for.
 * @returns An array of suggested fixes with priority ordering.
 */
export function suggestFixes(report: AuditReport): Array<{
  finding: AuditFinding;
  fix: string;
  priority: number;
}> {
  const severityPriority: Record<AuditFinding['severity'], number> = {
    critical: 1,
    error: 2,
    warning: 3,
    info: 4,
  };

  const fixes = report.findings.map(finding => ({
    finding,
    fix: finding.recommendation,
    priority: severityPriority[finding.severity],
  }));

  // Sort by priority (lower = higher priority)
  fixes.sort((a, b) => a.priority - b.priority);

  return fixes;
}
