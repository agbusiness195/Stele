/**
 * MCP Server Certification system.
 *
 * Proactively certifies MCP servers with trust reports and a badge system.
 * Evaluates servers against a set of criteria and assigns a badge level
 * (none, bronze, silver, gold, platinum) based on the resulting score.
 *
 * @packageDocumentation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

/** Badge levels awarded to MCP servers based on certification score. */
export type BadgeLevel = 'none' | 'bronze' | 'silver' | 'gold' | 'platinum';

/** Profile describing an MCP server's identity and capabilities. */
export interface MCPServerProfile {
  /** Unique identifier for the server. */
  serverId: string;
  /** Human-readable server name. */
  serverName: string;
  /** Server version string. */
  version: string;
  /** List of capabilities the server supports. */
  capabilities: string[];
  /** Timestamp when the server was first registered (ms since epoch). */
  registeredAt: number;
  /** Timestamp when the server was last audited (ms since epoch). */
  lastAuditedAt: number;
}

/** Criteria used to evaluate an MCP server for certification. */
export interface CertificationCriteria {
  /** Whether the server has a covenant defined. */
  covenantDefined: boolean;
  /** Whether the server's identity has been verified. */
  identityVerified: boolean;
  /** Whether attestation is enabled. */
  attestationEnabled: boolean;
  /** The enforcement mode in use. */
  enforcementMode: 'enforce' | 'audit' | 'none';
  /** Server uptime percentage (0-100). */
  uptimePercentage: number;
  /** 95th-percentile response time in milliseconds. */
  responseTimeP95Ms: number;
  /** Whether the server has passed a security audit. */
  securityAuditPassed: boolean;
  /** Whether documentation is complete. */
  documentationComplete: boolean;
}

/** The result of evaluating an MCP server against certification criteria. */
export interface ServerCertification {
  /** The server profile. */
  profile: MCPServerProfile;
  /** The criteria used for evaluation. */
  criteria: CertificationCriteria;
  /** The badge level awarded. */
  badge: BadgeLevel;
  /** The numeric score (0-100). */
  score: number;
  /** Human-readable trust report. */
  report: string;
  /** Timestamp when the certification was issued (ms since epoch). */
  certifiedAt: number;
  /** Timestamp when the certification expires (ms since epoch). */
  expiresAt: number;
}

// ─── Constants ───────────────────────────────────────────────────────────────

/** Certification validity duration: 90 days in milliseconds. */
const CERTIFICATION_TTL_MS = 90 * 24 * 60 * 60 * 1000;

// ─── Score thresholds ────────────────────────────────────────────────────────

const BADGE_THRESHOLDS: Array<{ min: number; badge: BadgeLevel }> = [
  { min: 90, badge: 'platinum' },
  { min: 75, badge: 'gold' },
  { min: 60, badge: 'silver' },
  { min: 40, badge: 'bronze' },
];

// ─── Functions ───────────────────────────────────────────────────────────────

/**
 * Create a new MCP server profile.
 *
 * @param params - Profile parameters.
 * @returns A complete MCPServerProfile with timestamps set to now.
 */
export function createServerProfile(params: {
  serverId: string;
  serverName: string;
  version: string;
  capabilities: string[];
}): MCPServerProfile {
  const now = Date.now();
  return {
    serverId: params.serverId,
    serverName: params.serverName,
    version: params.version,
    capabilities: [...params.capabilities],
    registeredAt: now,
    lastAuditedAt: now,
  };
}

/**
 * Calculate the certification score from criteria.
 *
 * Scoring breakdown:
 * - covenantDefined: +20
 * - identityVerified: +15
 * - attestationEnabled: +15
 * - enforcementMode: enforce=+20, audit=+10, none=+0
 * - uptimePercentage >= 99.9: +10, >= 99: +5
 * - responseTimeP95Ms <= 100: +10, <= 500: +5
 * - securityAuditPassed: +5
 * - documentationComplete: +5
 *
 * @param criteria - The certification criteria to score.
 * @returns The numeric score (0-100).
 */
function computeScore(criteria: CertificationCriteria): number {
  let score = 0;

  if (criteria.covenantDefined) score += 20;
  if (criteria.identityVerified) score += 15;
  if (criteria.attestationEnabled) score += 15;

  if (criteria.enforcementMode === 'enforce') {
    score += 20;
  } else if (criteria.enforcementMode === 'audit') {
    score += 10;
  }

  if (criteria.uptimePercentage >= 99.9) {
    score += 10;
  } else if (criteria.uptimePercentage >= 99) {
    score += 5;
  }

  if (criteria.responseTimeP95Ms <= 100) {
    score += 10;
  } else if (criteria.responseTimeP95Ms <= 500) {
    score += 5;
  }

  if (criteria.securityAuditPassed) score += 5;
  if (criteria.documentationComplete) score += 5;

  return score;
}

/**
 * Determine the badge level from a numeric score.
 *
 * @param score - The certification score (0-100).
 * @returns The badge level.
 */
function determineBadge(score: number): BadgeLevel {
  for (const threshold of BADGE_THRESHOLDS) {
    if (score >= threshold.min) {
      return threshold.badge;
    }
  }
  return 'none';
}

/**
 * Generate a human-readable trust report from the certification criteria.
 *
 * @param profile - The server profile.
 * @param criteria - The certification criteria.
 * @param score - The computed score.
 * @param badge - The awarded badge level.
 * @returns A multi-line report string.
 */
function buildReport(
  profile: MCPServerProfile,
  criteria: CertificationCriteria,
  score: number,
  badge: BadgeLevel,
): string {
  const lines: string[] = [
    `Trust Report for ${profile.serverName} (${profile.serverId})`,
    `Version: ${profile.version}`,
    `Badge: ${badge.toUpperCase()} (Score: ${score}/100)`,
    '',
    'Criteria Results:',
    `  Covenant Defined:      ${criteria.covenantDefined ? 'PASS (+20)' : 'FAIL (+0)'}`,
    `  Identity Verified:     ${criteria.identityVerified ? 'PASS (+15)' : 'FAIL (+0)'}`,
    `  Attestation Enabled:   ${criteria.attestationEnabled ? 'PASS (+15)' : 'FAIL (+0)'}`,
    `  Enforcement Mode:      ${criteria.enforcementMode} (${criteria.enforcementMode === 'enforce' ? '+20' : criteria.enforcementMode === 'audit' ? '+10' : '+0'})`,
    `  Uptime:                ${criteria.uptimePercentage}% (${criteria.uptimePercentage >= 99.9 ? '+10' : criteria.uptimePercentage >= 99 ? '+5' : '+0'})`,
    `  Response Time (P95):   ${criteria.responseTimeP95Ms}ms (${criteria.responseTimeP95Ms <= 100 ? '+10' : criteria.responseTimeP95Ms <= 500 ? '+5' : '+0'})`,
    `  Security Audit:        ${criteria.securityAuditPassed ? 'PASS (+5)' : 'FAIL (+0)'}`,
    `  Documentation:         ${criteria.documentationComplete ? 'PASS (+5)' : 'FAIL (+0)'}`,
  ];

  return lines.join('\n');
}

/**
 * Evaluate an MCP server against certification criteria and produce
 * a full ServerCertification including badge, score, and report.
 *
 * @param profile - The server profile to evaluate.
 * @param criteria - The certification criteria.
 * @returns A complete ServerCertification.
 */
export function evaluateServer(
  profile: MCPServerProfile,
  criteria: CertificationCriteria,
): ServerCertification {
  const score = computeScore(criteria);
  const badge = determineBadge(score);
  const report = buildReport(profile, criteria, score, badge);
  const certifiedAt = Date.now();

  return {
    profile,
    criteria,
    badge,
    score,
    report,
    certifiedAt,
    expiresAt: certifiedAt + CERTIFICATION_TTL_MS,
  };
}

/**
 * Generate an aggregate trust report across multiple server certifications.
 *
 * @param certifications - Array of server certifications to analyze.
 * @returns An aggregate trust report with distributions and recommendations.
 */
export function generateTrustReport(certifications: ServerCertification[]): {
  totalServers: number;
  certifiedServers: number;
  averageScore: number;
  badgeDistribution: Record<BadgeLevel, number>;
  topServers: Array<{ serverId: string; score: number; badge: BadgeLevel }>;
  recommendations: string[];
} {
  const totalServers = certifications.length;

  const badgeDistribution: Record<BadgeLevel, number> = {
    none: 0,
    bronze: 0,
    silver: 0,
    gold: 0,
    platinum: 0,
  };

  let totalScore = 0;
  let certifiedCount = 0;

  for (const cert of certifications) {
    badgeDistribution[cert.badge]++;
    totalScore += cert.score;
    if (cert.badge !== 'none') {
      certifiedCount++;
    }
  }

  const averageScore = totalServers > 0 ? Math.round((totalScore / totalServers) * 100) / 100 : 0;

  // Top servers sorted by score descending, take up to 10
  const sorted = [...certifications].sort((a, b) => b.score - a.score);
  const topServers = sorted.slice(0, 10).map((cert) => ({
    serverId: cert.profile.serverId,
    score: cert.score,
    badge: cert.badge,
  }));

  // Generate recommendations based on the fleet's overall health
  const recommendations: string[] = [];

  if (badgeDistribution.none > 0) {
    recommendations.push(
      `${badgeDistribution.none} server(s) have no badge. Consider defining covenants and enabling identity verification.`,
    );
  }

  const noEnforcement = certifications.filter((c) => c.criteria.enforcementMode === 'none');
  if (noEnforcement.length > 0) {
    recommendations.push(
      `${noEnforcement.length} server(s) have enforcement disabled. Enable at least audit mode for better trust posture.`,
    );
  }

  const noAttestation = certifications.filter((c) => !c.criteria.attestationEnabled);
  if (noAttestation.length > 0) {
    recommendations.push(
      `${noAttestation.length} server(s) lack attestation. Enable attestation to improve certification scores.`,
    );
  }

  const lowUptime = certifications.filter((c) => c.criteria.uptimePercentage < 99);
  if (lowUptime.length > 0) {
    recommendations.push(
      `${lowUptime.length} server(s) have uptime below 99%. Investigate reliability issues.`,
    );
  }

  const slowServers = certifications.filter((c) => c.criteria.responseTimeP95Ms > 500);
  if (slowServers.length > 0) {
    recommendations.push(
      `${slowServers.length} server(s) have P95 response time above 500ms. Optimize performance.`,
    );
  }

  if (averageScore >= 75 && recommendations.length === 0) {
    recommendations.push('Fleet is in good health. Continue monitoring for regressions.');
  }

  return {
    totalServers,
    certifiedServers: certifiedCount,
    averageScore,
    badgeDistribution,
    topServers,
    recommendations,
  };
}

/**
 * Renew a server certification with updated criteria.
 *
 * Re-evaluates the server with the new criteria and updates timestamps.
 *
 * @param cert - The existing certification to renew.
 * @param newCriteria - The updated certification criteria.
 * @returns A new ServerCertification with fresh timestamps and score.
 */
export function renewCertification(
  cert: ServerCertification,
  newCriteria: CertificationCriteria,
): ServerCertification {
  const updatedProfile: MCPServerProfile = {
    ...cert.profile,
    lastAuditedAt: Date.now(),
  };

  return evaluateServer(updatedProfile, newCriteria);
}
