import { sha256Object } from '@stele/crypto';
import { SteleError, SteleErrorCode } from '@stele/types';

export type {
  LegalIdentityPackage,
  ComplianceRecord,
  JurisdictionalMapping,
  CovenantRecord,
  ReputationSnapshot,
  AttestationRecord,
  InsuranceRecord,
  ComplianceStandard,
  JurisdictionComplianceEntry,
  CrossJurisdictionResult,
  AuditTrailEntry,
  AuditTrailExport,
  RegulatoryGap,
  RegulatoryGapAnalysisResult,
} from './types';

import type {
  LegalIdentityPackage,
  ComplianceRecord,
  JurisdictionalMapping,
  CovenantRecord,
  ReputationSnapshot,
  AttestationRecord,
  InsuranceRecord,
  ComplianceStandard,
  JurisdictionComplianceEntry,
  CrossJurisdictionResult,
  AuditTrailEntry,
  AuditTrailExport,
  RegulatoryGap,
  RegulatoryGapAnalysisResult,
} from './types';

// ---------------------------------------------------------------------------
// Jurisdiction & compliance registries
// ---------------------------------------------------------------------------

export interface JurisdictionInfo {
  legalFramework: string;
  complianceStandard: string;
  requiredFields: string[];
}

export interface ComplianceStandardInfo {
  requiredScore: number;
  requiredAttestationCoverage: number;
  requiredCanaryPassRate: number;
  description: string;
}

export interface ComplianceWeights {
  covenantCoverage: number;
  breachFreedom: number;
  attestationCoverage: number;
  canaryPassRate: number;
}

const DEFAULT_WEIGHTS: ComplianceWeights = {
  covenantCoverage: 0.3,
  breachFreedom: 0.3,
  attestationCoverage: 0.2,
  canaryPassRate: 0.2,
};

/**
 * Known jurisdictions and their legal frameworks.
 * Use registerJurisdiction() to add custom entries.
 */
const jurisdictionRegistry: Record<string, JurisdictionInfo> = {
  US: {
    legalFramework: 'US Federal / State Law',
    complianceStandard: 'SOC2',
    requiredFields: ['agentId', 'operatorId', 'complianceRecord', 'attestations', 'insurancePolicies'],
  },
  EU: {
    legalFramework: 'EU General Data Protection Regulation',
    complianceStandard: 'GDPR',
    requiredFields: ['agentId', 'operatorId', 'complianceRecord', 'covenantHistory', 'attestations', 'reputationSnapshot'],
  },
  UK: {
    legalFramework: 'UK General Data Protection Regulation',
    complianceStandard: 'UK-GDPR',
    requiredFields: ['agentId', 'operatorId', 'complianceRecord', 'covenantHistory', 'attestations'],
  },
  JP: {
    legalFramework: 'Act on the Protection of Personal Information',
    complianceStandard: 'APPI',
    requiredFields: ['agentId', 'operatorId', 'complianceRecord', 'attestations'],
  },
};

/** Read-only snapshot of the jurisdiction registry. */
export const JURISDICTIONS: Record<string, JurisdictionInfo> = jurisdictionRegistry;

/**
 * Register a custom jurisdiction. Throws if code is empty or info is incomplete.
 */
export function registerJurisdiction(code: string, info: JurisdictionInfo): void {
  if (!code || code.trim() === '') {
    throw new SteleError('Jurisdiction code must be a non-empty string', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (!info.legalFramework || !info.complianceStandard || !Array.isArray(info.requiredFields)) {
    throw new SteleError('JurisdictionInfo must include legalFramework, complianceStandard, and requiredFields', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  jurisdictionRegistry[code] = { ...info, requiredFields: [...info.requiredFields] };
}

/**
 * Compliance standard requirements.
 */
export const COMPLIANCE_STANDARDS: Record<ComplianceStandard, ComplianceStandardInfo> = {
  SOC2: {
    requiredScore: 0.8,
    requiredAttestationCoverage: 0.9,
    requiredCanaryPassRate: 0.95,
    description: 'Service Organization Control 2 - Trust Services Criteria',
  },
  ISO27001: {
    requiredScore: 0.85,
    requiredAttestationCoverage: 0.85,
    requiredCanaryPassRate: 0.9,
    description: 'Information Security Management System',
  },
  GDPR: {
    requiredScore: 0.75,
    requiredAttestationCoverage: 0.8,
    requiredCanaryPassRate: 0.9,
    description: 'General Data Protection Regulation',
  },
  CCPA: {
    requiredScore: 0.7,
    requiredAttestationCoverage: 0.75,
    requiredCanaryPassRate: 0.85,
    description: 'California Consumer Privacy Act',
  },
  HIPAA: {
    requiredScore: 0.9,
    requiredAttestationCoverage: 0.95,
    requiredCanaryPassRate: 0.98,
    description: 'Health Insurance Portability and Accountability Act',
  },
};

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function validateNonEmpty(value: string, name: string): void {
  if (!value || value.trim() === '') {
    throw new SteleError(`${name} must be a non-empty string`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
}

function validateComplianceRecord(record: ComplianceRecord): void {
  if (record.totalInteractions < 0) {
    throw new SteleError('totalInteractions must be non-negative', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (record.covenantedInteractions < 0) {
    throw new SteleError('covenantedInteractions must be non-negative', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (record.breaches < 0) {
    throw new SteleError('breaches must be non-negative', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (record.canaryTests < 0) {
    throw new SteleError('canaryTests must be non-negative', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (record.canaryPasses < 0) {
    throw new SteleError('canaryPasses must be non-negative', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (record.attestationCoverage < 0 || record.attestationCoverage > 1) {
    throw new SteleError('attestationCoverage must be between 0 and 1', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (record.covenantedInteractions > record.totalInteractions) {
    throw new SteleError('covenantedInteractions cannot exceed totalInteractions', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (record.breaches > record.totalInteractions) {
    throw new SteleError('breaches cannot exceed totalInteractions', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (record.canaryPasses > record.canaryTests) {
    throw new SteleError('canaryPasses cannot exceed canaryTests', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/**
 * Creates a LegalIdentityPackage.
 * Validates agentId and operatorId are non-empty.
 * packageHash = sha256 of all content.
 */
export function exportLegalPackage(
  agentId: string,
  operatorId: string,
  data: {
    covenants: CovenantRecord[];
    compliance: ComplianceRecord;
    reputation: ReputationSnapshot;
    attestations: AttestationRecord[];
    insurance: InsuranceRecord[];
  },
  format: 'json' | 'pdf' | 'legal-xml' = 'json',
): LegalIdentityPackage {
  validateNonEmpty(agentId, 'agentId');
  validateNonEmpty(operatorId, 'operatorId');

  const exportedAt = Date.now();

  const content = {
    agentId,
    operatorId,
    covenantHistory: data.covenants,
    complianceRecord: data.compliance,
    reputationSnapshot: data.reputation,
    attestations: data.attestations,
    insurancePolicies: data.insurance,
    exportFormat: format,
    exportedAt,
  };

  const packageHash = sha256Object(content);

  return {
    agentId,
    operatorId,
    covenantHistory: data.covenants,
    complianceRecord: data.compliance,
    reputationSnapshot: data.reputation,
    attestations: data.attestations,
    insurancePolicies: data.insurance,
    exportFormat: format,
    exportedAt,
    packageHash,
  };
}

/**
 * Maps package fields to jurisdiction requirements.
 * Known jurisdictions: 'US' (SOC2), 'EU' (GDPR), 'UK' (UK-GDPR), 'JP' (APPI).
 * Custom jurisdictions can be added via registerJurisdiction().
 * Returns JurisdictionalMapping with legalFramework, requiredFields, complianceStandard, and mappedFields.
 */
export function mapToJurisdiction(
  pkg: LegalIdentityPackage,
  jurisdiction: string,
): JurisdictionalMapping {
  validateNonEmpty(jurisdiction, 'jurisdiction');

  const jurisdictionInfo = jurisdictionRegistry[jurisdiction];

  if (!jurisdictionInfo) {
    return {
      jurisdiction,
      legalFramework: 'Unknown',
      requiredFields: [],
      complianceStandard: 'Unknown',
      mappedFields: {},
    };
  }

  const mappedFields: Record<string, string> = {};

  for (const field of jurisdictionInfo.requiredFields) {
    switch (field) {
      case 'agentId':
        mappedFields[field] = pkg.agentId;
        break;
      case 'operatorId':
        mappedFields[field] = pkg.operatorId;
        break;
      case 'complianceRecord':
        mappedFields[field] = JSON.stringify(pkg.complianceRecord);
        break;
      case 'covenantHistory':
        mappedFields[field] = JSON.stringify(pkg.covenantHistory);
        break;
      case 'attestations':
        mappedFields[field] = JSON.stringify(pkg.attestations);
        break;
      case 'insurancePolicies':
        mappedFields[field] = JSON.stringify(pkg.insurancePolicies);
        break;
      case 'reputationSnapshot':
        mappedFields[field] = JSON.stringify(pkg.reputationSnapshot);
        break;
    }
  }

  return {
    jurisdiction,
    legalFramework: jurisdictionInfo.legalFramework,
    requiredFields: jurisdictionInfo.requiredFields,
    complianceStandard: jurisdictionInfo.complianceStandard,
    mappedFields,
  };
}

/**
 * Generates a compliance report for a specific standard.
 * Validates the ComplianceRecord and uses configurable weights.
 * Returns { standard, passed, score, gaps, details }.
 */
export function generateComplianceReport(
  compliance: ComplianceRecord,
  standard: ComplianceStandard,
  weights: ComplianceWeights = DEFAULT_WEIGHTS,
): { standard: ComplianceStandard; passed: boolean; score: number; gaps: string[]; details: Record<string, number> } {
  validateComplianceRecord(compliance);

  const requirements = COMPLIANCE_STANDARDS[standard];
  const gaps: string[] = [];

  const covenantCoverage = compliance.totalInteractions > 0
    ? compliance.covenantedInteractions / compliance.totalInteractions
    : 0;
  const breachRate = compliance.totalInteractions > 0
    ? compliance.breaches / compliance.totalInteractions
    : 0;
  const canaryPassRate = compliance.canaryTests > 0
    ? compliance.canaryPasses / compliance.canaryTests
    : 0;

  const score =
    (covenantCoverage * weights.covenantCoverage) +
    ((1 - breachRate) * weights.breachFreedom) +
    (compliance.attestationCoverage * weights.attestationCoverage) +
    (canaryPassRate * weights.canaryPassRate);

  if (score < requirements.requiredScore) {
    gaps.push(`Overall compliance score ${score.toFixed(3)} is below required ${requirements.requiredScore}`);
  }

  if (compliance.attestationCoverage < requirements.requiredAttestationCoverage) {
    gaps.push(`Attestation coverage ${compliance.attestationCoverage.toFixed(3)} is below required ${requirements.requiredAttestationCoverage}`);
  }

  if (canaryPassRate < requirements.requiredCanaryPassRate) {
    gaps.push(`Canary pass rate ${canaryPassRate.toFixed(3)} is below required ${requirements.requiredCanaryPassRate}`);
  }

  if (breachRate > 0.05) {
    gaps.push(`Breach rate ${breachRate.toFixed(3)} exceeds maximum threshold of 0.05`);
  }

  const passed = gaps.length === 0;

  return {
    standard,
    passed,
    score,
    gaps,
    details: {
      covenantCoverage,
      breachRate,
      canaryPassRate,
      attestationCoverage: compliance.attestationCoverage,
    },
  };
}

// ---------------------------------------------------------------------------
// crossJurisdictionCompliance
// ---------------------------------------------------------------------------

/**
 * Checks compliance across multiple jurisdictions simultaneously and
 * identifies conflicts between jurisdictional requirements.
 *
 * For each jurisdiction:
 * 1. Maps the package to the jurisdiction
 * 2. Checks which required fields are present
 * 3. If a known ComplianceStandard is found, runs a compliance report
 *
 * Conflicts are identified when jurisdictions have contradictory requirements
 * (e.g., one jurisdiction requires a field that another prohibits, or
 * different standards set conflicting thresholds).
 */
export function crossJurisdictionCompliance(
  pkg: LegalIdentityPackage,
  jurisdictions: string[],
  compliance: ComplianceRecord,
): CrossJurisdictionResult {
  if (!jurisdictions || jurisdictions.length === 0) {
    throw new SteleError('jurisdictions must be a non-empty array', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  for (const j of jurisdictions) {
    validateNonEmpty(j, 'jurisdiction code');
  }
  validateComplianceRecord(compliance);

  const entries: JurisdictionComplianceEntry[] = [];
  const conflicts: string[] = [];
  const recommendations: string[] = [];

  // Track all required fields per jurisdiction for conflict detection
  const requiredFieldsByJurisdiction: Record<string, string[]> = {};
  const standardsByJurisdiction: Record<string, string> = {};

  for (const jurisdiction of jurisdictions) {
    const info = jurisdictionRegistry[jurisdiction];

    if (!info) {
      entries.push({
        jurisdiction,
        standard: 'Unknown',
        passed: false,
        score: 0,
        gaps: [`Jurisdiction "${jurisdiction}" is not registered`],
        missingFields: [],
      });
      continue;
    }

    requiredFieldsByJurisdiction[jurisdiction] = info.requiredFields;
    standardsByJurisdiction[jurisdiction] = info.complianceStandard;

    // Check which required fields are missing from the package
    const packageFields = new Set<string>();
    if (pkg.agentId) packageFields.add('agentId');
    if (pkg.operatorId) packageFields.add('operatorId');
    if (pkg.complianceRecord) packageFields.add('complianceRecord');
    if (pkg.covenantHistory && pkg.covenantHistory.length > 0) packageFields.add('covenantHistory');
    if (pkg.attestations && pkg.attestations.length > 0) packageFields.add('attestations');
    if (pkg.insurancePolicies && pkg.insurancePolicies.length > 0) packageFields.add('insurancePolicies');
    if (pkg.reputationSnapshot) packageFields.add('reputationSnapshot');

    const missingFields = info.requiredFields.filter(f => !packageFields.has(f));

    // Try to run compliance report if the standard is known
    const knownStandards = Object.keys(COMPLIANCE_STANDARDS) as ComplianceStandard[];
    const matchedStandard = knownStandards.find(s => s === info.complianceStandard);

    let passed = false;
    let score = 0;
    const gaps: string[] = [];

    if (matchedStandard) {
      const report = generateComplianceReport(compliance, matchedStandard);
      passed = report.passed && missingFields.length === 0;
      score = report.score;
      gaps.push(...report.gaps);
    } else {
      gaps.push(`No compliance standard "${info.complianceStandard}" is registered for scoring`);
    }

    if (missingFields.length > 0) {
      gaps.push(`Missing required fields: ${missingFields.join(', ')}`);
      passed = false;
    }

    entries.push({
      jurisdiction,
      standard: info.complianceStandard,
      passed,
      score,
      gaps,
      missingFields,
    });
  }

  // Detect conflicts between jurisdictions
  const jurisdictionPairs: Array<[string, string]> = [];
  for (let i = 0; i < jurisdictions.length; i++) {
    for (let j = i + 1; j < jurisdictions.length; j++) {
      jurisdictionPairs.push([jurisdictions[i]!, jurisdictions[j]!]);
    }
  }

  for (const [jA, jB] of jurisdictionPairs) {
    const fieldsA = requiredFieldsByJurisdiction[jA];
    const fieldsB = requiredFieldsByJurisdiction[jB];
    if (!fieldsA || !fieldsB) continue;

    // Conflict: one jurisdiction requires a field the other does not
    // This is informational -- not a hard conflict, but worth noting
    const onlyInA = fieldsA.filter(f => !fieldsB.includes(f));
    const onlyInB = fieldsB.filter(f => !fieldsA.includes(f));

    if (onlyInA.length > 0 && onlyInB.length > 0) {
      conflicts.push(
        `${jA} and ${jB} have differing field requirements: ${jA} uniquely requires [${onlyInA.join(', ')}], ${jB} uniquely requires [${onlyInB.join(', ')}]`,
      );
    }

    // Conflict: different compliance standards with different thresholds
    const stdA = standardsByJurisdiction[jA];
    const stdB = standardsByJurisdiction[jB];
    if (stdA && stdB && stdA !== stdB) {
      const knownA = COMPLIANCE_STANDARDS[stdA as ComplianceStandard];
      const knownB = COMPLIANCE_STANDARDS[stdB as ComplianceStandard];
      if (knownA && knownB && knownA.requiredScore !== knownB.requiredScore) {
        conflicts.push(
          `${jA} (${stdA}) requires score >= ${knownA.requiredScore} while ${jB} (${stdB}) requires >= ${knownB.requiredScore}`,
        );
      }
    }
  }

  // Generate recommendations
  const failingJurisdictions = entries.filter(e => !e.passed);
  if (failingJurisdictions.length > 0) {
    recommendations.push(
      `Address compliance gaps in: ${failingJurisdictions.map(e => e.jurisdiction).join(', ')}`,
    );
  }

  const allMissingFields = new Set<string>();
  for (const entry of entries) {
    for (const f of entry.missingFields) {
      allMissingFields.add(f);
    }
  }
  if (allMissingFields.size > 0) {
    recommendations.push(
      `Provide missing data fields: ${[...allMissingFields].join(', ')}`,
    );
  }

  if (conflicts.length > 0) {
    recommendations.push(
      'Review jurisdictional conflicts and consider meeting the strictest requirements across all jurisdictions',
    );
  }

  const overallCompliant = entries.every(e => e.passed);

  return {
    overallCompliant,
    jurisdictions: entries,
    conflicts,
    recommendations,
  };
}

// ---------------------------------------------------------------------------
// auditTrailExport
// ---------------------------------------------------------------------------

/**
 * Generates a chronological audit trail from a LegalIdentityPackage.
 *
 * Combines events from:
 * - Covenant history (signed, expired, revoked events)
 * - Attestation records
 * - Compliance record (breach and canary test summary events)
 * - Insurance records (coverage changes)
 *
 * All entries are sorted by timestamp (ascending) and include a summary
 * with event counts and time range.
 */
export function auditTrailExport(
  pkg: LegalIdentityPackage,
): AuditTrailExport {
  validateNonEmpty(pkg.agentId, 'agentId');

  const entries: AuditTrailEntry[] = [];

  // Covenant events
  for (const covenant of pkg.covenantHistory) {
    const eventType = covenant.status === 'active'
      ? 'covenant-signed' as const
      : covenant.status === 'expired'
        ? 'covenant-expired' as const
        : 'covenant-revoked' as const;

    entries.push({
      timestamp: covenant.signedAt,
      eventType,
      description: `Covenant ${covenant.id} ${eventType.replace('covenant-', '')}: [${covenant.constraints.join('; ')}]`,
      sourceId: covenant.id,
      metadata: {
        constraints: covenant.constraints,
        status: covenant.status,
      },
    });
  }

  // Attestation events
  for (const attestation of pkg.attestations) {
    entries.push({
      timestamp: attestation.timestamp,
      eventType: 'attestation',
      description: `Attestation ${attestation.id} with ${attestation.counterpartyId}: ${attestation.match ? 'matched' : 'mismatched'}`,
      sourceId: attestation.id,
      metadata: {
        counterpartyId: attestation.counterpartyId,
        match: attestation.match,
      },
    });
  }

  // Compliance summary events (single aggregated entry)
  if (pkg.complianceRecord.totalInteractions > 0) {
    if (pkg.complianceRecord.breaches > 0) {
      entries.push({
        timestamp: pkg.exportedAt,
        eventType: 'breach',
        description: `${pkg.complianceRecord.breaches} breach(es) recorded across ${pkg.complianceRecord.totalInteractions} total interactions`,
        sourceId: pkg.agentId,
        metadata: {
          breaches: pkg.complianceRecord.breaches,
          totalInteractions: pkg.complianceRecord.totalInteractions,
          breachRate: pkg.complianceRecord.breaches / pkg.complianceRecord.totalInteractions,
        },
      });
    }

    if (pkg.complianceRecord.canaryTests > 0) {
      entries.push({
        timestamp: pkg.exportedAt,
        eventType: 'canary-test',
        description: `Canary testing: ${pkg.complianceRecord.canaryPasses}/${pkg.complianceRecord.canaryTests} passed (${((pkg.complianceRecord.canaryPasses / pkg.complianceRecord.canaryTests) * 100).toFixed(1)}%)`,
        sourceId: pkg.agentId,
        metadata: {
          canaryTests: pkg.complianceRecord.canaryTests,
          canaryPasses: pkg.complianceRecord.canaryPasses,
          passRate: pkg.complianceRecord.canaryPasses / pkg.complianceRecord.canaryTests,
        },
      });
    }
  }

  // Insurance events
  for (const insurance of pkg.insurancePolicies) {
    entries.push({
      timestamp: pkg.exportedAt,
      eventType: 'insurance-change',
      description: `Insurance policy ${insurance.id}: coverage ${insurance.coverage}, premium ${insurance.premium}, status ${insurance.status}`,
      sourceId: insurance.id,
      metadata: {
        coverage: insurance.coverage,
        premium: insurance.premium,
        status: insurance.status,
      },
    });
  }

  // Sort chronologically
  entries.sort((a, b) => a.timestamp - b.timestamp);

  // Build summary
  const eventCounts: Record<string, number> = {};
  for (const entry of entries) {
    eventCounts[entry.eventType] = (eventCounts[entry.eventType] ?? 0) + 1;
  }

  const timestamps = entries.map(e => e.timestamp);
  const timeRange = entries.length > 0
    ? { start: Math.min(...timestamps), end: Math.max(...timestamps) }
    : { start: 0, end: 0 };

  return {
    agentId: pkg.agentId,
    generatedAt: Date.now(),
    entries,
    summary: {
      totalEvents: entries.length,
      timeRange,
      eventCounts,
    },
  };
}

// ---------------------------------------------------------------------------
// regulatoryGapAnalysis
// ---------------------------------------------------------------------------

/**
 * Identifies gaps between the current compliance state and a target
 * regulatory standard.
 *
 * Evaluates:
 * - Overall compliance score vs. required score
 * - Attestation coverage vs. required coverage
 * - Canary pass rate vs. required pass rate
 * - Breach rate vs. maximum threshold
 * - Covenant coverage adequacy
 *
 * Returns a detailed gap analysis with severity ratings, remediation
 * suggestions, and an estimated effort level.
 */
export function regulatoryGapAnalysis(
  compliance: ComplianceRecord,
  targetStandard: ComplianceStandard,
  weights: ComplianceWeights = DEFAULT_WEIGHTS,
): RegulatoryGapAnalysisResult {
  validateComplianceRecord(compliance);

  const requirements = COMPLIANCE_STANDARDS[targetStandard];
  if (!requirements) {
    throw new SteleError(`Unknown compliance standard: "${targetStandard}"`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }

  const report = generateComplianceReport(compliance, targetStandard, weights);

  const gaps: RegulatoryGap[] = [];

  // 1. Overall score gap
  if (report.score < requirements.requiredScore) {
    const deficit = requirements.requiredScore - report.score;
    const severity: RegulatoryGap['severity'] = deficit > 0.2 ? 'critical' : deficit > 0.1 ? 'major' : 'minor';
    gaps.push({
      area: 'Overall Compliance Score',
      currentState: `Score: ${report.score.toFixed(3)}`,
      requiredState: `Score >= ${requirements.requiredScore}`,
      severity,
      remediation: `Improve overall compliance by ${(deficit * 100).toFixed(1)} percentage points. Focus on weakest contributing factors.`,
    });
  }

  // 2. Attestation coverage gap
  if (compliance.attestationCoverage < requirements.requiredAttestationCoverage) {
    const deficit = requirements.requiredAttestationCoverage - compliance.attestationCoverage;
    const severity: RegulatoryGap['severity'] = deficit > 0.2 ? 'critical' : deficit > 0.1 ? 'major' : 'minor';
    gaps.push({
      area: 'Attestation Coverage',
      currentState: `Coverage: ${(compliance.attestationCoverage * 100).toFixed(1)}%`,
      requiredState: `Coverage >= ${(requirements.requiredAttestationCoverage * 100).toFixed(1)}%`,
      severity,
      remediation: `Increase attestation coverage by ${(deficit * 100).toFixed(1)} percentage points. Add attestation to ${Math.ceil(deficit * (compliance.totalInteractions || 100))} more interactions.`,
    });
  }

  // 3. Canary pass rate gap
  const canaryPassRate = compliance.canaryTests > 0
    ? compliance.canaryPasses / compliance.canaryTests
    : 0;
  if (canaryPassRate < requirements.requiredCanaryPassRate) {
    const deficit = requirements.requiredCanaryPassRate - canaryPassRate;
    const severity: RegulatoryGap['severity'] = deficit > 0.15 ? 'critical' : deficit > 0.05 ? 'major' : 'minor';
    gaps.push({
      area: 'Canary Test Pass Rate',
      currentState: `Pass rate: ${(canaryPassRate * 100).toFixed(1)}%`,
      requiredState: `Pass rate >= ${(requirements.requiredCanaryPassRate * 100).toFixed(1)}%`,
      severity,
      remediation: `Improve canary test pass rate by ${(deficit * 100).toFixed(1)} percentage points. Investigate and fix ${compliance.canaryTests - compliance.canaryPasses} failing canary tests.`,
    });
  }

  // 4. Breach rate gap
  const breachRate = compliance.totalInteractions > 0
    ? compliance.breaches / compliance.totalInteractions
    : 0;
  if (breachRate > 0.05) {
    const severity: RegulatoryGap['severity'] = breachRate > 0.15 ? 'critical' : breachRate > 0.1 ? 'major' : 'minor';
    gaps.push({
      area: 'Breach Rate',
      currentState: `Breach rate: ${(breachRate * 100).toFixed(1)}%`,
      requiredState: 'Breach rate <= 5.0%',
      severity,
      remediation: `Reduce breach rate by ${((breachRate - 0.05) * 100).toFixed(1)} percentage points. Implement additional safeguards and constraint enforcement.`,
    });
  }

  // 5. Covenant coverage gap
  const covenantCoverage = compliance.totalInteractions > 0
    ? compliance.covenantedInteractions / compliance.totalInteractions
    : 0;
  if (covenantCoverage < 0.9) {
    const deficit = 0.9 - covenantCoverage;
    const severity: RegulatoryGap['severity'] = deficit > 0.3 ? 'critical' : deficit > 0.15 ? 'major' : 'minor';
    gaps.push({
      area: 'Covenant Coverage',
      currentState: `Coverage: ${(covenantCoverage * 100).toFixed(1)}%`,
      requiredState: 'Coverage >= 90.0%',
      severity,
      remediation: `Add covenants to ${Math.ceil(deficit * compliance.totalInteractions)} more interactions to reach 90% coverage.`,
    });
  }

  // Calculate readiness percentage
  const totalChecks = 5;
  const passedChecks = totalChecks - gaps.length;
  const readinessPercentage = (passedChecks / totalChecks) * 100;

  const criticalGapCount = gaps.filter(g => g.severity === 'critical').length;

  // Estimate remediation effort
  let estimatedRemediationEffort: RegulatoryGapAnalysisResult['estimatedRemediationEffort'];
  if (criticalGapCount >= 2 || gaps.length >= 4) {
    estimatedRemediationEffort = 'high';
  } else if (criticalGapCount >= 1 || gaps.length >= 2) {
    estimatedRemediationEffort = 'medium';
  } else {
    estimatedRemediationEffort = 'low';
  }

  return {
    targetStandard,
    currentScore: report.score,
    requiredScore: requirements.requiredScore,
    gaps,
    readinessPercentage,
    criticalGapCount,
    estimatedRemediationEffort,
  };
}

// ---------------------------------------------------------------------------
// Nonlinear Compliance Surface
// ---------------------------------------------------------------------------

/** A dependency between two compliance requirements. */
export interface RequirementDependency {
  /** Requirement that depends on another. */
  dependentRequirement: string;
  /** Requirement that the dependent relies on. */
  prerequisiteRequirement: string;
  /** How much the dependent's effective score is multiplied by the prerequisite's score (0-1). */
  couplingStrength: number;
}

/** Individual requirement score entry. */
export interface RequirementScore {
  name: string;
  rawScore: number;
  effectiveScore: number;
  dependsOn: string[];
}

/** Result of a nonlinear compliance surface evaluation. */
export interface ComplianceSurfaceResult {
  /** Overall nonlinear compliance score. */
  overallScore: number;
  /** Per-requirement effective scores (accounting for dependencies). */
  requirementScores: RequirementScore[];
  /** Pairs of requirements with the strongest coupling effects. */
  criticalDependencies: Array<{ from: string; to: string; impact: number }>;
  /** Comparison with the simple weighted-average score. */
  linearBaselineScore: number;
  /** How much the nonlinear model diverges from the linear model. */
  nonlinearDivergence: number;
}

/**
 * Nonlinear compliance scoring model that accounts for interaction effects
 * between requirements.
 *
 * In the real world, compliance requirements are not independent: if a
 * foundational requirement (e.g., access control) fails, dependent requirements
 * (e.g., data encryption at rest) lose much of their effectiveness. This class
 * models these dependencies as a directed graph with coupling strengths.
 */
export class ComplianceSurface {
  private readonly dependencies: RequirementDependency[] = [];
  private readonly requirementNames: Set<string> = new Set();

  /**
   * Register a requirement name.
   */
  addRequirement(name: string): void {
    if (!name || name.trim() === '') {
      throw new SteleError(
        'Requirement name must be a non-empty string',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.requirementNames.add(name);
  }

  /**
   * Add a dependency between two requirements.
   * @param dep The dependency definition.
   */
  addDependency(dep: RequirementDependency): void {
    if (!dep.dependentRequirement || dep.dependentRequirement.trim() === '') {
      throw new SteleError(
        'dependentRequirement must be a non-empty string',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!dep.prerequisiteRequirement || dep.prerequisiteRequirement.trim() === '') {
      throw new SteleError(
        'prerequisiteRequirement must be a non-empty string',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!Number.isFinite(dep.couplingStrength) || dep.couplingStrength < 0 || dep.couplingStrength > 1) {
      throw new SteleError(
        'couplingStrength must be between 0 and 1',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.requirementNames.add(dep.dependentRequirement);
    this.requirementNames.add(dep.prerequisiteRequirement);
    this.dependencies.push({ ...dep });
  }

  /**
   * Evaluate compliance scores with nonlinear dependency propagation.
   *
   * For each requirement with dependencies, the effective score is:
   *   effectiveScore = rawScore * product_over_deps(1 - coupling * (1 - prerequisite_effective_score))
   *
   * This means:
   * - If a prerequisite has effective score 1.0, no penalty (full factor = 1)
   * - If a prerequisite has effective score 0.0, penalty = coupling strength
   * - Intermediate values are linear interpolation
   *
   * Dependencies are resolved iteratively (up to 10 passes) for transitive chains.
   *
   * @param rawScores Map of requirement name to raw compliance score (0-1).
   */
  evaluate(rawScores: Record<string, number>): ComplianceSurfaceResult {
    // Validate all requirement names have scores
    for (const name of this.requirementNames) {
      if (!(name in rawScores)) {
        throw new SteleError(
          `Missing score for requirement "${name}"`,
          SteleErrorCode.PROTOCOL_INVALID_INPUT,
        );
      }
      const score = rawScores[name]!;
      if (!Number.isFinite(score) || score < 0 || score > 1) {
        throw new SteleError(
          `Score for "${name}" must be between 0 and 1, got ${score}`,
          SteleErrorCode.PROTOCOL_INVALID_INPUT,
        );
      }
    }

    // Build adjacency: dependentRequirement -> list of (prerequisite, coupling)
    const adj = new Map<string, Array<{ prereq: string; coupling: number }>>();
    for (const dep of this.dependencies) {
      if (!adj.has(dep.dependentRequirement)) {
        adj.set(dep.dependentRequirement, []);
      }
      adj.get(dep.dependentRequirement)!.push({
        prereq: dep.prerequisiteRequirement,
        coupling: dep.couplingStrength,
      });
    }

    // Initialize effective scores from raw scores
    const effective: Record<string, number> = {};
    for (const name of this.requirementNames) {
      effective[name] = rawScores[name]!;
    }

    // Iterative propagation (handles transitive dependencies)
    const MAX_ITERATIONS = 10;
    const CONVERGENCE_THRESHOLD = 1e-6;
    for (let iter = 0; iter < MAX_ITERATIONS; iter++) {
      let maxChange = 0;

      for (const name of this.requirementNames) {
        const deps = adj.get(name);
        if (!deps || deps.length === 0) continue;

        let factor = 1;
        for (const { prereq, coupling } of deps) {
          const prereqScore = effective[prereq]!;
          // Penalty factor: 1 when prereq is perfect, (1 - coupling) when prereq is zero
          factor *= 1 - coupling * (1 - prereqScore);
        }

        const newScore = rawScores[name]! * factor;
        const change = Math.abs(newScore - effective[name]!);
        if (change > maxChange) maxChange = change;
        effective[name] = newScore;
      }

      if (maxChange < CONVERGENCE_THRESHOLD) break;
    }

    // Build per-requirement results
    const requirementScores: RequirementScore[] = [];
    for (const name of this.requirementNames) {
      const deps = adj.get(name);
      requirementScores.push({
        name,
        rawScore: rawScores[name]!,
        effectiveScore: effective[name]!,
        dependsOn: deps ? deps.map(d => d.prereq) : [],
      });
    }

    // Identify critical dependencies (largest impact = largest score reduction)
    const criticalDependencies: Array<{ from: string; to: string; impact: number }> = [];
    for (const dep of this.dependencies) {
      const raw = rawScores[dep.dependentRequirement]!;
      const eff = effective[dep.dependentRequirement]!;
      criticalDependencies.push({
        from: dep.prerequisiteRequirement,
        to: dep.dependentRequirement,
        impact: raw - eff,
      });
    }
    criticalDependencies.sort((a, b) => b.impact - a.impact);

    // Overall nonlinear score = average of effective scores
    const names = [...this.requirementNames];
    const overallScore = names.length > 0
      ? names.reduce((s, n) => s + effective[n]!, 0) / names.length
      : 0;

    // Linear baseline = average of raw scores
    const linearBaselineScore = names.length > 0
      ? names.reduce((s, n) => s + rawScores[n]!, 0) / names.length
      : 0;

    return {
      overallScore,
      requirementScores,
      criticalDependencies,
      linearBaselineScore,
      nonlinearDivergence: linearBaselineScore - overallScore,
    };
  }
}

// ---------------------------------------------------------------------------
// Temporal Compliance Tracking
// ---------------------------------------------------------------------------

/** A timestamped compliance score observation. */
export interface ComplianceObservation {
  timestamp: number;
  score: number;
  label?: string;
}

/** Result of compliance trajectory analysis. */
export interface ComplianceTrajectoryResult {
  /** Compliance scores over time. */
  observations: ComplianceObservation[];
  /** Least-squares trend line slope (positive = improving). */
  trendSlope: number;
  /** Least-squares trend line intercept. */
  trendIntercept: number;
  /** R-squared (goodness of fit) for the trend line. */
  rSquared: number;
  /** Whether compliance degradation is detected. */
  degradationDetected: boolean;
  /** Estimated time (as timestamp) when score will breach the threshold. */
  estimatedBreachTime: number | null;
  /** The threshold used for breach detection. */
  breachThreshold: number;
  /** Rate of change per unit time. */
  rateOfChange: number;
}

/**
 * Tracks compliance scores over time, computes trend lines using
 * least-squares regression, and detects compliance degradation
 * before threshold breaches occur.
 */
export class ComplianceTrajectory {
  private readonly observations: ComplianceObservation[] = [];
  private readonly breachThreshold: number;

  /**
   * @param breachThreshold Compliance score below which a breach is flagged (default: 0.7).
   */
  constructor(breachThreshold = 0.7) {
    if (!Number.isFinite(breachThreshold) || breachThreshold < 0 || breachThreshold > 1) {
      throw new SteleError(
        'breachThreshold must be between 0 and 1',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.breachThreshold = breachThreshold;
  }

  /**
   * Record a compliance observation.
   */
  record(obs: ComplianceObservation): void {
    if (!Number.isFinite(obs.score) || obs.score < 0 || obs.score > 1) {
      throw new SteleError(
        'Compliance score must be between 0 and 1',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!Number.isFinite(obs.timestamp)) {
      throw new SteleError(
        'Timestamp must be a finite number',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.observations.push({ ...obs });
  }

  /**
   * Analyze the compliance trajectory.
   *
   * Computes a least-squares trend line and estimates when (if ever)
   * the compliance score will breach the threshold.
   *
   * @throws {SteleError} if fewer than 2 observations are recorded.
   */
  analyze(): ComplianceTrajectoryResult {
    if (this.observations.length < 2) {
      throw new SteleError(
        'Need at least 2 observations for trajectory analysis',
        SteleErrorCode.PROTOCOL_COMPUTATION_FAILED,
      );
    }

    const sorted = [...this.observations].sort((a, b) => a.timestamp - b.timestamp);
    const timestamps = sorted.map(o => o.timestamp);
    const scores = sorted.map(o => o.score);

    // Least-squares linear regression: score = intercept + slope * timestamp
    const n = sorted.length;
    let sumT = 0, sumS = 0, sumTS = 0, sumT2 = 0;
    for (let i = 0; i < n; i++) {
      sumT += timestamps[i]!;
      sumS += scores[i]!;
      sumTS += timestamps[i]! * scores[i]!;
      sumT2 += timestamps[i]! * timestamps[i]!;
    }

    const denom = n * sumT2 - sumT * sumT;
    let slope: number, intercept: number;
    if (Math.abs(denom) < 1e-12) {
      slope = 0;
      intercept = sumS / n;
    } else {
      slope = (n * sumTS - sumT * sumS) / denom;
      intercept = (sumS - slope * sumT) / n;
    }

    // R-squared
    const meanS = sumS / n;
    let ssRes = 0, ssTot = 0;
    for (let i = 0; i < n; i++) {
      const predicted = intercept + slope * timestamps[i]!;
      ssRes += (scores[i]! - predicted) ** 2;
      ssTot += (scores[i]! - meanS) ** 2;
    }
    const rSquared = ssTot > 0 ? 1 - ssRes / ssTot : 0;

    // Degradation detection
    const degradationDetected = slope < -1e-10;

    // Estimate breach time: solve intercept + slope * t = breachThreshold
    let estimatedBreachTime: number | null = null;
    if (slope < 0) {
      const lastTimestamp = timestamps[timestamps.length - 1]!;
      const lastPredicted = intercept + slope * lastTimestamp;
      if (lastPredicted > this.breachThreshold) {
        const breachT = (this.breachThreshold - intercept) / slope;
        if (breachT > lastTimestamp) {
          estimatedBreachTime = breachT;
        }
      }
    }

    // Rate of change per unit time is just the slope
    return {
      observations: sorted,
      trendSlope: slope,
      trendIntercept: intercept,
      rSquared,
      degradationDetected,
      estimatedBreachTime,
      breachThreshold: this.breachThreshold,
      rateOfChange: slope,
    };
  }

  /** Return the current number of observations. */
  getObservationCount(): number {
    return this.observations.length;
  }
}

// ---------------------------------------------------------------------------
// Gradient-Based Gap Remediation
// ---------------------------------------------------------------------------

/** A single remediation action with priority. */
export interface RemediationAction {
  /** Requirement to improve. */
  requirement: string;
  /** Current score. */
  currentScore: number;
  /** Estimated overall compliance improvement if this requirement reaches target. */
  expectedImpact: number;
  /** The compliance gradient for this requirement. */
  gradient: number;
  /** Priority rank (1 = highest priority). */
  priority: number;
  /** Suggested target score. */
  targetScore: number;
}

/** Result of a remediation planning analysis. */
export interface RemediationPlanResult {
  /** Ordered list of remediation actions (highest impact first). */
  actions: RemediationAction[];
  /** Current overall compliance score. */
  currentOverallScore: number;
  /** Projected overall score if all actions are completed. */
  projectedOverallScore: number;
  /** Maximum achievable improvement. */
  maxImprovement: number;
}

/**
 * Computes the compliance gradient (which requirement improvements yield
 * the most overall compliance improvement) and generates prioritized
 * remediation plans.
 *
 * Uses numerical differentiation on the compliance surface to determine
 * the sensitivity of overall compliance to each requirement, then ranks
 * requirements by their improvement potential.
 */
export class RemediationPlanner {
  private readonly surface: ComplianceSurface;

  /**
   * @param surface The compliance surface model to use for gradient computation.
   */
  constructor(surface: ComplianceSurface) {
    this.surface = surface;
  }

  /**
   * Generate a prioritized remediation plan.
   *
   * For each requirement, numerically estimates the gradient of overall
   * compliance with respect to that requirement's score. Requirements
   * with the highest gradients are prioritized first.
   *
   * @param currentScores Current per-requirement compliance scores (0-1).
   * @param targetImprovement How much to improve each requirement by in the plan (default: 0.1).
   */
  plan(currentScores: Record<string, number>, targetImprovement = 0.1): RemediationPlanResult {
    if (targetImprovement <= 0 || targetImprovement > 1) {
      throw new SteleError(
        'targetImprovement must be between 0 (exclusive) and 1 (inclusive)',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    // Evaluate current state
    const baseline = this.surface.evaluate(currentScores);
    const requirementNames = Object.keys(currentScores);

    // Compute gradient for each requirement via numerical differentiation
    const epsilon = 0.01;
    const gradients: Array<{ name: string; gradient: number }> = [];

    for (const name of requirementNames) {
      const perturbed = { ...currentScores };
      const newScore = Math.min(1, currentScores[name]! + epsilon);
      perturbed[name] = newScore;

      try {
        const perturbedResult = this.surface.evaluate(perturbed);
        const gradient = (perturbedResult.overallScore - baseline.overallScore) / epsilon;
        gradients.push({ name, gradient });
      } catch {
        // If evaluation fails for perturbed state, assign zero gradient
        gradients.push({ name, gradient: 0 });
      }
    }

    // Sort by gradient magnitude (descending) for priority
    gradients.sort((a, b) => b.gradient - a.gradient);

    // Build remediation actions
    const actions: RemediationAction[] = [];
    let projectedOverall = baseline.overallScore;

    for (let i = 0; i < gradients.length; i++) {
      const { name, gradient } = gradients[i]!;
      const current = currentScores[name]!;
      const target = Math.min(1, current + targetImprovement);
      const expectedImpact = gradient * (target - current);

      if (current < 1 && gradient > 0) {
        actions.push({
          requirement: name,
          currentScore: current,
          expectedImpact,
          gradient,
          priority: i + 1,
          targetScore: target,
        });
        projectedOverall += expectedImpact;
      }
    }

    return {
      actions,
      currentOverallScore: baseline.overallScore,
      projectedOverallScore: Math.min(1, projectedOverall),
      maxImprovement: Math.min(1, projectedOverall) - baseline.overallScore,
    };
  }
}

// ---------------------------------------------------------------------------
// Jurisdiction Conflict Resolution
// ---------------------------------------------------------------------------

/** A regulatory requirement from a specific jurisdiction. */
export interface JurisdictionalRequirement {
  /** Jurisdiction code (e.g., 'US', 'EU'). */
  jurisdiction: string;
  /** Requirement identifier. */
  requirementId: string;
  /** Human-readable description. */
  description: string;
  /** The required score or threshold (0-1). */
  threshold: number;
  /** Category/domain of the requirement. */
  category: string;
}

/** A detected conflict between jurisdictional requirements. */
export interface JurisdictionConflict {
  /** First conflicting requirement. */
  requirementA: JurisdictionalRequirement;
  /** Second conflicting requirement. */
  requirementB: JurisdictionalRequirement;
  /** Type of conflict detected. */
  conflictType: 'threshold-mismatch' | 'contradictory' | 'overlap';
  /** Human-readable conflict description. */
  description: string;
  /** Severity of the conflict. */
  severity: 'high' | 'medium' | 'low';
}

/** Strategy for resolving jurisdiction conflicts. */
export type ResolutionStrategy = 'strictest-wins' | 'lex-specialis' | 'proportionality';

/** Resolution result for a single conflict. */
export interface ConflictResolution {
  conflict: JurisdictionConflict;
  strategy: ResolutionStrategy;
  resolvedThreshold: number;
  resolvedRequirement: string;
  rationale: string;
}

/** Result of jurisdiction conflict resolution analysis. */
export interface JurisdictionConflictResult {
  /** All detected conflicts. */
  conflicts: JurisdictionConflict[];
  /** Resolutions applied (one per conflict). */
  resolutions: ConflictResolution[];
  /** Number of unresolvable conflicts. */
  unresolvableCount: number;
  /** Harmonized requirements (after conflict resolution). */
  harmonizedRequirements: JurisdictionalRequirement[];
}

/**
 * Detects conflicting requirements across jurisdictions and applies
 * resolution strategies.
 *
 * Supported resolution strategies:
 * - **strictest-wins**: Always adopt the higher threshold.
 * - **lex-specialis**: More specific requirements override general ones.
 * - **proportionality**: Balance by taking the geometric mean of thresholds.
 */
export class JurisdictionConflictResolver {
  private readonly requirements: JurisdictionalRequirement[] = [];

  /**
   * Add a jurisdictional requirement.
   */
  addRequirement(req: JurisdictionalRequirement): void {
    if (!req.jurisdiction || req.jurisdiction.trim() === '') {
      throw new SteleError(
        'jurisdiction must be a non-empty string',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!req.requirementId || req.requirementId.trim() === '') {
      throw new SteleError(
        'requirementId must be a non-empty string',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!Number.isFinite(req.threshold) || req.threshold < 0 || req.threshold > 1) {
      throw new SteleError(
        'threshold must be between 0 and 1',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!req.category || req.category.trim() === '') {
      throw new SteleError(
        'category must be a non-empty string',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.requirements.push({ ...req });
  }

  /**
   * Detect conflicts and apply a resolution strategy.
   *
   * Conflicts are detected between requirements from different jurisdictions
   * that share the same category but have different thresholds.
   *
   * @param strategy Resolution strategy to apply (default: 'strictest-wins').
   */
  resolve(strategy: ResolutionStrategy = 'strictest-wins'): JurisdictionConflictResult {
    if (!['strictest-wins', 'lex-specialis', 'proportionality'].includes(strategy)) {
      throw new SteleError(
        `Unknown resolution strategy: "${strategy}"`,
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    // Group requirements by category
    const byCategory = new Map<string, JurisdictionalRequirement[]>();
    for (const req of this.requirements) {
      if (!byCategory.has(req.category)) {
        byCategory.set(req.category, []);
      }
      byCategory.get(req.category)!.push(req);
    }

    const conflicts: JurisdictionConflict[] = [];
    const resolutions: ConflictResolution[] = [];
    const harmonized = new Map<string, JurisdictionalRequirement>();

    for (const [category, reqs] of byCategory) {
      // Detect pairwise conflicts within each category
      for (let i = 0; i < reqs.length; i++) {
        for (let j = i + 1; j < reqs.length; j++) {
          const a = reqs[i]!;
          const b = reqs[j]!;

          if (a.jurisdiction === b.jurisdiction) continue;

          const thresholdDiff = Math.abs(a.threshold - b.threshold);
          if (thresholdDiff < 0.001) continue; // No meaningful conflict

          const severity: JurisdictionConflict['severity'] =
            thresholdDiff > 0.2 ? 'high' : thresholdDiff > 0.1 ? 'medium' : 'low';

          const conflict: JurisdictionConflict = {
            requirementA: a,
            requirementB: b,
            conflictType: 'threshold-mismatch',
            description: `${a.jurisdiction}:${a.requirementId} requires threshold ${a.threshold} but ${b.jurisdiction}:${b.requirementId} requires ${b.threshold} for category "${category}"`,
            severity,
          };
          conflicts.push(conflict);

          // Apply resolution strategy
          const resolution = this.applyStrategy(conflict, strategy);
          resolutions.push(resolution);
        }
      }

      // Build harmonized requirement for this category
      if (reqs.length > 0) {
        const resolved = this.harmonizeCategory(reqs, strategy);
        harmonized.set(category, resolved);
      }
    }

    // Add uncategorized/unconflicted requirements
    for (const req of this.requirements) {
      if (!harmonized.has(req.category)) {
        harmonized.set(req.category, { ...req });
      }
    }

    return {
      conflicts,
      resolutions,
      unresolvableCount: 0, // All strategies produce a resolution
      harmonizedRequirements: [...harmonized.values()],
    };
  }

  /** Get all registered requirements. */
  getRequirements(): JurisdictionalRequirement[] {
    return this.requirements.map(r => ({ ...r }));
  }

  private applyStrategy(conflict: JurisdictionConflict, strategy: ResolutionStrategy): ConflictResolution {
    const a = conflict.requirementA;
    const b = conflict.requirementB;

    switch (strategy) {
      case 'strictest-wins': {
        const winner = a.threshold >= b.threshold ? a : b;
        return {
          conflict,
          strategy,
          resolvedThreshold: winner.threshold,
          resolvedRequirement: winner.requirementId,
          rationale: `Adopted strictest threshold ${winner.threshold} from ${winner.jurisdiction} (${winner.requirementId})`,
        };
      }
      case 'lex-specialis': {
        // More specific = longer description (heuristic for specificity)
        const moreSpecific = a.description.length >= b.description.length ? a : b;
        return {
          conflict,
          strategy,
          resolvedThreshold: moreSpecific.threshold,
          resolvedRequirement: moreSpecific.requirementId,
          rationale: `Applied lex specialis: more specific requirement ${moreSpecific.requirementId} from ${moreSpecific.jurisdiction} prevails`,
        };
      }
      case 'proportionality': {
        // Geometric mean balances both jurisdictions
        const geoMean = Math.sqrt(a.threshold * b.threshold);
        return {
          conflict,
          strategy,
          resolvedThreshold: geoMean,
          resolvedRequirement: `${a.requirementId}+${b.requirementId}`,
          rationale: `Proportionality test: geometric mean ${geoMean.toFixed(4)} of ${a.jurisdiction} (${a.threshold}) and ${b.jurisdiction} (${b.threshold})`,
        };
      }
    }
  }

  private harmonizeCategory(
    reqs: JurisdictionalRequirement[],
    strategy: ResolutionStrategy,
  ): JurisdictionalRequirement {
    const base = reqs[0]!;

    let resolvedThreshold: number;
    switch (strategy) {
      case 'strictest-wins':
        resolvedThreshold = Math.max(...reqs.map(r => r.threshold));
        break;
      case 'lex-specialis': {
        const mostSpecific = reqs.reduce((best, r) =>
          r.description.length > best.description.length ? r : best, reqs[0]!);
        resolvedThreshold = mostSpecific.threshold;
        break;
      }
      case 'proportionality': {
        const product = reqs.reduce((p, r) => p * r.threshold, 1);
        resolvedThreshold = Math.pow(product, 1 / reqs.length);
        break;
      }
    }

    return {
      jurisdiction: reqs.map(r => r.jurisdiction).join('+'),
      requirementId: `harmonized:${base.category}`,
      description: `Harmonized requirement for ${base.category} across ${reqs.map(r => r.jurisdiction).join(', ')}`,
      threshold: resolvedThreshold,
      category: base.category,
    };
  }
}

// ---------------------------------------------------------------------------
// Regulatory Change Impact Analysis
// ---------------------------------------------------------------------------

/** A proposed regulatory change. */
export interface RegulatoryChange {
  /** Identifier for this change. */
  changeId: string;
  /** Human-readable description of the change. */
  description: string;
  /** Jurisdiction introducing the change. */
  jurisdiction: string;
  /** Compliance standard being modified. */
  affectedStandard: ComplianceStandard;
  /** New required score threshold (null if unchanged). */
  newRequiredScore: number | null;
  /** New attestation coverage requirement (null if unchanged). */
  newAttestationCoverage: number | null;
  /** New canary pass rate requirement (null if unchanged). */
  newCanaryPassRate: number | null;
}

/** Impact on a specific covenant. */
export interface CovenantImpact {
  covenantId: string;
  /** Whether this covenant would still be compliant after the change. */
  compliantAfterChange: boolean;
  /** Score gap (negative = deficit). */
  scoreGap: number;
  /** Specific areas affected. */
  affectedAreas: string[];
}

/** Result of a regulatory impact analysis. */
export interface RegulatoryImpactResult {
  /** The proposed change analyzed. */
  change: RegulatoryChange;
  /** Current compliance status. */
  currentlyCompliant: boolean;
  /** Compliance status after the proposed change. */
  compliantAfterChange: boolean;
  /** Current compliance score. */
  currentScore: number;
  /** Required score after the change. */
  requiredScoreAfterChange: number;
  /** Score deficit (negative = below threshold). */
  scoreDeficit: number;
  /** Impacted covenants. */
  covenantImpacts: CovenantImpact[];
  /** Remediation recommendations. */
  recommendations: string[];
  /** Risk level of the change. */
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
}

/**
 * Models the impact of proposed regulatory changes on current compliance
 * posture, identifying which covenants would be affected and how.
 *
 * Simulates the effect of changed thresholds, coverage requirements,
 * and pass rates without actually modifying any data.
 */
export class RegulatoryImpactAnalyzer {
  /**
   * Analyze the impact of a proposed regulatory change.
   *
   * @param change The proposed regulatory change.
   * @param currentCompliance Current compliance record.
   * @param covenants Current covenants for impact assessment.
   * @param weights Compliance weights to use for scoring (default weights used if omitted).
   */
  analyze(
    change: RegulatoryChange,
    currentCompliance: ComplianceRecord,
    covenants: CovenantRecord[] = [],
    weights: ComplianceWeights = DEFAULT_WEIGHTS,
  ): RegulatoryImpactResult {
    if (!change.changeId || change.changeId.trim() === '') {
      throw new SteleError(
        'changeId must be a non-empty string',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!change.affectedStandard) {
      throw new SteleError(
        'affectedStandard must be specified',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    validateComplianceRecord(currentCompliance);

    // Get current standard requirements
    const currentStandard = COMPLIANCE_STANDARDS[change.affectedStandard];
    if (!currentStandard) {
      throw new SteleError(
        `Unknown compliance standard: "${change.affectedStandard}"`,
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    // Compute current compliance
    const currentReport = generateComplianceReport(currentCompliance, change.affectedStandard, weights);

    // Compute effective new requirements
    const newRequiredScore = change.newRequiredScore ?? currentStandard.requiredScore;
    const newAttestationCoverage = change.newAttestationCoverage ?? currentStandard.requiredAttestationCoverage;
    const newCanaryPassRate = change.newCanaryPassRate ?? currentStandard.requiredCanaryPassRate;

    // Assess compliance under new requirements
    const canaryPassRate = currentCompliance.canaryTests > 0
      ? currentCompliance.canaryPasses / currentCompliance.canaryTests
      : 0;

    const gaps: string[] = [];
    if (currentReport.score < newRequiredScore) {
      gaps.push(`Overall score ${currentReport.score.toFixed(3)} below new threshold ${newRequiredScore}`);
    }
    if (currentCompliance.attestationCoverage < newAttestationCoverage) {
      gaps.push(`Attestation coverage ${currentCompliance.attestationCoverage.toFixed(3)} below new requirement ${newAttestationCoverage}`);
    }
    if (canaryPassRate < newCanaryPassRate) {
      gaps.push(`Canary pass rate ${canaryPassRate.toFixed(3)} below new requirement ${newCanaryPassRate}`);
    }

    const compliantAfterChange = gaps.length === 0;
    const scoreDeficit = currentReport.score - newRequiredScore;

    // Covenant-level impact analysis
    const covenantImpacts: CovenantImpact[] = [];
    for (const covenant of covenants) {
      const affectedAreas: string[] = [];

      // Check if the covenant's constraints would be impacted
      if (change.newRequiredScore !== null && change.newRequiredScore > currentStandard.requiredScore) {
        affectedAreas.push('higher-score-threshold');
      }
      if (change.newAttestationCoverage !== null && change.newAttestationCoverage > currentStandard.requiredAttestationCoverage) {
        affectedAreas.push('stricter-attestation');
      }
      if (change.newCanaryPassRate !== null && change.newCanaryPassRate > currentStandard.requiredCanaryPassRate) {
        affectedAreas.push('stricter-canary-testing');
      }

      covenantImpacts.push({
        covenantId: covenant.id,
        compliantAfterChange: affectedAreas.length === 0 || compliantAfterChange,
        scoreGap: scoreDeficit,
        affectedAreas,
      });
    }

    // Generate recommendations
    const recommendations: string[] = [];
    if (!compliantAfterChange) {
      if (scoreDeficit < 0) {
        recommendations.push(
          `Improve overall compliance score by ${Math.abs(scoreDeficit).toFixed(3)} points to meet new threshold of ${newRequiredScore}`,
        );
      }
      if (currentCompliance.attestationCoverage < newAttestationCoverage) {
        recommendations.push(
          `Increase attestation coverage from ${(currentCompliance.attestationCoverage * 100).toFixed(1)}% to ${(newAttestationCoverage * 100).toFixed(1)}%`,
        );
      }
      if (canaryPassRate < newCanaryPassRate) {
        recommendations.push(
          `Improve canary pass rate from ${(canaryPassRate * 100).toFixed(1)}% to ${(newCanaryPassRate * 100).toFixed(1)}%`,
        );
      }
    }

    // Risk level
    let riskLevel: RegulatoryImpactResult['riskLevel'];
    if (compliantAfterChange) {
      riskLevel = 'none';
    } else if (Math.abs(scoreDeficit) > 0.2) {
      riskLevel = 'critical';
    } else if (Math.abs(scoreDeficit) > 0.1) {
      riskLevel = 'high';
    } else if (Math.abs(scoreDeficit) > 0.05) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    return {
      change,
      currentlyCompliant: currentReport.passed,
      compliantAfterChange,
      currentScore: currentReport.score,
      requiredScoreAfterChange: newRequiredScore,
      scoreDeficit,
      covenantImpacts,
      recommendations,
      riskLevel,
    };
  }

  /**
   * Analyze multiple regulatory changes simultaneously to understand
   * their combined effect.
   *
   * @param changes List of proposed changes.
   * @param currentCompliance Current compliance record.
   * @param covenants Current covenants.
   * @param weights Compliance weights.
   */
  analyzeMultiple(
    changes: RegulatoryChange[],
    currentCompliance: ComplianceRecord,
    covenants: CovenantRecord[] = [],
    weights: ComplianceWeights = DEFAULT_WEIGHTS,
  ): {
    individualResults: RegulatoryImpactResult[];
    combinedRiskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
    totalRecommendations: string[];
  } {
    if (changes.length === 0) {
      throw new SteleError(
        'Must provide at least one regulatory change',
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    const individualResults: RegulatoryImpactResult[] = [];
    const allRecommendations = new Set<string>();

    for (const change of changes) {
      const result = this.analyze(change, currentCompliance, covenants, weights);
      individualResults.push(result);
      for (const rec of result.recommendations) {
        allRecommendations.add(rec);
      }
    }

    // Combined risk = worst individual risk
    const riskOrder: Array<RegulatoryImpactResult['riskLevel']> = ['none', 'low', 'medium', 'high', 'critical'];
    let worstRiskIdx = 0;
    for (const result of individualResults) {
      const idx = riskOrder.indexOf(result.riskLevel);
      if (idx > worstRiskIdx) worstRiskIdx = idx;
    }

    return {
      individualResults,
      combinedRiskLevel: riskOrder[worstRiskIdx]!,
      totalRecommendations: [...allRecommendations],
    };
  }
}

// ---------------------------------------------------------------------------
// Compliance Autopilot
// ---------------------------------------------------------------------------

/** Configuration for continuous compliance monitoring. */
export interface ComplianceMonitorConfig {
  frameworks: string[]; // e.g., ['GDPR', 'SOC2', 'EU_AI_ACT']
  checkIntervalMs: number; // default 3600000 (1 hour)
  alertThreshold: number; // score below which alerts fire (default 0.7)
  autoReport: boolean; // generate reports automatically
  operationalBudget?: number; // total operational budget for cost calculation
}

/** A point-in-time compliance snapshot. */
export interface ComplianceSnapshot {
  timestamp: number;
  overallScore: number; // 0-1
  frameworkScores: Record<string, number>;
  alerts: ComplianceAlert[];
  costAsPercentOfBudget?: number;
}

/** An alert raised when compliance scores are below threshold or trending down. */
export interface ComplianceAlert {
  framework: string;
  severity: 'info' | 'warning' | 'critical';
  message: string;
  preViolation: boolean; // true if detecting trend toward violation
  currentScore: number;
  projectedScore: number; // where score is heading
}

/** Trajectory analysis across multiple compliance snapshots. */
export interface ComplianceAutopilotTrajectory {
  snapshots: ComplianceSnapshot[];
  trend: 'improving' | 'stable' | 'declining';
  projectedDaysToViolation: number | null; // null if not declining
  recommendations: string[];
}

/**
 * Create a compliance monitor configuration with sensible defaults.
 *
 * @param config - Partial configuration to override defaults.
 * @returns A full ComplianceMonitorConfig with defaults applied.
 */
export function createComplianceMonitor(
  config: Partial<ComplianceMonitorConfig>,
): ComplianceMonitorConfig {
  return {
    frameworks: config.frameworks ?? ['GDPR'],
    checkIntervalMs: config.checkIntervalMs ?? 3600000,
    alertThreshold: config.alertThreshold ?? 0.7,
    autoReport: config.autoReport ?? true,
    operationalBudget: config.operationalBudget,
  };
}

/**
 * Take a compliance snapshot given current framework scores.
 *
 * Generates alerts for any framework below the alert threshold.
 * Pre-violation alerts are generated when a score is above the threshold
 * but close to it (within 0.1).
 *
 * @param config - The compliance monitor configuration.
 * @param currentScores - Current compliance scores per framework.
 * @returns A compliance snapshot with alerts.
 */
export function takeSnapshot(
  config: ComplianceMonitorConfig,
  currentScores: Record<string, number>,
): ComplianceSnapshot {
  const timestamp = Date.now();
  const frameworkScores: Record<string, number> = {};
  const alerts: ComplianceAlert[] = [];

  let scoreSum = 0;
  let scoreCount = 0;

  for (const framework of config.frameworks) {
    const score = currentScores[framework] ?? 0;
    frameworkScores[framework] = score;
    scoreSum += score;
    scoreCount++;

    if (score < config.alertThreshold) {
      // Below threshold: actual violation alert
      const severity: ComplianceAlert['severity'] = score < 0.5 ? 'critical' : 'warning';
      alerts.push({
        framework,
        severity,
        message: `${framework} compliance score ${score.toFixed(2)} is below threshold ${config.alertThreshold}`,
        preViolation: false,
        currentScore: score,
        projectedScore: score,
      });
    } else if (score < config.alertThreshold + 0.1) {
      // Above threshold but close: pre-violation alert
      alerts.push({
        framework,
        severity: 'info',
        message: `${framework} compliance score ${score.toFixed(2)} is approaching threshold ${config.alertThreshold}`,
        preViolation: true,
        currentScore: score,
        projectedScore: score - 0.05, // projected slight decline
      });
    }
  }

  const overallScore = scoreCount > 0 ? scoreSum / scoreCount : 0;

  const snapshot: ComplianceSnapshot = {
    timestamp,
    overallScore,
    frameworkScores,
    alerts,
  };

  if (config.operationalBudget !== undefined && config.operationalBudget > 0) {
    // Estimate compliance cost as a function of the number of frameworks
    // and the alert count (more alerts = more remediation cost)
    const baseCost = config.frameworks.length * 1000;
    const alertCost = alerts.length * 500;
    const totalCost = baseCost + alertCost;
    snapshot.costAsPercentOfBudget = (totalCost / config.operationalBudget) * 100;
  }

  return snapshot;
}

/**
 * Analyze trajectory across multiple compliance snapshots.
 *
 * Requires at least 2 snapshots. Determines trend by comparing
 * the last overall score to the first. Projects days to violation
 * if the trend is declining.
 *
 * @param snapshots - Array of compliance snapshots (must have at least 2).
 * @returns Trajectory analysis with trend, projection, and recommendations.
 */
export function analyzeTrajectory(
  snapshots: ComplianceSnapshot[],
): ComplianceAutopilotTrajectory {
  if (snapshots.length < 2) {
    return {
      snapshots,
      trend: 'stable',
      projectedDaysToViolation: null,
      recommendations: ['Collect more compliance snapshots for meaningful trajectory analysis'],
    };
  }

  // Sort by timestamp ascending
  const sorted = [...snapshots].sort((a, b) => a.timestamp - b.timestamp);
  const first = sorted[0]!;
  const last = sorted[sorted.length - 1]!;

  const scoreDelta = last.overallScore - first.overallScore;

  let trend: ComplianceAutopilotTrajectory['trend'];
  if (scoreDelta > 0.05) {
    trend = 'improving';
  } else if (scoreDelta < -0.05) {
    trend = 'declining';
  } else {
    trend = 'stable';
  }

  let projectedDaysToViolation: number | null = null;

  if (trend === 'declining') {
    // Linear extrapolation: how many days until score reaches 0.7 (default threshold)
    const timeSpanMs = last.timestamp - first.timestamp;
    const timeSpanDays = timeSpanMs / (1000 * 60 * 60 * 24);

    if (timeSpanDays > 0 && scoreDelta < 0) {
      const dailyDecline = Math.abs(scoreDelta) / timeSpanDays;
      // Assume threshold is 0.7
      const threshold = 0.7;
      if (last.overallScore > threshold) {
        const remainingBuffer = last.overallScore - threshold;
        projectedDaysToViolation = Math.round(remainingBuffer / dailyDecline);
      } else {
        // Already below threshold
        projectedDaysToViolation = 0;
      }
    }
  }

  // Generate recommendations based on weakest frameworks
  const recommendations: string[] = [];

  // Collect all framework scores from the latest snapshot
  const latestScores = last.frameworkScores;
  const sortedFrameworks = Object.entries(latestScores)
    .sort(([, a], [, b]) => a - b);

  if (sortedFrameworks.length > 0) {
    const [weakest, weakestScore] = sortedFrameworks[0]!;
    if (weakestScore < 0.7) {
      recommendations.push(`Prioritize ${weakest} compliance improvement (current score: ${weakestScore.toFixed(2)})`);
    }
    if (weakestScore < 0.5) {
      recommendations.push(`Critical: ${weakest} requires immediate remediation`);
    }
  }

  if (trend === 'declining') {
    recommendations.push('Compliance trend is declining. Review recent changes and remediate gaps.');
    if (projectedDaysToViolation !== null && projectedDaysToViolation < 30) {
      recommendations.push(`Warning: projected violation within ${projectedDaysToViolation} days`);
    }
  }

  if (trend === 'stable' && recommendations.length === 0) {
    recommendations.push('Compliance is stable. Continue monitoring for changes.');
  }

  if (trend === 'improving' && recommendations.length === 0) {
    recommendations.push('Compliance is improving. Maintain current practices.');
  }

  return {
    snapshots: sorted,
    trend,
    projectedDaysToViolation,
    recommendations,
  };
}

/**
 * Generate a regulatory report from compliance trajectory data.
 *
 * @param config - The compliance monitor configuration.
 * @param trajectory - The trajectory analysis to report on.
 * @returns A regulatory report with compliance status and details.
 */
export function generateRegulatoryReport(
  config: ComplianceMonitorConfig,
  trajectory: ComplianceAutopilotTrajectory,
): {
  reportId: string;
  generatedAt: number;
  frameworks: string[];
  overallCompliance: number;
  status: 'compliant' | 'at_risk' | 'non_compliant';
  details: string;
} {
  const now = Date.now();

  // Use the latest snapshot for current state
  const latestSnapshot = trajectory.snapshots.length > 0
    ? trajectory.snapshots[trajectory.snapshots.length - 1]!
    : null;

  const overallCompliance = latestSnapshot?.overallScore ?? 0;
  const frameworkScores = latestSnapshot?.frameworkScores ?? {};

  // Determine status based on individual framework scores
  let status: 'compliant' | 'at_risk' | 'non_compliant' = 'compliant';

  for (const framework of config.frameworks) {
    const score = frameworkScores[framework] ?? 0;
    if (score < 0.5) {
      status = 'non_compliant';
      break;
    }
    if (score < 0.8) {
      status = 'at_risk';
    }
  }

  // Build details string
  const detailLines: string[] = [];
  detailLines.push(`Regulatory Compliance Report`);
  detailLines.push(`Generated: ${new Date(now).toISOString()}`);
  detailLines.push(`Frameworks: ${config.frameworks.join(', ')}`);
  detailLines.push(`Overall Compliance: ${(overallCompliance * 100).toFixed(1)}%`);
  detailLines.push(`Status: ${status.toUpperCase()}`);
  detailLines.push(`Trend: ${trajectory.trend}`);

  if (trajectory.projectedDaysToViolation !== null) {
    detailLines.push(`Projected days to violation: ${trajectory.projectedDaysToViolation}`);
  }

  for (const framework of config.frameworks) {
    const score = frameworkScores[framework] ?? 0;
    detailLines.push(`  ${framework}: ${(score * 100).toFixed(1)}%`);
  }

  if (trajectory.recommendations.length > 0) {
    detailLines.push(`Recommendations:`);
    for (const rec of trajectory.recommendations) {
      detailLines.push(`  - ${rec}`);
    }
  }

  return {
    reportId: `report-${now}`,
    generatedAt: now,
    frameworks: config.frameworks,
    overallCompliance,
    status,
    details: detailLines.join('\n'),
  };
}
