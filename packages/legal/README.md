# @grith/legal

Legal identity packages, regulatory compliance mapping, and jurisdiction conflict resolution for covenant systems.

## Installation

```bash
npm install @grith/legal
```

## Key APIs

- **exportLegalPackage()**: Creates a hashed LegalIdentityPackage bundling covenants, compliance records, attestations, reputation, and insurance data.
- **mapToJurisdiction()**: Maps a legal package to jurisdiction-specific requirements (US/SOC2, EU/GDPR, UK/UK-GDPR, JP/APPI).
- **generateComplianceReport()**: Scores compliance against a standard (SOC2, ISO27001, GDPR, CCPA, HIPAA) with configurable weights.
- **crossJurisdictionCompliance()**: Checks compliance across multiple jurisdictions simultaneously, detecting conflicts.
- **auditTrailExport()**: Generates a chronological audit trail from a LegalIdentityPackage.
- **regulatoryGapAnalysis()**: Identifies gaps between current compliance and a target standard with severity ratings and remediation suggestions.
- **registerJurisdiction()**: Registers custom jurisdictions beyond the built-in set.
- **ComplianceSurface**: Nonlinear compliance scoring model that accounts for interaction effects between requirements.
- **ComplianceTrajectory**: Tracks compliance scores over time with least-squares trend analysis and degradation detection.
- **RemediationPlanner**: Gradient-based prioritization of compliance remediation actions.
- **JurisdictionConflictResolver**: Detects and resolves cross-jurisdiction requirement conflicts using strictest-wins, lex-specialis, or proportionality strategies.
- **RegulatoryImpactAnalyzer**: Models the impact of proposed regulatory changes on current compliance posture.

## Usage

```typescript
import {
  exportLegalPackage,
  mapToJurisdiction,
  generateComplianceReport,
  regulatoryGapAnalysis,
} from '@grith/legal';

const pkg = exportLegalPackage('agent-1', 'operator-1', {
  covenants: [{ id: 'cov-1', constraints: ['no-delete'], signedAt: Date.now(), status: 'active' }],
  compliance: { totalInteractions: 100, covenantedInteractions: 95, breaches: 0,
                canaryTests: 50, canaryPasses: 49, attestationCoverage: 0.92 },
  reputation: { score: 0.95, totalInteractions: 100 },
  attestations: [],
  insurance: [],
});

const mapping = mapToJurisdiction(pkg, 'EU');
console.log(mapping.legalFramework); // 'EU General Data Protection Regulation'

const report = generateComplianceReport(pkg.complianceRecord, 'GDPR');
console.log(report.passed); // true

const gaps = regulatoryGapAnalysis(pkg.complianceRecord, 'HIPAA');
console.log(gaps.readinessPercentage);
```

## Docs

See the [Grith SDK root documentation](../../README.md) for the full API reference.
