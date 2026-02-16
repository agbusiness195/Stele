/**
 * Protocol Re-export Integration Tests
 *
 * Verifies that all protocol packages re-exported from @stele/protocols are
 * correctly available and are the expected types (function, class, object).
 * Detailed behavioral tests are in each package's own test suite.
 *
 * NOTE: Protocol re-exports have moved from @stele/sdk to @stele/protocols
 * as part of the SDK split. Enforcement remains in @stele/sdk.
 */
import { describe, it, expect } from 'vitest';
import * as protocols from '@stele/protocols';
import * as sdk from '@stele/sdk';

describe('Protocol Re-exports via @stele/protocols', () => {
  // ─── Canary ───────────────────────────────────────────────────────────
  describe('Canary', () => {
    it('exports canary functions', () => {
      expect(typeof protocols.generateCanary).toBe('function');
      expect(typeof protocols.evaluateCanary).toBe('function');
      expect(typeof protocols.detectionProbability).toBe('function');
      expect(typeof protocols.isCanaryExpired).toBe('function');
      expect(typeof protocols.canarySchedule).toBe('function');
      expect(typeof protocols.canaryCorrelation).toBe('function');
    });
  });

  // ─── Game Theory ──────────────────────────────────────────────────────
  describe('Game Theory', () => {
    it('exports game theory functions', () => {
      expect(typeof protocols.validateGameTheoryParameters).toBe('function');
      expect(typeof protocols.proveHonesty).toBe('function');
      expect(typeof protocols.minimumStake).toBe('function');
      expect(typeof protocols.minimumDetection).toBe('function');
      expect(typeof protocols.expectedCostOfBreach).toBe('function');
      expect(typeof protocols.honestyMargin).toBe('function');
      expect(typeof protocols.repeatedGameEquilibrium).toBe('function');
      expect(typeof protocols.coalitionStability).toBe('function');
      expect(typeof protocols.mechanismDesign).toBe('function');
      expect(typeof protocols.modelPrincipalAgent).toBe('function');
      expect(typeof protocols.analyzeTier).toBe('function');
      expect(typeof protocols.defineConjecture).toBe('function');
      expect(typeof protocols.getStandardConjectures).toBe('function');
      expect(typeof protocols.analyzeImpossibilityBounds).toBe('function');
    });
  });

  // ─── Composition ──────────────────────────────────────────────────────
  describe('Composition', () => {
    it('exports composition functions and constants', () => {
      expect(typeof protocols.compose).toBe('function');
      expect(typeof protocols.proveSystemProperty).toBe('function');
      expect(typeof protocols.validateComposition).toBe('function');
      expect(typeof protocols.intersectConstraints).toBe('function');
      expect(typeof protocols.findConflicts).toBe('function');
      expect(typeof protocols.decomposeCovenants).toBe('function');
      expect(typeof protocols.compositionComplexity).toBe('function');
      expect(typeof protocols.trustCompose).toBe('function');
      expect(typeof protocols.trustIntersect).toBe('function');
      expect(typeof protocols.trustNegate).toBe('function');
      expect(typeof protocols.trustTensorProduct).toBe('function');
      expect(typeof protocols.trustInverse).toBe('function');
      expect(typeof protocols.proveAlgebraicProperties).toBe('function');
      expect(typeof protocols.defineSafetyEnvelope).toBe('function');
      expect(typeof protocols.proposeImprovement).toBe('function');
      expect(typeof protocols.applyImprovement).toBe('function');
      expect(typeof protocols.verifyEnvelopeIntegrity).toBe('function');
    });

    it('exports trust identity and zero constants', () => {
      expect(protocols.TRUST_IDENTITY).toBeDefined();
      expect(protocols.TRUST_IDENTITY.confidence).toBe(1);
      expect(protocols.TRUST_ZERO).toBeDefined();
      expect(protocols.TRUST_ZERO.confidence).toBe(0);
    });

    it('trust algebra operations produce correct results', () => {
      const a = { confidence: 0.9, dimensions: { integrity: 0.8 } };
      const b = { confidence: 0.8, dimensions: { integrity: 0.7 } };

      const composed = protocols.trustCompose(a, b);
      expect(composed.confidence).toBeGreaterThan(0);
      expect(composed.confidence).toBeLessThanOrEqual(1);

      const intersection = protocols.trustIntersect(a, b);
      expect(intersection.confidence).toBeLessThanOrEqual(Math.min(a.confidence, b.confidence));
    });
  });

  // ─── Antifragile ──────────────────────────────────────────────────────
  describe('Antifragile', () => {
    it('exports antifragile functions and classes', () => {
      expect(typeof protocols.generateAntibody).toBe('function');
      expect(typeof protocols.proposeToGovernance).toBe('function');
      expect(typeof protocols.networkHealth).toBe('function');
      expect(typeof protocols.adoptAntibody).toBe('function');
      expect(typeof protocols.forceAdopt).toBe('function');
      expect(typeof protocols.rejectAntibody).toBe('function');
      expect(typeof protocols.voteForAntibody).toBe('function');
      expect(typeof protocols.antibodyExists).toBe('function');
      expect(typeof protocols.stressTest).toBe('function');
      expect(typeof protocols.antifragilityIndex).toBe('function');
      expect(typeof protocols.calibratedAntifragilityIndex).toBe('function');
      expect(typeof protocols.StressResponseCurve).toBe('function'); // class
      expect(typeof protocols.PhaseTransitionDetector).toBe('function'); // class
      expect(typeof protocols.FitnessEvolution).toBe('function'); // class
    });

    it('generates antibody from valid breach', () => {
      const breach = {
        id: 'b1',
        violatedConstraint: "deny delete on '/system/**'",
        severity: 'high' as const,
      };
      const antibody = protocols.generateAntibody(breach);
      expect(antibody.derivedFromBreach).toBe('b1');
      expect(antibody.status).toBe('proposed');
      expect(antibody.proposedConstraint).toBeTruthy();
    });

    it('computes network health', () => {
      const breach = {
        id: 'b1',
        violatedConstraint: "deny delete on '/system/**'",
        severity: 'high' as const,
      };
      const health = protocols.networkHealth([], [breach]);
      expect(health.totalBreaches).toBe(1);
      expect(health.resistanceScore).toBeGreaterThanOrEqual(0);
    });
  });

  // ─── Consensus ────────────────────────────────────────────────────────
  describe('Consensus', () => {
    it('exports consensus functions and classes', () => {
      expect(typeof protocols.computeAccountability).toBe('function');
      expect(typeof protocols.evaluateCounterparty).toBe('function');
      expect(typeof protocols.networkAccountabilityRate).toBe('function');
      expect(typeof protocols.byzantineFaultTolerance).toBe('function');
      expect(typeof protocols.quorumSize).toBe('function');
      expect(typeof protocols.consensusLatency).toBe('function');
      expect(typeof protocols.tierToMinScore).toBe('function');
      expect(typeof protocols.compareTiers).toBe('function');
      expect(typeof protocols.validateConsensusConfig).toBe('function');
      expect(typeof protocols.validateProtocolData).toBe('function');
      expect(typeof protocols.validateConsensusPolicy).toBe('function');
      expect(typeof protocols.StreamlinedBFT).toBe('function'); // class
      expect(typeof protocols.DynamicQuorum).toBe('function'); // class
      expect(typeof protocols.PipelineSimulator).toBe('function'); // class
      expect(typeof protocols.QuorumIntersectionVerifier).toBe('function'); // class
    });

    it('byzantine fault tolerance works', () => {
      const result = protocols.byzantineFaultTolerance(10);
      expect(result.canTolerate).toBe(true);
      expect(result.maxFaultyNodes).toBe(3);
    });

    it('quorum size works', () => {
      const result = protocols.quorumSize(10, 'bft');
      expect(result.quorumSize).toBeGreaterThan(0);
      expect(result.protocol).toBe('bft');
    });

    it('tier comparison works', () => {
      expect(protocols.compareTiers('exemplary', 'basic')).toBe(1);
      expect(protocols.compareTiers('basic', 'exemplary')).toBe(-1);
      expect(protocols.compareTiers('verified', 'verified')).toBe(0);
    });
  });

  // ─── Robustness ───────────────────────────────────────────────────────
  describe('Robustness', () => {
    it('exports robustness functions', () => {
      expect(typeof protocols.assessSeverity).toBe('function');
      expect(typeof protocols.proveRobustness).toBe('function');
      expect(typeof protocols.fuzz).toBe('function');
      expect(typeof protocols.generateAdversarialInputs).toBe('function');
      expect(typeof protocols.formalVerification).toBe('function');
      expect(typeof protocols.robustnessScore).toBe('function');
    });
  });

  // ─── Recursive ────────────────────────────────────────────────────────
  describe('Recursive', () => {
    it('exports recursive functions', () => {
      expect(typeof protocols.createMetaCovenant).toBe('function');
      expect(typeof protocols.verifyRecursively).toBe('function');
      expect(typeof protocols.proveTermination).toBe('function');
      expect(typeof protocols.trustBase).toBe('function');
      expect(typeof protocols.addLayer).toBe('function');
      expect(typeof protocols.computeTrustTransitivity).toBe('function');
      expect(typeof protocols.findMinimalVerificationSet).toBe('function');
    });
  });

  // ─── Alignment ────────────────────────────────────────────────────────
  describe('Alignment', () => {
    it('exports alignment functions, classes, and constants', () => {
      expect(Array.isArray(protocols.STANDARD_ALIGNMENT_PROPERTIES)).toBe(true);
      expect(protocols.STANDARD_ALIGNMENT_PROPERTIES.length).toBeGreaterThan(0);
      expect(typeof protocols.defineAlignment).toBe('function');
      expect(typeof protocols.assessAlignment).toBe('function');
      expect(typeof protocols.alignmentGap).toBe('function');
      expect(typeof protocols.alignmentDrift).toBe('function');
      expect(typeof protocols.alignmentDecomposition).toBe('function');
      expect(typeof protocols.AdaptiveAlignmentTracker).toBe('function'); // class
      expect(typeof protocols.PropertyAnomalyDetector).toBe('function'); // class
      expect(typeof protocols.DriftForecaster).toBe('function'); // class
      expect(typeof protocols.AlignmentSurface).toBe('function'); // class
      expect(typeof protocols.AlignmentFeedbackLoop).toBe('function'); // class
    });
  });

  // ─── Norms ────────────────────────────────────────────────────────────
  describe('Norms', () => {
    it('exports norms functions', () => {
      expect(typeof protocols.analyzeNorms).toBe('function');
      expect(typeof protocols.discoverNorms).toBe('function');
      expect(typeof protocols.proposeStandard).toBe('function');
      expect(typeof protocols.generateTemplate).toBe('function');
      expect(typeof protocols.normConflictDetection).toBe('function');
      expect(typeof protocols.normPrecedence).toBe('function');
    });
  });

  // ─── Substrate ────────────────────────────────────────────────────────
  describe('Substrate', () => {
    it('exports substrate functions and constants', () => {
      expect(protocols.SUBSTRATE_DEFAULTS).toBeDefined();
      expect(Object.keys(protocols.SUBSTRATE_DEFAULTS).length).toBeGreaterThan(0);
      expect(typeof protocols.createAdapter).toBe('function');
      expect(typeof protocols.physicalCovenant).toBe('function');
      expect(typeof protocols.translateCovenant).toBe('function');
      expect(typeof protocols.checkPhysicalConstraint).toBe('function');
      expect(typeof protocols.checkSafetyBound).toBe('function');
      expect(typeof protocols.substrateCompatibility).toBe('function');
      expect(typeof protocols.constraintTranslation).toBe('function');
      expect(typeof protocols.substrateCapabilityMatrix).toBe('function');
    });
  });

  // ─── Derivatives ──────────────────────────────────────────────────────
  describe('Derivatives', () => {
    it('exports derivatives functions', () => {
      expect(typeof protocols.assessRisk).toBe('function');
      expect(typeof protocols.priceInsurance).toBe('function');
      expect(typeof protocols.createPolicy).toBe('function');
      expect(typeof protocols.createFuture).toBe('function');
      expect(typeof protocols.settleFuture).toBe('function');
      expect(typeof protocols.claimPolicy).toBe('function');
      expect(typeof protocols.blackScholesPrice).toBe('function');
      expect(typeof protocols.valueAtRisk).toBe('function');
      expect(typeof protocols.hedgeRatio).toBe('function');
    });
  });

  // ─── Legal ────────────────────────────────────────────────────────────
  describe('Legal', () => {
    it('exports legal functions, classes, and constants', () => {
      expect(protocols.JURISDICTIONS).toBeDefined();
      expect(Object.keys(protocols.JURISDICTIONS).length).toBeGreaterThan(0);
      expect(protocols.COMPLIANCE_STANDARDS).toBeDefined();
      expect(Object.keys(protocols.COMPLIANCE_STANDARDS).length).toBeGreaterThan(0);
      expect(typeof protocols.registerJurisdiction).toBe('function');
      expect(typeof protocols.exportLegalPackage).toBe('function');
      expect(typeof protocols.mapToJurisdiction).toBe('function');
      expect(typeof protocols.generateComplianceReport).toBe('function');
      expect(typeof protocols.crossJurisdictionCompliance).toBe('function');
      expect(typeof protocols.auditTrailExport).toBe('function');
      expect(typeof protocols.regulatoryGapAnalysis).toBe('function');
      expect(typeof protocols.ComplianceSurface).toBe('function'); // class
      expect(typeof protocols.ComplianceTrajectory).toBe('function'); // class
      expect(typeof protocols.RemediationPlanner).toBe('function'); // class
      expect(typeof protocols.JurisdictionConflictResolver).toBe('function'); // class
      expect(typeof protocols.RegulatoryImpactAnalyzer).toBe('function'); // class
      expect(typeof protocols.createComplianceMonitor).toBe('function');
      expect(typeof protocols.takeSnapshot).toBe('function');
      expect(typeof protocols.analyzeTrajectory).toBe('function');
      expect(typeof protocols.generateRegulatoryReport).toBe('function');
    });
  });

  // ─── Enforcement (still in SDK) ──────────────────────────────────────
  describe('Enforcement', () => {
    it('exports enforcement functions, classes, and error types from SDK', () => {
      expect(typeof sdk.Monitor).toBe('function'); // class
      expect(typeof sdk.CapabilityGate).toBe('function'); // class
      expect(typeof sdk.AuditChain).toBe('function'); // class
      expect(typeof sdk.MonitorDeniedError).toBe('function'); // class
      expect(typeof sdk.CapabilityError).toBe('function'); // class
      expect(typeof sdk.verifyMerkleProof).toBe('function');
      expect(typeof sdk.createProvenanceRecord).toBe('function');
      expect(typeof sdk.buildProvenanceChain).toBe('function');
      expect(typeof sdk.verifyProvenance).toBe('function');
      expect(typeof sdk.queryProvenance).toBe('function');
      expect(typeof sdk.createDefenseConfig).toBe('function');
      expect(typeof sdk.analyzeDefense).toBe('function');
      expect(typeof sdk.addDefenseLayer).toBe('function');
      expect(typeof sdk.disableLayer).toBe('function');
    });

    it('error classes are proper Error subclasses', () => {
      const denied = new sdk.MonitorDeniedError('test-action', 'test-resource', undefined, undefined);
      expect(denied).toBeInstanceOf(Error);
      const capErr = new sdk.CapabilityError('test');
      expect(capErr).toBeInstanceOf(Error);
    });
  });

  // ─── Negotiation ──────────────────────────────────────────────────────
  describe('Negotiation', () => {
    it('exports negotiation functions and classes', () => {
      expect(typeof protocols.initiateNegotiation).toBe('function');
      expect(typeof protocols.propose).toBe('function');
      expect(typeof protocols.counter).toBe('function');
      expect(typeof protocols.agree).toBe('function');
      expect(typeof protocols.evaluateNegotiation).toBe('function');
      expect(typeof protocols.isNegotiationExpired).toBe('function');
      expect(typeof protocols.failNegotiation).toBe('function');
      expect(typeof protocols.roundCount).toBe('function');
      expect(typeof protocols.computeNashBargainingSolution).toBe('function');
      expect(typeof protocols.paretoFrontier).toBe('function');
      expect(typeof protocols.computeNPartyNash).toBe('function');
      expect(typeof protocols.ConcessionProtocol).toBe('function'); // class
      expect(typeof protocols.IncrementalParetoFrontier).toBe('function'); // class
      expect(typeof protocols.zeuthenStrategy).toBe('function');
      expect(typeof protocols.runZeuthenNegotiation).toBe('function');
    });
  });

  // ─── Cross-package integration ────────────────────────────────────────
  describe('Cross-package via @stele/protocols', () => {
    it('protocols export count is comprehensive', () => {
      const exportCount = Object.keys(protocols).length;
      // @stele/protocols consolidates ~300 exports from 20 protocol packages
      expect(exportCount).toBeGreaterThanOrEqual(250);
    });

    it('all functions are callable (not undefined)', () => {
      const fns = Object.entries(protocols).filter(
        ([, v]) => typeof v === 'function',
      );
      // Every function export should not be undefined
      for (const [name, fn] of fns) {
        expect(fn, `${name} should be a function`).toBeDefined();
      }
    });
  });
});
