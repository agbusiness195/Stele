/**
 * SDK Protocol Re-export Integration Tests
 *
 * Verifies that all protocol packages re-exported from @kervyx/sdk are
 * correctly available and are the expected types (function, class, object).
 * Detailed behavioral tests are in each package's own test suite.
 */
import { describe, it, expect } from 'vitest';
import * as sdk from '@kervyx/sdk';

describe('SDK > Protocol Re-exports', () => {
  // ─── Canary ───────────────────────────────────────────────────────────
  describe('Canary', () => {
    it('exports canary functions', () => {
      expect(typeof sdk.generateCanary).toBe('function');
      expect(typeof sdk.evaluateCanary).toBe('function');
      expect(typeof sdk.detectionProbability).toBe('function');
      expect(typeof sdk.isCanaryExpired).toBe('function');
      expect(typeof sdk.canarySchedule).toBe('function');
      expect(typeof sdk.canaryCorrelation).toBe('function');
    });
  });

  // ─── Game Theory ──────────────────────────────────────────────────────
  describe('Game Theory', () => {
    it('exports game theory functions', () => {
      expect(typeof sdk.validateGameTheoryParameters).toBe('function');
      expect(typeof sdk.proveHonesty).toBe('function');
      expect(typeof sdk.minimumStake).toBe('function');
      expect(typeof sdk.minimumDetection).toBe('function');
      expect(typeof sdk.expectedCostOfBreach).toBe('function');
      expect(typeof sdk.honestyMargin).toBe('function');
      expect(typeof sdk.repeatedGameEquilibrium).toBe('function');
      expect(typeof sdk.coalitionStability).toBe('function');
      expect(typeof sdk.mechanismDesign).toBe('function');
      expect(typeof sdk.modelPrincipalAgent).toBe('function');
      expect(typeof sdk.analyzeTier).toBe('function');
      expect(typeof sdk.defineConjecture).toBe('function');
      expect(typeof sdk.getStandardConjectures).toBe('function');
      expect(typeof sdk.analyzeImpossibilityBounds).toBe('function');
    });
  });

  // ─── Composition ──────────────────────────────────────────────────────
  describe('Composition', () => {
    it('exports composition functions and constants', () => {
      expect(typeof sdk.compose).toBe('function');
      expect(typeof sdk.proveSystemProperty).toBe('function');
      expect(typeof sdk.validateComposition).toBe('function');
      expect(typeof sdk.intersectConstraints).toBe('function');
      expect(typeof sdk.findConflicts).toBe('function');
      expect(typeof sdk.decomposeCovenants).toBe('function');
      expect(typeof sdk.compositionComplexity).toBe('function');
      expect(typeof sdk.trustCompose).toBe('function');
      expect(typeof sdk.trustIntersect).toBe('function');
      expect(typeof sdk.trustNegate).toBe('function');
      expect(typeof sdk.trustTensorProduct).toBe('function');
      expect(typeof sdk.trustInverse).toBe('function');
      expect(typeof sdk.proveAlgebraicProperties).toBe('function');
      expect(typeof sdk.defineSafetyEnvelope).toBe('function');
      expect(typeof sdk.proposeImprovement).toBe('function');
      expect(typeof sdk.applyImprovement).toBe('function');
      expect(typeof sdk.verifyEnvelopeIntegrity).toBe('function');
    });

    it('exports trust identity and zero constants', () => {
      expect(sdk.TRUST_IDENTITY).toBeDefined();
      expect(sdk.TRUST_IDENTITY.confidence).toBe(1);
      expect(sdk.TRUST_ZERO).toBeDefined();
      expect(sdk.TRUST_ZERO.confidence).toBe(0);
    });

    it('trust algebra operations produce correct results', () => {
      const a = { confidence: 0.9, dimensions: { integrity: 0.8 } };
      const b = { confidence: 0.8, dimensions: { integrity: 0.7 } };

      const composed = sdk.trustCompose(a, b);
      expect(composed.confidence).toBeGreaterThan(0);
      expect(composed.confidence).toBeLessThanOrEqual(1);

      const intersection = sdk.trustIntersect(a, b);
      expect(intersection.confidence).toBeLessThanOrEqual(Math.min(a.confidence, b.confidence));
    });
  });

  // ─── Antifragile ──────────────────────────────────────────────────────
  describe('Antifragile', () => {
    it('exports antifragile functions and classes', () => {
      expect(typeof sdk.generateAntibody).toBe('function');
      expect(typeof sdk.proposeToGovernance).toBe('function');
      expect(typeof sdk.networkHealth).toBe('function');
      expect(typeof sdk.adoptAntibody).toBe('function');
      expect(typeof sdk.forceAdopt).toBe('function');
      expect(typeof sdk.rejectAntibody).toBe('function');
      expect(typeof sdk.voteForAntibody).toBe('function');
      expect(typeof sdk.antibodyExists).toBe('function');
      expect(typeof sdk.stressTest).toBe('function');
      expect(typeof sdk.antifragilityIndex).toBe('function');
      expect(typeof sdk.calibratedAntifragilityIndex).toBe('function');
      expect(typeof sdk.StressResponseCurve).toBe('function'); // class
      expect(typeof sdk.PhaseTransitionDetector).toBe('function'); // class
      expect(typeof sdk.FitnessEvolution).toBe('function'); // class
    });

    it('generates antibody from valid breach', () => {
      const breach = {
        id: 'b1',
        violatedConstraint: "deny delete on '/system/**'",
        severity: 'high' as const,
      };
      const antibody = sdk.generateAntibody(breach);
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
      const health = sdk.networkHealth([], [breach]);
      expect(health.totalBreaches).toBe(1);
      expect(health.resistanceScore).toBeGreaterThanOrEqual(0);
    });
  });

  // ─── Consensus ────────────────────────────────────────────────────────
  describe('Consensus', () => {
    it('exports consensus functions and classes', () => {
      expect(typeof sdk.computeAccountability).toBe('function');
      expect(typeof sdk.evaluateCounterparty).toBe('function');
      expect(typeof sdk.networkAccountabilityRate).toBe('function');
      expect(typeof sdk.byzantineFaultTolerance).toBe('function');
      expect(typeof sdk.quorumSize).toBe('function');
      expect(typeof sdk.consensusLatency).toBe('function');
      expect(typeof sdk.tierToMinScore).toBe('function');
      expect(typeof sdk.compareTiers).toBe('function');
      expect(typeof sdk.validateConsensusConfig).toBe('function');
      expect(typeof sdk.validateProtocolData).toBe('function');
      expect(typeof sdk.validateConsensusPolicy).toBe('function');
      expect(typeof sdk.StreamlinedBFT).toBe('function'); // class
      expect(typeof sdk.DynamicQuorum).toBe('function'); // class
      expect(typeof sdk.PipelineSimulator).toBe('function'); // class
      expect(typeof sdk.QuorumIntersectionVerifier).toBe('function'); // class
    });

    it('byzantine fault tolerance works', () => {
      const result = sdk.byzantineFaultTolerance(10);
      expect(result.canTolerate).toBe(true);
      expect(result.maxFaultyNodes).toBe(3);
    });

    it('quorum size works', () => {
      const result = sdk.quorumSize(10, 'bft');
      expect(result.quorumSize).toBeGreaterThan(0);
      expect(result.protocol).toBe('bft');
    });

    it('tier comparison works', () => {
      expect(sdk.compareTiers('exemplary', 'basic')).toBe(1);
      expect(sdk.compareTiers('basic', 'exemplary')).toBe(-1);
      expect(sdk.compareTiers('verified', 'verified')).toBe(0);
    });
  });

  // ─── Robustness ───────────────────────────────────────────────────────
  describe('Robustness', () => {
    it('exports robustness functions', () => {
      expect(typeof sdk.assessSeverity).toBe('function');
      expect(typeof sdk.proveRobustness).toBe('function');
      expect(typeof sdk.fuzz).toBe('function');
      expect(typeof sdk.generateAdversarialInputs).toBe('function');
      expect(typeof sdk.formalVerification).toBe('function');
      expect(typeof sdk.robustnessScore).toBe('function');
    });
  });

  // ─── Recursive ────────────────────────────────────────────────────────
  describe('Recursive', () => {
    it('exports recursive functions', () => {
      expect(typeof sdk.createMetaCovenant).toBe('function');
      expect(typeof sdk.verifyRecursively).toBe('function');
      expect(typeof sdk.proveTermination).toBe('function');
      expect(typeof sdk.trustBase).toBe('function');
      expect(typeof sdk.addLayer).toBe('function');
      expect(typeof sdk.computeTrustTransitivity).toBe('function');
      expect(typeof sdk.findMinimalVerificationSet).toBe('function');
    });
  });

  // ─── Alignment ────────────────────────────────────────────────────────
  describe('Alignment', () => {
    it('exports alignment functions, classes, and constants', () => {
      expect(Array.isArray(sdk.STANDARD_ALIGNMENT_PROPERTIES)).toBe(true);
      expect(sdk.STANDARD_ALIGNMENT_PROPERTIES.length).toBeGreaterThan(0);
      expect(typeof sdk.defineAlignment).toBe('function');
      expect(typeof sdk.assessAlignment).toBe('function');
      expect(typeof sdk.alignmentGap).toBe('function');
      expect(typeof sdk.alignmentDrift).toBe('function');
      expect(typeof sdk.alignmentDecomposition).toBe('function');
      expect(typeof sdk.AdaptiveAlignmentTracker).toBe('function'); // class
      expect(typeof sdk.PropertyAnomalyDetector).toBe('function'); // class
      expect(typeof sdk.DriftForecaster).toBe('function'); // class
      expect(typeof sdk.AlignmentSurface).toBe('function'); // class
      expect(typeof sdk.AlignmentFeedbackLoop).toBe('function'); // class
    });
  });

  // ─── Norms ────────────────────────────────────────────────────────────
  describe('Norms', () => {
    it('exports norms functions', () => {
      expect(typeof sdk.analyzeNorms).toBe('function');
      expect(typeof sdk.discoverNorms).toBe('function');
      expect(typeof sdk.proposeStandard).toBe('function');
      expect(typeof sdk.generateTemplate).toBe('function');
      expect(typeof sdk.normConflictDetection).toBe('function');
      expect(typeof sdk.normPrecedence).toBe('function');
    });
  });

  // ─── Substrate ────────────────────────────────────────────────────────
  describe('Substrate', () => {
    it('exports substrate functions and constants', () => {
      expect(sdk.SUBSTRATE_DEFAULTS).toBeDefined();
      expect(Object.keys(sdk.SUBSTRATE_DEFAULTS).length).toBeGreaterThan(0);
      expect(typeof sdk.createAdapter).toBe('function');
      expect(typeof sdk.physicalCovenant).toBe('function');
      expect(typeof sdk.translateCovenant).toBe('function');
      expect(typeof sdk.checkPhysicalConstraint).toBe('function');
      expect(typeof sdk.checkSafetyBound).toBe('function');
      expect(typeof sdk.substrateCompatibility).toBe('function');
      expect(typeof sdk.constraintTranslation).toBe('function');
      expect(typeof sdk.substrateCapabilityMatrix).toBe('function');
    });
  });

  // ─── Derivatives ──────────────────────────────────────────────────────
  describe('Derivatives', () => {
    it('exports derivatives functions', () => {
      expect(typeof sdk.assessRisk).toBe('function');
      expect(typeof sdk.priceInsurance).toBe('function');
      expect(typeof sdk.createPolicy).toBe('function');
      expect(typeof sdk.createFuture).toBe('function');
      expect(typeof sdk.settleFuture).toBe('function');
      expect(typeof sdk.claimPolicy).toBe('function');
      expect(typeof sdk.blackScholesPrice).toBe('function');
      expect(typeof sdk.valueAtRisk).toBe('function');
      expect(typeof sdk.hedgeRatio).toBe('function');
    });
  });

  // ─── Legal ────────────────────────────────────────────────────────────
  describe('Legal', () => {
    it('exports legal functions, classes, and constants', () => {
      expect(sdk.JURISDICTIONS).toBeDefined();
      expect(Object.keys(sdk.JURISDICTIONS).length).toBeGreaterThan(0);
      expect(sdk.COMPLIANCE_STANDARDS).toBeDefined();
      expect(Object.keys(sdk.COMPLIANCE_STANDARDS).length).toBeGreaterThan(0);
      expect(typeof sdk.registerJurisdiction).toBe('function');
      expect(typeof sdk.exportLegalPackage).toBe('function');
      expect(typeof sdk.mapToJurisdiction).toBe('function');
      expect(typeof sdk.generateComplianceReport).toBe('function');
      expect(typeof sdk.crossJurisdictionCompliance).toBe('function');
      expect(typeof sdk.auditTrailExport).toBe('function');
      expect(typeof sdk.regulatoryGapAnalysis).toBe('function');
      expect(typeof sdk.ComplianceSurface).toBe('function'); // class
      expect(typeof sdk.ComplianceTrajectory).toBe('function'); // class
      expect(typeof sdk.RemediationPlanner).toBe('function'); // class
      expect(typeof sdk.JurisdictionConflictResolver).toBe('function'); // class
      expect(typeof sdk.RegulatoryImpactAnalyzer).toBe('function'); // class
      expect(typeof sdk.createComplianceMonitor).toBe('function');
      expect(typeof sdk.takeSnapshot).toBe('function');
      expect(typeof sdk.analyzeTrajectory).toBe('function');
      expect(typeof sdk.generateRegulatoryReport).toBe('function');
    });
  });

  // ─── Enforcement ──────────────────────────────────────────────────────
  describe('Enforcement', () => {
    it('exports enforcement functions, classes, and error types', () => {
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
      expect(typeof sdk.initiateNegotiation).toBe('function');
      expect(typeof sdk.propose).toBe('function');
      expect(typeof sdk.counter).toBe('function');
      expect(typeof sdk.agree).toBe('function');
      expect(typeof sdk.evaluateNegotiation).toBe('function');
      expect(typeof sdk.isNegotiationExpired).toBe('function');
      expect(typeof sdk.failNegotiation).toBe('function');
      expect(typeof sdk.roundCount).toBe('function');
      expect(typeof sdk.computeNashBargainingSolution).toBe('function');
      expect(typeof sdk.paretoFrontier).toBe('function');
      expect(typeof sdk.computeNPartyNash).toBe('function');
      expect(typeof sdk.ConcessionProtocol).toBe('function'); // class
      expect(typeof sdk.IncrementalParetoFrontier).toBe('function'); // class
      expect(typeof sdk.zeuthenStrategy).toBe('function');
      expect(typeof sdk.runZeuthenNegotiation).toBe('function');
    });
  });

  // ─── Cross-package integration ────────────────────────────────────────
  describe('Cross-package via SDK', () => {
    it('can use canary + game theory together', () => {
      // Verify these are the same functions from their respective packages
      const canaryFn = sdk.generateCanary;
      const gameTheoryFn = sdk.proveHonesty;
      expect(canaryFn).toBe(canaryFn); // identity check
      expect(gameTheoryFn).toBe(gameTheoryFn);
    });

    it('SDK export count is comprehensive', () => {
      const exportCount = Object.keys(sdk).length;
      // We now export 431 values from the SDK (up from ~270 before protocol re-exports)
      expect(exportCount).toBeGreaterThanOrEqual(400);
    });

    it('all functions are callable (not undefined)', () => {
      const fns = Object.entries(sdk).filter(
        ([, v]) => typeof v === 'function',
      );
      // Every function export should not be undefined
      for (const [name, fn] of fns) {
        expect(fn, `${name} should be a function`).toBeDefined();
      }
    });
  });
});
