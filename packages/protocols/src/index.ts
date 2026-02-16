/**
 * @stele/protocols -- Unified facade for all Stele protocol modules.
 *
 * Provides namespaced access to every protocol-level package in the Stele
 * ecosystem. Import from this package instead of 20+ individual packages.
 *
 * @example
 * ```typescript
 * import * as protocols from '@stele/protocols';
 *
 * // Breach detection
 * protocols.createBreachAttestation(...);
 *
 * // Game theory
 * protocols.proveHonesty(...);
 *
 * // Or import specific items:
 * import { createBreachAttestation, computeReputationScore } from '@stele/protocols';
 * ```
 *
 * @packageDocumentation
 */

// ─── Breach Detection ─────────────────────────────────────────────────────────
export {
  createBreachAttestation,
  verifyBreachAttestation,
  TrustGraph,
  ExponentialDegradation,
  BreachStateMachine,
  RecoveryModel,
  RepeatOffenderDetector,
  createPlaybook,
  matchIncident,
  createIncidentReport,
  escalateIncident,
  resolveIncident,
} from '@stele/breach';
export type {
  BreachAttestation,
  TrustStatus,
  TrustNode,
  BreachEvent,
} from '@stele/breach';

// ─── Reputation ───────────────────────────────────────────────────────────────
export {
  computeReputationScore,
  createReceipt,
  verifyReceipt,
  countersignReceipt,
  verifyReceiptChain,
  computeReceiptsMerkleRoot,
  DEFAULT_SCORING_CONFIG,
  createStake,
  releaseStake,
  burnStake,
  createDelegation,
  burnDelegation,
  coBurnDelegation,
  createEndorsement,
  verifyEndorsement,
  ReceiptDAG,
  ReputationDecayModel,
  GraduatedBurner,
  ReputationAggregator,
  createResourcePool,
  allocateTrust,
  releaseTrust,
  slashStake,
  collateralizationRatio,
  computeProfile,
  compareProfiles,
  STAKE_TIERS,
  assignTier,
  createStakedAgent,
  recordQuery,
  computeGovernanceVote,
} from '@stele/reputation';
export type {
  ReputationScore,
  ExecutionReceipt,
  ReputationStake,
  ReputationDelegation,
  Endorsement,
  ScoringConfig,
  ResourcePool,
  SlashingEvent,
  TrustDimension,
  MultidimensionalProfile,
  StakeTier,
  StakeTierConfig,
  StakedAgent,
} from '@stele/reputation';

// ─── Proof ────────────────────────────────────────────────────────────────────
export {
  generateComplianceProof,
  verifyComplianceProof,
  computeAuditCommitment,
  computeConstraintCommitment,
  poseidonHash,
  hashToField,
  fieldToHex,
  FIELD_PRIME,
} from '@stele/proof';
export type {
  ComplianceProof,
  ProofVerificationResult,
  ProofGenerationOptions,
  AuditEntryData,
} from '@stele/proof';

// ─── Attestation ──────────────────────────────────────────────────────────────
export {
  createAttestation,
  verifyAttestation,
  signAttestation,
  isSigned,
  reconcile,
  getDiscrepancies,
  attestationChainVerify,
  computeAttestationCoverage,
  createEntanglement,
  buildEntanglementNetwork,
  verifyEntangled,
  assessConditionalRisk,
} from '@stele/attestation';
export type {
  ExternalAttestation,
  AttestationReconciliation,
  Discrepancy,
  ReceiptSummary,
  AttestationChainLink,
  ChainVerificationResult,
  AgentAction,
  AttestationCoverageResult,
} from '@stele/attestation';

// ─── Canary ───────────────────────────────────────────────────────────────────
export {
  generateCanary,
  evaluateCanary,
  detectionProbability,
  isExpired as isCanaryExpired,
  canarySchedule,
  canaryCorrelation,
} from '@stele/canary';
export type {
  ChallengePayload,
  Canary,
  CanaryResult,
  CanaryScheduleEntry,
  CanaryScheduleResult,
  CanaryCorrelationResult,
} from '@stele/canary';

// ─── Game Theory ──────────────────────────────────────────────────────────────
export {
  validateParameters as validateGameTheoryParameters,
  proveHonesty,
  minimumStake,
  minimumDetection,
  expectedCostOfBreach,
  honestyMargin,
  repeatedGameEquilibrium,
  coalitionStability,
  mechanismDesign,
  modelPrincipalAgent,
  analyzeTier,
  defineConjecture,
  getStandardConjectures,
  analyzeImpossibilityBounds,
} from '@stele/gametheory';
export type {
  HonestyParameters,
  HonestyProof,
  RepeatedGameParams,
  RepeatedGameResult,
  CoalitionValue,
  CoalitionStabilityResult,
  MechanismDesignParams,
  MechanismDesignResult,
  OperatorPrincipal,
  PrincipalAgentModel,
  AdoptionTier,
  TierAnalysis,
  ConjectureStatus,
  Conjecture,
  ImpossibilityBound,
} from '@stele/gametheory';

// ─── Composition ──────────────────────────────────────────────────────────────
export {
  compose,
  proveSystemProperty,
  validateComposition,
  intersectConstraints,
  findConflicts,
  decomposeCovenants,
  compositionComplexity,
  TRUST_IDENTITY,
  TRUST_ZERO,
  trustCompose,
  trustIntersect,
  trustNegate,
  trustTensorProduct,
  trustInverse,
  proveAlgebraicProperties,
  defineSafetyEnvelope,
  proposeImprovement,
  applyImprovement,
  verifyEnvelopeIntegrity,
} from '@stele/composition';
export type {
  CompositionProof,
  ComposedConstraint,
  SystemProperty,
  CovenantSummary,
  DecomposedCovenant,
  CompositionComplexityResult,
  TrustValue,
  AlgebraicProof,
  SafetyEnvelope,
  ImprovementProposal,
  ImprovementResult,
} from '@stele/composition';

// ─── Antifragile ──────────────────────────────────────────────────────────────
export {
  generateAntibody,
  proposeToGovernance,
  networkHealth,
  adoptAntibody,
  forceAdopt,
  rejectAntibody,
  voteForAntibody,
  antibodyExists,
  stressTest,
  antifragilityIndex,
  StressResponseCurve,
  PhaseTransitionDetector,
  FitnessEvolution,
  calibratedAntifragilityIndex,
} from '@stele/antifragile';
export type {
  BreachAntibody,
  NetworkHealth,
  GovernanceProposal as AntifragileGovernanceProposal,
  BreachSummary,
  StressTestResult,
  AntifragilityIndexResult,
  StressResponseConfig,
  MetricObservation,
  PhaseTransitionResult,
  ScoredAntibody,
  FitnessEvolutionConfig,
  CalibratedAntifragilityResult,
} from '@stele/antifragile';

// ─── Consensus ────────────────────────────────────────────────────────────────
export {
  validateConfig as validateConsensusConfig,
  validateProtocolData,
  validatePolicy as validateConsensusPolicy,
  tierToMinScore,
  compareTiers,
  computeAccountability,
  evaluateCounterparty,
  networkAccountabilityRate,
  byzantineFaultTolerance,
  quorumSize,
  consensusLatency,
  StreamlinedBFT,
  DynamicQuorum,
  PipelineSimulator,
  QuorumIntersectionVerifier,
} from '@stele/consensus';
export type {
  AccountabilityTier,
  AccountabilityScore,
  InteractionPolicy,
  AccessDecision,
  ProtocolData,
  AccountabilityConfig,
  BFTResult,
  ConsensusProtocol,
  QuorumResult,
  ConsensusLatencyParams,
  ConsensusLatencyResult,
  BFTPhase,
  BFTVote,
  QuorumCertificate,
  BFTBlock,
  BFTViewState,
  Epoch,
  ReconfigRequest,
  NetworkCondition,
  PipelineSimulationResult,
  QuorumIntersectionResult,
} from '@stele/consensus';

// ─── Robustness ───────────────────────────────────────────────────────────────
export {
  assessSeverity,
  proveRobustness,
  fuzz,
  generateAdversarialInputs,
  formalVerification,
  robustnessScore,
} from '@stele/robustness';
export type {
  RobustnessProof,
  InputBound,
  RobustnessReport,
  Vulnerability,
  CovenantSpec,
  ConstraintSpec,
  RobustnessOptions,
  FormalVerificationResult,
  Contradiction,
  RobustnessScoreResult,
  RobustnessFactor,
} from '@stele/robustness';

// ─── Recursive ────────────────────────────────────────────────────────────────
export {
  createMetaCovenant,
  verifyRecursively,
  proveTermination,
  trustBase,
  addLayer,
  computeTrustTransitivity,
  findMinimalVerificationSet,
} from '@stele/recursive';
export type {
  MetaTargetType,
  MetaCovenant,
  RecursiveVerification,
  TerminationProof,
  TrustBase as RecursiveTrustBase,
  VerificationEntity,
  TrustEdge,
  TransitiveTrustResult,
  VerifierNode,
  MinimalVerificationSetResult,
} from '@stele/recursive';

// ─── Alignment ────────────────────────────────────────────────────────────────
export {
  STANDARD_ALIGNMENT_PROPERTIES,
  defineAlignment,
  assessAlignment,
  alignmentGap,
  alignmentDrift,
  alignmentDecomposition,
  AdaptiveAlignmentTracker,
  PropertyAnomalyDetector,
  DriftForecaster,
  AlignmentSurface,
  AlignmentFeedbackLoop,
} from '@stele/alignment';
export type {
  AlignmentProperty,
  AlignmentCovenant,
  AlignmentReport,
  ExecutionRecord as AlignmentExecutionRecord,
  AlignmentDriftResult,
  AlignmentDecompositionResult,
  PropertyContribution,
  WeightObservation,
  AdaptiveWeightSnapshot,
  PropertyStatistics,
  AnomalyResult,
  DriftForecast,
  DimensionGradient,
  AlignmentSurfaceResult,
  FeedbackLoopConfig,
  AlignmentOutcome,
  FeedbackLoopState,
} from '@stele/alignment';

// ─── Norms ────────────────────────────────────────────────────────────────────
export {
  analyzeNorms,
  discoverNorms,
  proposeStandard,
  generateTemplate,
  normConflictDetection,
  normPrecedence,
} from '@stele/norms';
export type {
  DiscoveredNorm,
  NormAnalysis,
  NormCluster,
  GovernanceProposal as NormGovernanceProposal,
  CovenantData,
  CovenantTemplate,
  NormDefinition,
  NormConflict,
  NormPrecedenceResult,
} from '@stele/norms';

// ─── Substrate ────────────────────────────────────────────────────────────────
export {
  SUBSTRATE_DEFAULTS,
  createAdapter,
  physicalCovenant,
  translateCovenant,
  checkPhysicalConstraint,
  checkSafetyBound,
  substrateCompatibility,
  constraintTranslation,
  substrateCapabilityMatrix,
} from '@stele/substrate';
export type {
  SubstrateType,
  SubstrateAdapter,
  PhysicalConstraint,
  SafetyBound,
  UniversalCovenant,
  AdapterConfig,
  SafetyBoundResult,
  CompatibilityResult,
  EnforcementRule,
  ConstraintTranslationResult,
  CapabilityEntry,
  CapabilityMatrixRow,
  CapabilityMatrix,
} from '@stele/substrate';

// ─── Derivatives ──────────────────────────────────────────────────────────────
export {
  assessRisk,
  priceInsurance,
  createPolicy,
  createFuture,
  settleFuture,
  claimPolicy,
  blackScholesPrice,
  valueAtRisk,
  hedgeRatio,
} from '@stele/derivatives';
export type {
  TrustFuture,
  AgentInsurancePolicy,
  RiskAssessment,
  RiskFactor,
  Settlement,
  ReputationData,
  PricingConfig,
  BlackScholesParams,
  BlackScholesResult,
  VaRParams,
  VaRResult,
  HedgeRatioParams,
  HedgeRatioResult,
} from '@stele/derivatives';

// ─── Legal ────────────────────────────────────────────────────────────────────
export {
  JURISDICTIONS,
  registerJurisdiction,
  COMPLIANCE_STANDARDS,
  exportLegalPackage,
  mapToJurisdiction,
  generateComplianceReport,
  crossJurisdictionCompliance,
  auditTrailExport,
  regulatoryGapAnalysis,
  ComplianceSurface,
  ComplianceTrajectory,
  RemediationPlanner,
  JurisdictionConflictResolver,
  RegulatoryImpactAnalyzer,
  createComplianceMonitor,
  takeSnapshot,
  analyzeTrajectory,
  generateRegulatoryReport,
} from '@stele/legal';
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
  JurisdictionInfo,
  ComplianceStandardInfo,
  ComplianceWeights,
  RequirementDependency,
  RequirementScore,
  ComplianceSurfaceResult,
  ComplianceObservation,
  ComplianceTrajectoryResult,
  RemediationAction,
  RemediationPlanResult,
  JurisdictionalRequirement,
  JurisdictionConflict,
  ResolutionStrategy,
  ConflictResolution,
  JurisdictionConflictResult,
  RegulatoryChange,
  CovenantImpact,
  RegulatoryImpactResult,
  ComplianceMonitorConfig,
  ComplianceSnapshot,
  ComplianceAlert,
  ComplianceAutopilotTrajectory,
} from '@stele/legal';

// ─── Negotiation ──────────────────────────────────────────────────────────────
export {
  initiate as initiateNegotiation,
  propose,
  counter,
  agree,
  evaluate as evaluateNegotiation,
  isExpired as isNegotiationExpired,
  fail as failNegotiation,
  roundCount,
  computeNashBargainingSolution,
  paretoFrontier,
  computeNPartyNash,
  ConcessionProtocol,
  IncrementalParetoFrontier,
  zeuthenStrategy,
  runZeuthenNegotiation,
} from '@stele/negotiation';
export type {
  NegotiationSession,
  Proposal,
  NegotiationPolicy,
  UtilityFunction,
  Outcome,
  NashBargainingSolution,
  ParetoOutcome,
  NPartyNashConfig,
  NPartyNashResult,
  ConcessionState,
  ConcessionEvent,
  ConcessionConfig,
  ZeuthenResult,
} from '@stele/negotiation';

// ─── Temporal ─────────────────────────────────────────────────────────────────
export {
  defineEvolution,
  evaluateTriggers,
  canEvolve,
  evolve,
  evolutionHistory,
  computeDecaySchedule,
  expirationForecast,
  DecayModel,
  ContinuousTrigger,
  ViolationForecaster,
  TemporalConstraintAlgebra,
  DEFAULT_GOVERNANCE_BOOTSTRAP,
  initializeGovernance,
  evaluatePhaseTransition,
  transitionPhase,
  computeVotingPower,
} from '@stele/temporal';
export type {
  TriggerType,
  TriggerAction,
  EvolutionPolicy as TemporalEvolutionPolicy,
  EvolutionTrigger,
  TransitionFunction,
  EvolutionEvent,
  AgentState,
  CovenantState,
  DecayPoint,
  ViolationRecord,
  ExpirationForecastResult,
  DecayModelType,
  DecayModelConfig,
  ContinuousTriggerConfig,
  ContinuousTriggerResult,
  ForecastConfig,
  ForecastPoint,
  ForecastResult,
  TemporalConstraint,
  TemporalAlgebraResult,
  GovernancePhase,
  GovernanceState,
  GovernanceBootstrapConfig,
} from '@stele/temporal';

// ─── Discovery ─────────────────────────────────────────────────────────────────
export {
  DiscoveryClient,
  DiscoveryServer,
  buildDiscoveryDocument,
  validateDiscoveryDocument,
  buildKeyEntry,
  buildKeySet,
  WELL_KNOWN_PATH,
  CONFIGURATION_PATH,
  STELE_MEDIA_TYPE,
  MAX_DOCUMENT_AGE_MS,
  createFederationConfig,
  addResolver,
  removeResolver,
  resolveAgent,
  selectOptimalResolvers,
  createMarketplace,
  listAgent,
  searchMarketplace,
  createTransaction as createMarketplaceTransaction,
  completeTransaction,
  disputeTransaction,
} from '@stele/discovery';
export type {
  DiscoveryDocument,
  AgentKeyEntry,
  AgentKeySet,
  CovenantRegistryEntry,
  CovenantRegistryResponse,
  NegotiationRequest,
  NegotiationResponse,
  CrossPlatformVerificationRequest,
  CrossPlatformVerificationResponse,
  FetchOptions,
  BuildDiscoveryDocumentOptions,
  DiscoveryValidationResult,
  DiscoveryClientOptions,
  DiscoveryServerOptions,
  RouteHandler,
  FederatedResolver,
  FederationConfig,
  ResolutionResult,
  MarketplaceListing,
  MarketplaceConfig,
  MarketplaceQuery,
  MarketplaceTransaction,
} from '@stele/discovery';

// ─── Schema ────────────────────────────────────────────────────────────────────
export {
  COVENANT_SCHEMA,
  DISCOVERY_DOCUMENT_SCHEMA,
  AGENT_KEY_SCHEMA,
  CCL_EVALUATION_CONTEXT_SCHEMA,
  validateCovenantSchema,
  validateDiscoverySchema,
  validateAgentKeySchema,
  getAllSchemas,
} from '@stele/schema';
export type {
  SchemaValidationError,
  SchemaValidationResult,
} from '@stele/schema';
