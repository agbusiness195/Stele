export interface CompositionProof {
  agents: string[];
  individualCovenants: string[];
  composedConstraints: ComposedConstraint[];
  systemProperties: SystemProperty[];
  proof: string;
}

export interface ComposedConstraint {
  source: string;
  constraint: string;
  type: 'permit' | 'deny' | 'require' | 'limit';
}

export interface SystemProperty {
  property: string;
  holds: boolean;
  derivedFrom: string[];
}

export interface CovenantSummary {
  id: string;
  agentId: string;
  constraints: string[];
}

export interface DecomposedCovenant {
  /** Original covenant ID this was extracted from */
  sourceCovenantId: string;
  /** Agent that owns this sub-covenant */
  agentId: string;
  /** Single atomic constraint */
  constraint: string;
  /** Type of the constraint */
  type: 'permit' | 'deny' | 'require' | 'limit';
}

export interface CompositionComplexityResult {
  /** Total number of rules across all covenants */
  totalRules: number;
  /** Maximum nesting depth of conditions */
  maxConditionDepth: number;
  /** Number of distinct agents */
  agentCount: number;
  /** Number of conflicts (permit-deny overlaps) */
  conflictCount: number;
  /** Number of distinct action patterns */
  distinctActions: number;
  /** Number of distinct resource patterns */
  distinctResources: number;
  /** Complexity score: weighted combination of factors (0 = trivial, higher = more complex) */
  score: number;
}

// ---------------------------------------------------------------------------
// Trust Algebra types
// ---------------------------------------------------------------------------

export interface TrustValue {
  /** Trust dimensions with numeric values, e.g. { integrity: 0.9, competence: 0.8 } */
  dimensions: Record<string, number>;
  /** Confidence level from 0 to 1 */
  confidence: number;
}

export interface AlgebraicProof {
  /** Name of the algebraic property being tested */
  property: string;
  /** Whether the property holds for the tested samples */
  holds: boolean;
  /** A counterexample if the property does not hold */
  counterexample?: { a: TrustValue; b: TrustValue; c?: TrustValue };
}

// ---------------------------------------------------------------------------
// Bounded Self-Improvement types
// ---------------------------------------------------------------------------

export interface SafetyEnvelope {
  /** Properties that must always hold */
  invariants: string[];
  /** Parameter ranges with current values */
  parameterRanges: Record<string, { min: number; max: number; current: number }>;
  /** Kernel functions that cannot change */
  immutableKernel: string[];
}

export interface ImprovementProposal {
  /** Unique identifier for this proposal */
  id: string;
  /** Parameter being modified */
  parameter: string;
  /** Current value of the parameter */
  currentValue: number;
  /** Proposed new value */
  proposedValue: number;
  /** Expected improvement (positive = better) */
  expectedImprovement: number;
  /** Whether the proposal has been verified safe */
  safetyVerified: boolean;
  /** Rollback plan to restore previous value */
  rollbackPlan: { parameter: string; restoreValue: number };
}

export interface ImprovementResult {
  /** The proposal that was evaluated */
  proposal: ImprovementProposal;
  /** Whether the improvement was applied */
  applied: boolean;
  /** Reason for applying or rejecting */
  reason: string;
  /** The new envelope state after evaluation */
  newEnvelope: SafetyEnvelope;
}

// ---------------------------------------------------------------------------
// Trust Lattice & Delegation types
// ---------------------------------------------------------------------------

export interface PartialTrust {
  /** The trust assessment */
  value: TrustValue;
  /** Dimensions this trust applies to (e.g., ['integrity', 'competence']) */
  scope: string[];
  /** Who issued this trust assessment */
  source: string;
  /** Timestamp: when this trust becomes valid */
  validFrom: number;
  /** Timestamp: when this trust expires */
  validUntil: number;
}

export interface AttenuatedDelegation {
  /** Who is delegating */
  delegator: string;
  /** Who receives delegation */
  delegate: string;
  /** The trust being delegated */
  trust: TrustValue;
  /** Factor in [0,1] reducing trust through delegation */
  attenuation: number;
  /** Maximum delegation chain depth */
  maxDepth: number;
}

export interface TrustLatticeResult {
  /** Result of meet operation on the first two samples */
  meetResult: TrustValue;
  /** Result of join operation on the first two samples */
  joinResult: TrustValue;
  /** Whether meet and join satisfy lattice axioms for the sample */
  isLattice: boolean;
  /** Whether absorption holds: a ∨ (a ∧ b) = a */
  absorptionHolds: boolean;
  /** Whether idempotent holds: a ∨ a = a, a ∧ a = a */
  idempotentHolds: boolean;
}
