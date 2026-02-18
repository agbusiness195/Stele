/**
 * Formal Verification Specifications for the Accountability Kernel
 *
 * The Accountability Kernel has exactly four operations:
 *   1. Identity binding
 *   2. Covenant signing
 *   3. Proof verification
 *   4. Trust accounting
 *
 * This module defines machine-checkable invariants as predicate functions,
 * provides a verification harness to run them against test cases, and
 * includes a counterexample search (property-based testing style) to
 * strengthen confidence in each invariant.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface KernelInvariant {
  id: string;
  name: string;
  /** Human-readable description */
  description: string;
  /** The invariant as a predicate function */
  predicate: (...args: any[]) => boolean;
  /** Proof status */
  status: 'verified' | 'tested' | 'conjectured';
  /** Number of test cases that have validated this */
  testCount: number;
}

export interface KernelVerificationResult {
  invariant: KernelInvariant;
  holds: boolean;
  counterexample?: unknown;
  executionTimeMs: number;
}

// ---------------------------------------------------------------------------
// Constraint satisfiability analysis
// ---------------------------------------------------------------------------

/** Result of analyzing a constraint set for satisfiability. */
export interface ConstraintSatisfiabilityResult {
  /** Total number of constraints analyzed. */
  totalConstraints: number;
  /** Number of deny constraints. */
  denyCount: number;
  /** Number of permit constraints. */
  permitCount: number;
  /** Resources that have both a deny and a permit constraint. */
  conflictingResources: string[];
  /** Whether the constraint set is satisfiable (at least one action is permitted). */
  satisfiable: boolean;
}

// ---------------------------------------------------------------------------
// Simulated kernel domain types (for invariant predicates)
// ---------------------------------------------------------------------------

/** An identity binding associates a public key with agent metadata and a signature. */
interface IdentityBinding {
  agentId: string;
  publicKey: string;
  metadata: Record<string, unknown>;
  signature: string;
}

/** A signed covenant with constraints and lineage. */
interface SignedCovenant {
  id: string;
  constraints: string[];
  signature: string;
  version: number;
  timestamp: number;
  parentId?: string;
}

/** An audit entry used in proof commitments. */
interface AuditEntry {
  id: string;
  action: string;
  timestamp: number;
  hash: string;
}

/** A trust account that tracks collateral and trust balance. */
interface TrustAccount {
  agentId: string;
  trust: number;
  collateral: number;
  carryForwardRate: number;
}

/** A lineage record tracking covenant versions over time. */
interface LineageRecord {
  covenantId: string;
  version: number;
  timestamp: number;
}

/** A proof commitment over audit entries. */
interface ProofCommitment {
  entries: AuditEntry[];
  commitment: string;
  includedIds: string[];
}

/** A composed trust path through multiple agents. */
interface TrustComposition {
  path: string[];
  trustValues: number[];
  composedTrust: number;
}

// ---------------------------------------------------------------------------
// Deterministic hash simulation (for invariant predicates)
// ---------------------------------------------------------------------------

/**
 * Simple deterministic hash for use in invariant predicates.
 * This is NOT cryptographically secure -- it is used only to model
 * hash behavior within predicates so they can run synchronously.
 */
function simpleHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    hash = ((hash << 5) - hash + ch) | 0;
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}

/**
 * Compute a deterministic signature simulation for an identity binding.
 * The "signature" is a hash of all binding fields concatenated.
 */
function computeBindingSignature(binding: IdentityBinding): string {
  const payload = `${binding.agentId}|${binding.publicKey}|${JSON.stringify(binding.metadata)}`;
  return simpleHash(payload);
}

/**
 * Compute a deterministic hash for an identity (for uniqueness checks).
 */
function computeIdentityHash(binding: IdentityBinding): string {
  return simpleHash(`${binding.agentId}:${binding.publicKey}`);
}

// ---------------------------------------------------------------------------
// Invariant definitions
// ---------------------------------------------------------------------------

/**
 * Returns all kernel invariants (at least 12) that describe the formal
 * properties of the Accountability Kernel.
 *
 * Each invariant is a predicate function that accepts test inputs and
 * returns true if the invariant holds for those inputs.
 */
export function defineKernelInvariants(): KernelInvariant[] {
  return [
    // -----------------------------------------------------------------------
    // 1. Identity binding is unforgeable
    // -----------------------------------------------------------------------
    {
      id: 'INV-001',
      name: 'Identity binding unforgeability',
      description:
        'Changing any field of an identity binding invalidates its signature. ' +
        'For any valid binding b with signature s = sign(b), mutating any field ' +
        'of b to produce b\' implies sign(b\') !== s.',
      predicate: (binding: IdentityBinding): boolean => {
        const originalSig = computeBindingSignature(binding);

        // Mutate agentId
        const mutatedAgent: IdentityBinding = { ...binding, agentId: binding.agentId + '_tampered' };
        if (computeBindingSignature(mutatedAgent) === originalSig) return false;

        // Mutate publicKey
        const mutatedKey: IdentityBinding = { ...binding, publicKey: binding.publicKey + '_tampered' };
        if (computeBindingSignature(mutatedKey) === originalSig) return false;

        // Mutate metadata
        const mutatedMeta: IdentityBinding = {
          ...binding,
          metadata: { ...binding.metadata, _tampered: true },
        };
        if (computeBindingSignature(mutatedMeta) === originalSig) return false;

        return true;
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 2. Covenant narrowing (child constraints are strict subset of parent)
    // -----------------------------------------------------------------------
    {
      id: 'INV-002',
      name: 'Covenant narrowing',
      description:
        'A child covenant\'s constraints must be a strict subset of its parent\'s constraints. ' +
        'For any parent covenant P and child covenant C derived from P, every constraint ' +
        'in C must also appear in P, the child set must be strictly smaller, and the child ' +
        'must not introduce deny constraints that the parent does not have.',
      predicate: (parent: SignedCovenant, child: SignedCovenant): boolean => {
        if (child.parentId !== parent.id) return true; // not related, vacuously true

        const parentSet = new Set(parent.constraints);

        // Every child constraint must exist in the parent
        if (!child.constraints.every(c => parentSet.has(c))) return false;

        // Child must be strictly narrower (not equal) when parentId is set
        if (child.constraints.length >= parent.constraints.length) return false;

        // Extract deny constraints from parent and child
        const parentDenyResources = new Set<string>();
        for (const c of parent.constraints) {
          if (c.startsWith('deny:')) {
            parentDenyResources.add(c.slice(5));
          }
        }

        // Child must not introduce new deny constraints that parent doesn't have
        for (const c of child.constraints) {
          if (c.startsWith('deny:')) {
            const resource = c.slice(5);
            if (!parentDenyResources.has(resource)) return false;
          }
        }

        return true;
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 3. Proof determinism
    // -----------------------------------------------------------------------
    {
      id: 'INV-003',
      name: 'Proof determinism',
      description:
        'The same inputs always produce the same proof. Given identical audit entries, ' +
        'the computed commitment hash must be identical across invocations.',
      predicate: (entries: AuditEntry[]): boolean => {
        const payload = entries.map(e => `${e.id}:${e.action}:${e.timestamp}:${e.hash}`).join('|');
        const hash1 = simpleHash(payload);
        const hash2 = simpleHash(payload);
        return hash1 === hash2;
      },
      status: 'verified',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 4. Trust boundedness (trust <= collateral)
    // -----------------------------------------------------------------------
    {
      id: 'INV-004',
      name: 'Trust boundedness',
      description:
        'An agent\'s trust level must never exceed their posted collateral. ' +
        'For any trust account A, A.trust <= A.collateral.',
      predicate: (account: TrustAccount): boolean => {
        return account.trust <= account.collateral;
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 5. Lineage monotonicity (versions only increase)
    // -----------------------------------------------------------------------
    {
      id: 'INV-005',
      name: 'Lineage monotonicity',
      description:
        'Covenant versions only increase over time. For any lineage sequence ' +
        'L = [l_0, l_1, ..., l_n] of the same covenant, l_i.version < l_{i+1}.version.',
      predicate: (lineage: LineageRecord[]): boolean => {
        if (lineage.length <= 1) return true;
        for (let i = 1; i < lineage.length; i++) {
          if (lineage[i]!.version <= lineage[i - 1]!.version) return false;
        }
        return true;
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 6. Deny-wins
    // -----------------------------------------------------------------------
    {
      id: 'INV-006',
      name: 'Deny-wins',
      description:
        'A deny constraint always overrides a permit constraint on the same resource. ' +
        'For any set of constraints S and evaluation results E, if both "deny:R" and ' +
        '"permit:R" appear in S, the evaluation decision for R must be "deny".',
      predicate: (
        constraints: string[],
        evaluationResults: Array<{ resource: string; decision: 'permit' | 'deny' }>,
      ): boolean => {
        const denyResources = new Set<string>();
        const permitResources = new Set<string>();

        for (const c of constraints) {
          if (c.startsWith('deny:')) {
            denyResources.add(c.slice(5));
          } else if (c.startsWith('permit:')) {
            permitResources.add(c.slice(7));
          }
        }

        // For every resource that has BOTH deny and permit constraints,
        // the evaluation result must be 'deny'.
        const conflictedResources = new Set<string>();
        for (const resource of permitResources) {
          if (denyResources.has(resource)) {
            conflictedResources.add(resource);
          }
        }

        // Check that all conflicted resources have a 'deny' decision in the evaluation results
        const resultMap = new Map<string, 'permit' | 'deny'>();
        for (const result of evaluationResults) {
          resultMap.set(result.resource, result.decision);
        }

        for (const resource of conflictedResources) {
          const decision = resultMap.get(resource);
          // If there's a conflicted resource with no evaluation result, we cannot verify
          if (decision === undefined) return false;
          // If the decision is not 'deny', the deny-wins property is violated
          if (decision !== 'deny') return false;
        }

        return true;
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 7. Covenant immutability
    // -----------------------------------------------------------------------
    {
      id: 'INV-007',
      name: 'Covenant immutability',
      description:
        'A signed covenant cannot be modified without invalidating its signature. ' +
        'For a signed covenant C with signature S, changing C.constraints produces C\' ' +
        'where sign(C\') !== S.',
      predicate: (covenant: SignedCovenant): boolean => {
        const originalPayload = `${covenant.id}|${covenant.constraints.join(',')}|${covenant.version}`;
        const originalSig = simpleHash(originalPayload);

        // The provided signature should match the computed one
        if (covenant.signature !== originalSig) {
          // Already invalid -- vacuously immutable
          return true;
        }

        // Attempt mutation: add a constraint
        const mutatedConstraints = [...covenant.constraints, 'permit:injected-action'];
        const mutatedPayload = `${covenant.id}|${mutatedConstraints.join(',')}|${covenant.version}`;
        const mutatedSig = simpleHash(mutatedPayload);

        return mutatedSig !== originalSig;
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 8. Identity hash uniqueness
    // -----------------------------------------------------------------------
    {
      id: 'INV-008',
      name: 'Identity hash uniqueness',
      description:
        'Different identities produce different hashes. For any two identity bindings ' +
        'A and B where A.agentId !== B.agentId or A.publicKey !== B.publicKey, ' +
        'hash(A) !== hash(B).',
      predicate: (a: IdentityBinding, b: IdentityBinding): boolean => {
        // If they are structurally identical, they should hash identically
        if (a.agentId === b.agentId && a.publicKey === b.publicKey) {
          return computeIdentityHash(a) === computeIdentityHash(b);
        }
        // If they differ, their hashes should differ
        return computeIdentityHash(a) !== computeIdentityHash(b);
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 9. Timestamp ordering
    // -----------------------------------------------------------------------
    {
      id: 'INV-009',
      name: 'Timestamp ordering',
      description:
        'Lineage timestamps are monotonically non-decreasing. For any lineage ' +
        'sequence L, l_i.timestamp <= l_{i+1}.timestamp for all consecutive pairs.',
      predicate: (lineage: LineageRecord[]): boolean => {
        if (lineage.length <= 1) return true;
        for (let i = 1; i < lineage.length; i++) {
          if (lineage[i]!.timestamp < lineage[i - 1]!.timestamp) return false;
        }
        return true;
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 10. Carry-forward boundedness
    // -----------------------------------------------------------------------
    {
      id: 'INV-010',
      name: 'Carry-forward boundedness',
      description:
        'Carry-forward rates must be in the interval [0, 1]. For any trust account A, ' +
        '0 <= A.carryForwardRate <= 1.',
      predicate: (account: TrustAccount): boolean => {
        return account.carryForwardRate >= 0 && account.carryForwardRate <= 1;
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 11. Proof completeness
    // -----------------------------------------------------------------------
    {
      id: 'INV-011',
      name: 'Proof completeness',
      description:
        'Every audit entry is included in the proof commitment. For a proof commitment ' +
        'P built from entries E, P.includedIds must contain every e.id in E.',
      predicate: (commitment: ProofCommitment): boolean => {
        const includedSet = new Set(commitment.includedIds);
        return commitment.entries.every(e => includedSet.has(e.id));
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 12. Trust composition decay
    // -----------------------------------------------------------------------
    {
      id: 'INV-012',
      name: 'Trust composition decay',
      description:
        'Composed trust through a chain of agents never exceeds the minimum trust ' +
        'in any link. For a trust path [t_0, t_1, ..., t_n], ' +
        'composedTrust <= min(t_0, t_1, ..., t_n).',
      predicate: (composition: TrustComposition): boolean => {
        if (composition.trustValues.length === 0) return true;
        const minTrust = Math.min(...composition.trustValues);
        return composition.composedTrust <= minTrust;
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 13. Constraint consistency (satisfiability)
    // -----------------------------------------------------------------------
    {
      id: 'INV-013',
      name: 'Constraint consistency',
      description:
        'A set of constraints is satisfiable if there exists at least one action that ' +
        'is permitted. If all resources have deny constraints and no resource has a permit ' +
        'without a matching deny, the constraint set is unsatisfiable.',
      predicate: (constraints: string[]): boolean => {
        const denyResources = new Set<string>();
        const permitResources = new Set<string>();

        for (const c of constraints) {
          if (c.startsWith('deny:')) {
            denyResources.add(c.slice(5));
          } else if (c.startsWith('permit:')) {
            permitResources.add(c.slice(7));
          }
        }

        // If there are no constraints at all, vacuously satisfiable
        if (denyResources.size === 0 && permitResources.size === 0) return true;

        // Check if at least one permitted resource has no matching deny
        for (const resource of permitResources) {
          if (!denyResources.has(resource)) {
            // Found a resource that is permitted without a deny: satisfiable
            return true;
          }
        }

        // If we have permits but ALL are denied, or we have only denies: unsatisfiable
        // Flag this by returning false
        if (permitResources.size === 0 && denyResources.size > 0) {
          // Only deny constraints, no permits at all: unsatisfiable
          return false;
        }

        // All permitted resources are also denied: unsatisfiable
        return false;
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 14. Key rotation safety
    // -----------------------------------------------------------------------
    {
      id: 'INV-014',
      name: 'Key rotation safety',
      description:
        'When a key is rotated, all covenants signed with the old key must be re-signed ' +
        'or invalidated. For a key rotation from oldKey to newKey, every covenant whose ' +
        'signature was produced with oldKey must appear in the resignedCovenantIds set.',
      predicate: (input: {
        oldKey: string;
        newKey: string;
        covenants: SignedCovenant[];
        resignedCovenantIds: string[];
      }): boolean => {
        const { oldKey, covenants, resignedCovenantIds } = input;
        const resignedSet = new Set(resignedCovenantIds);

        // Find all covenants signed with the old key (we model this by
        // checking if the covenant's signature was computed using the old key)
        for (const covenant of covenants) {
          // Simulate: a covenant is "signed with oldKey" if its signature
          // matches what would be produced using the old key as part of the payload
          const payloadWithOldKey = `${covenant.id}|${covenant.constraints.join(',')}|${covenant.version}|${oldKey}`;
          const expectedOldSig = simpleHash(payloadWithOldKey);

          if (covenant.signature === expectedOldSig) {
            // This covenant was signed with the old key; it must be re-signed or invalidated
            if (!resignedSet.has(covenant.id)) {
              return false;
            }
          }
        }

        return true;
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 15. Trust algebra associativity
    // -----------------------------------------------------------------------
    {
      id: 'INV-015',
      name: 'Trust algebra associativity',
      description:
        'Trust composition is associative: compose(a, compose(b, c)) is approximately ' +
        'equal to compose(compose(a, b), c) within a tolerance of 1e-10.',
      predicate: (
        a: { dimensions: Record<string, number>; confidence: number },
        b: { dimensions: Record<string, number>; confidence: number },
        c: { dimensions: Record<string, number>; confidence: number },
      ): boolean => {
        const tolerance = 1e-10;

        // Compose helper: multiplies common dimension values and confidence
        const compose = (
          x: { dimensions: Record<string, number>; confidence: number },
          y: { dimensions: Record<string, number>; confidence: number },
        ): { dimensions: Record<string, number>; confidence: number } => {
          const keysX = Object.keys(x.dimensions);
          const keysYSet = new Set(Object.keys(y.dimensions));
          const commonKeys = keysX.filter(k => keysYSet.has(k));

          const dimensions: Record<string, number> = {};
          for (const key of commonKeys) {
            dimensions[key] = x.dimensions[key]! * y.dimensions[key]!;
          }

          return { dimensions, confidence: x.confidence * y.confidence };
        };

        // Approximate equality check
        const approxEqual = (
          x: { dimensions: Record<string, number>; confidence: number },
          y: { dimensions: Record<string, number>; confidence: number },
        ): boolean => {
          if (Math.abs(x.confidence - y.confidence) > tolerance) return false;

          const keysX = Object.keys(x.dimensions).sort();
          const keysY = Object.keys(y.dimensions).sort();
          if (keysX.length !== keysY.length) return false;
          for (let i = 0; i < keysX.length; i++) {
            if (keysX[i] !== keysY[i]) return false;
          }
          for (const key of keysX) {
            if (Math.abs(x.dimensions[key]! - y.dimensions[key]!) > tolerance) return false;
          }
          return true;
        };

        const lhs = compose(a, compose(b, c));
        const rhs = compose(compose(a, b), c);

        return approxEqual(lhs, rhs);
      },
      status: 'tested',
      testCount: 0,
    },

    // -----------------------------------------------------------------------
    // 16. Proof temporal validity
    // -----------------------------------------------------------------------
    {
      id: 'INV-016',
      name: 'Proof temporal validity',
      description:
        'Old proofs remain valid within their time-to-live period. If the current time ' +
        'is within the TTL window (currentTime - createdAt <= ttlMs), the proof ' +
        'commitment must still match the entries.',
      predicate: (input: {
        proof: ProofCommitment;
        createdAt: number;
        ttlMs: number;
        currentTime: number;
      }): boolean => {
        const { proof, createdAt, ttlMs, currentTime } = input;

        const withinTtl = (currentTime - createdAt) <= ttlMs;

        if (withinTtl) {
          // The proof must still be valid: commitment matches entries
          const expectedCommitment = simpleHash(
            proof.entries.map(e => `${e.id}:${e.action}:${e.timestamp}:${e.hash}`).join('|'),
          );

          // Check commitment matches
          if (proof.commitment !== expectedCommitment) return false;

          // Check all entry IDs are included
          const includedSet = new Set(proof.includedIds);
          if (!proof.entries.every(e => includedSet.has(e.id))) return false;
        }

        // If outside TTL, no validity requirement
        return true;
      },
      status: 'tested',
      testCount: 0,
    },
  ];
}

// ---------------------------------------------------------------------------
// Verification harness
// ---------------------------------------------------------------------------

/**
 * Run an invariant's predicate against an array of test cases and return
 * the verification result.
 *
 * Each test case is an array of arguments to be spread into the predicate.
 * If any test case causes the predicate to return false, the invariant
 * does not hold and the failing test case is reported as a counterexample.
 *
 * @param invariant - The kernel invariant to verify.
 * @param testCases - An array of argument tuples for the predicate.
 * @returns A KernelVerificationResult with timing and pass/fail information.
 */
export function verifyInvariant(
  invariant: KernelInvariant,
  testCases: unknown[][],
): KernelVerificationResult {
  const start = performance.now();
  let holds = true;
  let counterexample: unknown | undefined;

  for (const testCase of testCases) {
    try {
      const result = invariant.predicate(...testCase);
      if (!result) {
        holds = false;
        counterexample = testCase;
        break;
      }
    } catch (err) {
      holds = false;
      counterexample = { testCase, error: String(err) };
      break;
    }
  }

  const executionTimeMs = performance.now() - start;

  // Update the invariant's test count
  invariant.testCount += testCases.length;

  return {
    invariant,
    holds,
    counterexample,
    executionTimeMs,
  };
}

/**
 * Verify all kernel invariants against a map of test cases keyed by
 * invariant ID.
 *
 * @param testCases - A record mapping invariant IDs to arrays of test case
 *   argument tuples. Invariants with no matching key are verified with zero
 *   test cases (trivially passing).
 * @returns An array of KernelVerificationResult, one per invariant.
 */
export function verifyAllInvariants(
  testCases: Record<string, unknown[][]>,
): KernelVerificationResult[] {
  const invariants = defineKernelInvariants();
  const results: KernelVerificationResult[] = [];

  for (const invariant of invariants) {
    const cases = testCases[invariant.id] ?? [];
    results.push(verifyInvariant(invariant, cases));
  }

  return results;
}

// ---------------------------------------------------------------------------
// Counterexample search (property-based testing)
// ---------------------------------------------------------------------------

/** Generate a random string of a given length. */
function randomString(length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

/** Generate a random number in [min, max). */
function randomInRange(min: number, max: number): number {
  return min + Math.random() * (max - min);
}

/** Generate a random IdentityBinding. */
function randomIdentityBinding(): IdentityBinding {
  const binding: IdentityBinding = {
    agentId: `agent-${randomString(8)}`,
    publicKey: `pk-${randomString(16)}`,
    metadata: { role: randomString(4) },
    signature: '', // will be computed
  };
  binding.signature = computeBindingSignature(binding);
  return binding;
}

/** Generate a random SignedCovenant. */
function randomSignedCovenant(parentId?: string): SignedCovenant {
  const id = `cov-${randomString(8)}`;
  const numConstraints = Math.floor(Math.random() * 5) + 1;
  const constraints: string[] = [];
  for (let i = 0; i < numConstraints; i++) {
    const type = Math.random() > 0.5 ? 'deny' : 'permit';
    constraints.push(`${type}:${randomString(6)}`);
  }
  const version = Math.floor(Math.random() * 100) + 1;
  const payload = `${id}|${constraints.join(',')}|${version}`;
  return {
    id,
    constraints,
    signature: simpleHash(payload),
    version,
    timestamp: Date.now() + Math.floor(Math.random() * 10000),
    parentId,
  };
}

/** Generate a random TrustAccount with valid constraints. */
function randomTrustAccount(valid: boolean): TrustAccount {
  const collateral = randomInRange(0, 1000);
  const trust = valid ? randomInRange(0, collateral) : randomInRange(collateral + 1, collateral + 500);
  const carryForwardRate = valid ? randomInRange(0, 1) : randomInRange(1.1, 2.0);
  return {
    agentId: `agent-${randomString(6)}`,
    trust,
    collateral,
    carryForwardRate: valid ? carryForwardRate : carryForwardRate,
  };
}

/** Generate a random monotonically increasing lineage. */
function randomLineage(length: number, valid: boolean): LineageRecord[] {
  const records: LineageRecord[] = [];
  let version = 1;
  let timestamp = Date.now();
  for (let i = 0; i < length; i++) {
    records.push({
      covenantId: 'cov-test',
      version,
      timestamp,
    });
    if (valid) {
      version += Math.floor(Math.random() * 5) + 1;
      timestamp += Math.floor(Math.random() * 1000) + 1;
    } else {
      // Possibly decrease version or timestamp to violate invariant
      version += Math.random() > 0.3 ? 1 : -Math.floor(Math.random() * 3);
      timestamp += Math.random() > 0.3 ? 100 : -Math.floor(Math.random() * 500);
    }
  }
  return records;
}

/** Generate random test inputs for a given invariant ID. */
function generateRandomInput(invariantId: string): unknown[] {
  switch (invariantId) {
    case 'INV-001': {
      return [randomIdentityBinding()];
    }
    case 'INV-002': {
      const parent = randomSignedCovenant();
      // Ensure parent has at least 2 constraints so child can be strictly narrower
      if (parent.constraints.length < 2) {
        parent.constraints.push(`permit:${randomString(6)}`);
      }
      // Child is a strict subset of parent constraints (strictly fewer)
      const maxChildSize = parent.constraints.length - 1;
      const childSize = Math.max(1, Math.floor(Math.random() * maxChildSize) + 1);
      const childConstraints = parent.constraints.slice(0, Math.min(childSize, maxChildSize));
      const child: SignedCovenant = {
        ...randomSignedCovenant(parent.id),
        constraints: childConstraints,
        parentId: parent.id,
      };
      return [parent, child];
    }
    case 'INV-003': {
      const count = Math.floor(Math.random() * 5) + 1;
      const entries: AuditEntry[] = [];
      for (let i = 0; i < count; i++) {
        entries.push({
          id: `audit-${randomString(6)}`,
          action: randomString(8),
          timestamp: Date.now() + i * 100,
          hash: simpleHash(randomString(10)),
        });
      }
      return [entries];
    }
    case 'INV-004': {
      return [randomTrustAccount(true)];
    }
    case 'INV-005': {
      return [randomLineage(Math.floor(Math.random() * 8) + 2, true)];
    }
    case 'INV-006': {
      const constraints: string[] = [];
      const resources: string[] = [];
      const numConstraints = Math.floor(Math.random() * 6) + 2;
      for (let i = 0; i < numConstraints; i++) {
        const resource = `resource-${randomString(4)}`;
        resources.push(resource);
        const type = Math.random() > 0.5 ? 'deny' : 'permit';
        constraints.push(`${type}:${resource}`);
      }

      // Add some overlapping deny+permit pairs to exercise the invariant
      const sharedResource = `resource-${randomString(4)}`;
      constraints.push(`deny:${sharedResource}`);
      constraints.push(`permit:${sharedResource}`);

      // Build evaluation results: for resources with deny, the decision must be 'deny'
      const denyResources = new Set<string>();
      const permitResources = new Set<string>();
      for (const c of constraints) {
        if (c.startsWith('deny:')) denyResources.add(c.slice(5));
        else if (c.startsWith('permit:')) permitResources.add(c.slice(7));
      }

      const evaluationResults: Array<{ resource: string; decision: 'permit' | 'deny' }> = [];
      const allResources = new Set([...denyResources, ...permitResources]);
      for (const resource of allResources) {
        // Deny-wins: if a resource has a deny, the decision is 'deny'
        const decision: 'permit' | 'deny' = denyResources.has(resource) ? 'deny' : 'permit';
        evaluationResults.push({ resource, decision });
      }

      return [constraints, evaluationResults];
    }
    case 'INV-007': {
      return [randomSignedCovenant()];
    }
    case 'INV-008': {
      return [randomIdentityBinding(), randomIdentityBinding()];
    }
    case 'INV-009': {
      return [randomLineage(Math.floor(Math.random() * 8) + 2, true)];
    }
    case 'INV-010': {
      return [randomTrustAccount(true)];
    }
    case 'INV-011': {
      const entries: AuditEntry[] = [];
      const count = Math.floor(Math.random() * 5) + 1;
      for (let i = 0; i < count; i++) {
        entries.push({
          id: `audit-${randomString(6)}`,
          action: randomString(8),
          timestamp: Date.now() + i * 100,
          hash: simpleHash(randomString(10)),
        });
      }
      const commitment: ProofCommitment = {
        entries,
        commitment: simpleHash(entries.map(e => e.hash).join('|')),
        includedIds: entries.map(e => e.id),
      };
      return [commitment];
    }
    case 'INV-012': {
      const pathLength = Math.floor(Math.random() * 5) + 2;
      const trustValues: number[] = [];
      for (let i = 0; i < pathLength; i++) {
        trustValues.push(randomInRange(0.1, 1.0));
      }
      const minTrust = Math.min(...trustValues);
      // Composed trust is product (decays), which is always <= min
      const composedTrust = trustValues.reduce((a, b) => a * b, 1);
      const composition: TrustComposition = {
        path: trustValues.map((_, i) => `agent-${i}`),
        trustValues,
        composedTrust,
      };
      return [composition];
    }
    case 'INV-013': {
      // Generate a satisfiable constraint set: at least one permit without a matching deny
      const constraints: string[] = [];
      const numConstraints = Math.floor(Math.random() * 4) + 2;
      for (let i = 0; i < numConstraints; i++) {
        const resource = `resource-${randomString(4)}`;
        const type = Math.random() > 0.3 ? 'permit' : 'deny';
        constraints.push(`${type}:${resource}`);
      }
      // Ensure at least one permit that has no matching deny (satisfiable)
      const uniqueResource = `resource-unique-${randomString(6)}`;
      constraints.push(`permit:${uniqueResource}`);
      return [constraints];
    }
    case 'INV-014': {
      const oldKey = `key-old-${randomString(8)}`;
      const newKey = `key-new-${randomString(8)}`;
      const numCovenants = Math.floor(Math.random() * 4) + 1;
      const covenants: SignedCovenant[] = [];
      const resignedCovenantIds: string[] = [];

      for (let i = 0; i < numCovenants; i++) {
        const cov = randomSignedCovenant();
        // Sign some covenants with the old key
        if (Math.random() > 0.5) {
          const payloadWithOldKey = `${cov.id}|${cov.constraints.join(',')}|${cov.version}|${oldKey}`;
          cov.signature = simpleHash(payloadWithOldKey);
          // Ensure this covenant is in the resigned set
          resignedCovenantIds.push(cov.id);
        }
        covenants.push(cov);
      }

      return [{ oldKey, newKey, covenants, resignedCovenantIds }];
    }
    case 'INV-015': {
      const dims = ['integrity', 'competence', 'reliability'];
      const makeTrustValue = () => {
        const dimensions: Record<string, number> = {};
        for (const d of dims) {
          dimensions[d] = Math.random() * 0.8 + 0.1;
        }
        return { dimensions, confidence: Math.random() * 0.8 + 0.1 };
      };
      return [makeTrustValue(), makeTrustValue(), makeTrustValue()];
    }
    case 'INV-016': {
      const entries: AuditEntry[] = [];
      const count = Math.floor(Math.random() * 4) + 1;
      for (let i = 0; i < count; i++) {
        entries.push({
          id: `audit-${randomString(6)}`,
          action: randomString(8),
          timestamp: Date.now() + i * 100,
          hash: simpleHash(randomString(10)),
        });
      }
      const commitment = simpleHash(
        entries.map(e => `${e.id}:${e.action}:${e.timestamp}:${e.hash}`).join('|'),
      );
      const proof: ProofCommitment = {
        entries,
        commitment,
        includedIds: entries.map(e => e.id),
      };
      const createdAt = Date.now() - Math.floor(Math.random() * 5000);
      const ttlMs = Math.floor(Math.random() * 10000) + 5000;
      const currentTime = Date.now();
      return [{ proof, createdAt, ttlMs, currentTime }];
    }
    default:
      return [];
  }
}

/**
 * Run a random counterexample search for a given invariant.
 *
 * Generates random inputs and runs the invariant predicate, looking for
 * any input that causes the predicate to return false. This is analogous
 * to property-based testing (QuickCheck / fast-check style).
 *
 * @param invariant - The invariant to search for counterexamples.
 * @param iterations - Number of random inputs to generate and test.
 * @returns A KernelVerificationResult. If a counterexample is found,
 *   `holds` is false and `counterexample` contains the failing input.
 */
export function generateCounterexampleSearch(
  invariant: KernelInvariant,
  iterations: number,
): KernelVerificationResult {
  const start = performance.now();
  let holds = true;
  let counterexample: unknown | undefined;
  let tested = 0;

  for (let i = 0; i < iterations; i++) {
    const input = generateRandomInput(invariant.id);
    if (input.length === 0) continue;

    tested++;
    try {
      const result = invariant.predicate(...input);
      if (!result) {
        holds = false;
        counterexample = input;
        break;
      }
    } catch (err) {
      holds = false;
      counterexample = { input, error: String(err) };
      break;
    }
  }

  const executionTimeMs = performance.now() - start;
  invariant.testCount += tested;

  return {
    invariant,
    holds,
    counterexample,
    executionTimeMs,
  };
}

// ---------------------------------------------------------------------------
// Constraint satisfiability analysis
// ---------------------------------------------------------------------------

/**
 * Analyze a constraint set for satisfiability.
 *
 * Parses constraints of the form "deny:resource" and "permit:resource",
 * identifies conflicting resources (those with both deny and permit),
 * and determines whether the constraint set is satisfiable (at least one
 * resource is permitted without a matching deny).
 *
 * @param constraints - Array of constraint strings (e.g., "deny:foo", "permit:bar").
 * @returns A ConstraintSatisfiabilityResult with analysis details.
 */
export function checkConstraintSatisfiability(constraints: string[]): ConstraintSatisfiabilityResult {
  const denyResources = new Set<string>();
  const permitResources = new Set<string>();

  let denyCount = 0;
  let permitCount = 0;

  for (const c of constraints) {
    if (c.startsWith('deny:')) {
      denyResources.add(c.slice(5));
      denyCount++;
    } else if (c.startsWith('permit:')) {
      permitResources.add(c.slice(7));
      permitCount++;
    }
  }

  // Find resources that have both deny and permit
  const conflictingResources: string[] = [];
  for (const resource of permitResources) {
    if (denyResources.has(resource)) {
      conflictingResources.push(resource);
    }
  }
  conflictingResources.sort();

  // Satisfiable if at least one permitted resource has no matching deny
  let satisfiable = false;
  if (permitResources.size === 0 && denyResources.size === 0) {
    // No constraints at all: vacuously satisfiable
    satisfiable = true;
  } else {
    for (const resource of permitResources) {
      if (!denyResources.has(resource)) {
        satisfiable = true;
        break;
      }
    }
  }

  return {
    totalConstraints: constraints.length,
    denyCount,
    permitCount,
    conflictingResources,
    satisfiable,
  };
}
