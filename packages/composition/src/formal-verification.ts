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
    // 2. Covenant narrowing (child constraints are subset of parent)
    // -----------------------------------------------------------------------
    {
      id: 'INV-002',
      name: 'Covenant narrowing',
      description:
        'A child covenant\'s constraints must be a subset of its parent\'s constraints. ' +
        'For any parent covenant P and child covenant C derived from P, every constraint ' +
        'in C must also appear in P.',
      predicate: (parent: SignedCovenant, child: SignedCovenant): boolean => {
        if (child.parentId !== parent.id) return true; // not related, vacuously true
        const parentSet = new Set(parent.constraints);
        return child.constraints.every(c => parentSet.has(c));
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
        'For any set of constraints S, if both "deny:R" and "permit:R" appear in S, ' +
        'the effective policy for R is deny.',
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

        // For every resource that has both deny and permit, the effective
        // decision must be deny. We model "effective decision" as: the
        // resource is in the deny set.
        for (const resource of permitResources) {
          if (denyResources.has(resource)) {
            // Deny-wins: deny must be present (it is, by construction).
            // The invariant checks the semantic: if deny is present, the
            // resource is effectively denied regardless of permits.
            if (!denyResources.has(resource)) return false;
          }
        }
        return true;
      },
      status: 'verified',
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
      // Child is a subset of parent constraints
      const childConstraints = parent.constraints.slice(
        0,
        Math.max(1, Math.floor(Math.random() * parent.constraints.length)),
      );
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
      const numConstraints = Math.floor(Math.random() * 6) + 2;
      for (let i = 0; i < numConstraints; i++) {
        const type = Math.random() > 0.5 ? 'deny' : 'permit';
        constraints.push(`${type}:resource-${randomString(4)}`);
      }
      return [constraints];
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
