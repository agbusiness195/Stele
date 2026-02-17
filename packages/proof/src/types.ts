import type { HashHex } from '@stele/crypto';

/**
 * A zero-knowledge compliance proof attesting that audit log entries
 * satisfy the constraints defined in a covenant.
 */
export interface ComplianceProof {
  /** Schema version for forward compatibility */
  version: '1.0';
  /** The covenant this proof is generated for */
  covenantId: HashHex;
  /** Poseidon commitment over all audit log entries */
  auditLogCommitment: HashHex;
  /** Poseidon commitment over the constraint set */
  constraintCommitment: HashHex;
  /** The proof value (Poseidon hash of commitments for v0.1, JSON-encoded Groth16Proof for groth16) */
  proof: string;
  /** Public inputs visible to any verifier */
  publicInputs: string[];
  /** Which proof system was used */
  proofSystem: 'poseidon_hash' | 'groth16' | 'plonk';
  /** ISO 8601 timestamp when the proof was generated */
  generatedAt: string;
  /** Number of audit entries covered by this proof */
  entryCount: number;
}

/**
 * Result of verifying a compliance proof.
 */
export interface ProofVerificationResult {
  /** Whether the proof is valid */
  valid: boolean;
  /** The covenant the proof claims to cover */
  covenantId: HashHex;
  /** Number of entries covered */
  entryCount: number;
  /** Detailed error messages if verification failed */
  errors: string[];
}

/**
 * Options for generating a compliance proof.
 */
export interface ProofGenerationOptions {
  /** The covenant ID to bind this proof to */
  covenantId: HashHex;
  /** The constraint definitions (CCL source or canonical string) */
  constraints: string;
  /** Audit log entries to prove compliance over */
  auditEntries: AuditEntryData[];
  /** Proof system to use */
  proofSystem?: 'poseidon_hash' | 'groth16';
}

/**
 * Minimal audit entry data needed for proof generation.
 */
export interface AuditEntryData {
  /** The action that was taken */
  action: string;
  /** The resource the action targeted */
  resource: string;
  /** The enforcement outcome */
  outcome: 'EXECUTED' | 'DENIED' | 'IMPOSSIBLE';
  /** ISO 8601 timestamp of the action */
  timestamp: string;
  /** SHA-256 hash of the full audit entry */
  hash: HashHex;
}

// ---------------------------------------------------------------------------
// Groth16 ZK-SNARK types
// ---------------------------------------------------------------------------

/**
 * A simulated Groth16 proof consisting of three elliptic curve points
 * on the BN254 curve (represented as hex-encoded field elements) and
 * a verification key hash.
 *
 * In a real Groth16 system:
 * - `a` is a point on G1 (the "A" element of the proof)
 * - `b` is a point on G2 (the "B" element of the proof)
 * - `c` is a point on G1 (the "C" element of the proof)
 * - The pairing check is: e(A, B) = e(alpha, beta) * e(sum(pubInput_i * vk_i), gamma) * e(C, delta)
 */
export interface Groth16Proof {
  /** Proof element A — G1 point (hex-encoded field element) */
  a: string;
  /** Proof element B — G2 point (hex-encoded field element) */
  b: string;
  /** Proof element C — G1 point (hex-encoded field element) */
  c: string;
  /** Hash of the verification key, binds proof to a specific circuit */
  vkHash: string;
}

/**
 * Private witness data for a ZK circuit.
 *
 * The witness contains all private inputs that the prover knows
 * but does not reveal to the verifier. In a compliance proof context,
 * this includes the individual audit entry commitments and their
 * relationship to the constraint set.
 */
export interface ZKWitness {
  /** Per-entry private commitments (Poseidon hashes of entry data) */
  privateCommitments: bigint[];
  /** Blinding factors used to hide individual values */
  blindingFactors: bigint[];
  /** The accumulated private state (chained Poseidon of all commitments) */
  accumulatedState: bigint;
  /** Constraint satisfaction signals (one per entry, each is Poseidon(entry, constraint)) */
  constraintSignals: bigint[];
}

/**
 * A single R1CS-style constraint in the ZK circuit.
 *
 * Represents the relation: commitment is bound to auditValue
 * via the constraint Poseidon(commitment, auditValue) = output.
 */
export interface CircuitConstraint {
  /** The commitment value (public or private) */
  commitment: bigint;
  /** The audit value being constrained */
  auditValue: bigint;
  /** The constraint output: Poseidon(commitment, auditValue) */
  output: bigint;
}
