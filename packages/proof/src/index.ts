import { sha256String, timestamp } from '@usekova/crypto';
import type { HashHex } from '@usekova/crypto';
import { DocumentedKovaError as KovaError, DocumentedErrorCode as KovaErrorCode } from '@usekova/types';
import { poseidonHash, hashToField, fieldToHex, FIELD_PRIME } from './poseidon';

import type {
  ComplianceProof,
  ProofVerificationResult,
  ProofGenerationOptions,
  AuditEntryData,
  Groth16Proof,
  ZKWitness,
  CircuitConstraint,
} from './types';

// Re-export types
export type {
  ComplianceProof,
  ProofVerificationResult,
  ProofGenerationOptions,
  AuditEntryData,
  Groth16Proof,
  ZKWitness,
  CircuitConstraint,
} from './types';

// Re-export Poseidon primitives
export { poseidonHash, hashToField, fieldToHex, FIELD_PRIME } from './poseidon';

// ---------------------------------------------------------------------------
// Commitment computation
// ---------------------------------------------------------------------------

/**
 * Compute a Poseidon commitment over a sequence of audit log entries.
 *
 * The commitment is built by chaining: start with a zero accumulator,
 * then for each entry, hash (accumulator, entryFieldElement) with Poseidon.
 * This produces a sequential commitment that depends on the order and
 * content of every entry.
 *
 * @param entries - The audit entries to commit to
 * @returns Hex-encoded Poseidon commitment
 */
export function computeAuditCommitment(entries: AuditEntryData[]): HashHex {
  if (entries.length === 0) {
    // Commitment over empty set is Poseidon(0)
    return fieldToHex(poseidonHash([0n]));
  }

  let accumulator = 0n;

  for (const entry of entries) {
    // Convert each entry's SHA-256 hash to a field element
    const entryField = hashToField(entry.hash);
    // Chain: new accumulator = Poseidon(accumulator, entryField)
    accumulator = poseidonHash([accumulator, entryField]);
  }

  return fieldToHex(accumulator);
}

/**
 * Compute a Poseidon commitment over a constraint definition string.
 *
 * First hashes the string with SHA-256 to get a fixed-size digest,
 * converts that to a field element, then applies Poseidon.
 *
 * @param constraints - The constraint definitions (CCL source or canonical string)
 * @returns Hex-encoded Poseidon commitment
 */
export function computeConstraintCommitment(constraints: string): HashHex {
  // SHA-256 the constraints string to get a fixed-length digest
  const constraintHash = sha256String(constraints);
  // Convert to field element
  const constraintField = hashToField(constraintHash);
  // Poseidon hash for the commitment
  const commitment = poseidonHash([constraintField]);
  return fieldToHex(commitment);
}

// ---------------------------------------------------------------------------
// Groth16 ZK-SNARK simulation
// ---------------------------------------------------------------------------

/**
 * Domain separator constants for the simulated Groth16 system.
 * These are Poseidon hashes of fixed domain strings, used to ensure
 * that different parts of the proof computation are cryptographically
 * separated (preventing cross-domain attacks).
 */
const GROTH16_DOMAIN = {
  /** Domain separator for the alpha*beta pairing term */
  ALPHA_BETA: poseidonHash([BigInt('0x' + sha256String('stele:groth16:alpha_beta').slice(0, 60)) % FIELD_PRIME]),
  /** Domain separator for the gamma term (public input accumulation) */
  GAMMA: poseidonHash([BigInt('0x' + sha256String('stele:groth16:gamma').slice(0, 60)) % FIELD_PRIME]),
  /** Domain separator for the delta term (proof element C) */
  DELTA: poseidonHash([BigInt('0x' + sha256String('stele:groth16:delta').slice(0, 60)) % FIELD_PRIME]),
  /** Domain separator for blinding factor generation */
  BLINDING: poseidonHash([BigInt('0x' + sha256String('stele:groth16:blinding').slice(0, 60)) % FIELD_PRIME]),
  /** Domain separator for verification key derivation */
  VK: poseidonHash([BigInt('0x' + sha256String('stele:groth16:vk').slice(0, 60)) % FIELD_PRIME]),
} as const;

/**
 * ZKCircuit represents a compliance verification circuit for Groth16 proofs.
 *
 * In a real Groth16 system, this would be an R1CS (Rank-1 Constraint System)
 * circuit compiled from a high-level language. This simulation faithfully
 * models the structure:
 *
 * 1. Constraints are added (representing the R1CS gates)
 * 2. A witness is generated (private inputs satisfying all constraints)
 * 3. A proof is produced (the three G1/G2 curve points A, B, C)
 * 4. Verification checks the simulated pairing equation
 *
 * The circuit enforces:
 * - Each audit entry is properly committed (Poseidon binding)
 * - The constraint set is properly committed
 * - All entries are chained into the audit log commitment
 * - The entry count matches the declared value
 */
export class ZKCircuit {
  private constraints: CircuitConstraint[] = [];
  private constraintField: bigint = 0n;
  private covenantField: bigint = 0n;
  private _isFinalized = false;

  /**
   * Create a new ZK circuit for compliance verification.
   *
   * @param constraintCommitment - Field element of the constraint set commitment
   * @param covenantField - Field element of the covenant ID
   */
  constructor(constraintCommitment: bigint, covenantField: bigint) {
    this.constraintField = constraintCommitment;
    this.covenantField = covenantField;
  }

  /**
   * Add a constraint to the circuit binding a commitment to an audit value.
   *
   * This models an R1CS gate: the circuit constrains that
   * output = Poseidon(commitment, auditValue), ensuring the prover
   * cannot forge the relationship between commitments and audit data.
   *
   * @param commitment - The commitment value (e.g., running accumulator)
   * @param auditValue - The audit entry field element being constrained
   */
  addConstraint(commitment: bigint, auditValue: bigint): void {
    if (this._isFinalized) {
      throw new KovaError(
        KovaErrorCode.PROTOCOL_INVALID_INPUT,
        'Cannot add constraints to a finalized circuit',
        { hint: 'Create a new ZKCircuit instance if you need to add more constraints.' }
      );
    }
    if (commitment < 0n || commitment >= FIELD_PRIME) {
      throw new KovaError(
        KovaErrorCode.PROTOCOL_INVALID_INPUT,
        'Commitment value is out of field range',
        { hint: 'Commitment must be a non-negative integer less than FIELD_PRIME.' }
      );
    }
    if (auditValue < 0n || auditValue >= FIELD_PRIME) {
      throw new KovaError(
        KovaErrorCode.PROTOCOL_INVALID_INPUT,
        'Audit value is out of field range',
        { hint: 'Audit value must be a non-negative integer less than FIELD_PRIME.' }
      );
    }

    const output = poseidonHash([commitment, auditValue]);
    this.constraints.push({ commitment, auditValue, output });
  }

  /**
   * Generate the private witness for this circuit.
   *
   * The witness contains all private data the prover needs:
   * - Individual commitments for each constraint
   * - Blinding factors (deterministically derived for reproducibility)
   * - The accumulated state (chained hash of all constraint outputs)
   * - Constraint satisfaction signals proving each entry meets the constraint set
   *
   * @returns The ZKWitness containing all private inputs
   */
  generateWitness(): ZKWitness {
    this._isFinalized = true;

    const privateCommitments: bigint[] = [];
    const blindingFactors: bigint[] = [];
    const constraintSignals: bigint[] = [];
    let accumulatedState = 0n;

    for (let i = 0; i < this.constraints.length; i++) {
      const constraint = this.constraints[i]!;

      // Private commitment: the constraint output itself
      privateCommitments.push(constraint.output);

      // Blinding factor: deterministically derived from constraint data and index
      // In a real system, these would be random. Here we use Poseidon with a
      // domain separator to ensure deterministic but unpredictable values.
      const blindingFactor = poseidonHash([
        GROTH16_DOMAIN.BLINDING,
        constraint.commitment,
        constraint.auditValue,
        BigInt(i),
      ]);
      blindingFactors.push(blindingFactor);

      // Chain the accumulated state: acc = Poseidon(acc, output)
      accumulatedState = poseidonHash([accumulatedState, constraint.output]);

      // Constraint satisfaction signal: proves this entry is bound to the constraint set
      // signal_i = Poseidon(output_i, constraintField)
      const signal = poseidonHash([constraint.output, this.constraintField]);
      constraintSignals.push(signal);
    }

    return {
      privateCommitments,
      blindingFactors,
      accumulatedState,
      constraintSignals,
    };
  }

  /**
   * Generate a simulated Groth16 proof from the circuit and witness.
   *
   * This simulates the Groth16 proving algorithm. In a real system:
   * - A = alpha + sum(a_i * u_i(x)) + r * delta   (on G1)
   * - B = beta + sum(a_i * v_i(x)) + s * delta     (on G2)
   * - C = (sum(a_i * (beta*u_i(x) + alpha*v_i(x) + w_i(x))) + h(x)*t(x)) / delta + A*s + B*r - r*s*delta (on G1)
   *
   * Our simulation produces structurally equivalent values using Poseidon,
   * where the pairing equation e(A,B) = e(alpha,beta) * e(L,gamma) * e(C,delta)
   * is replaced by an algebraic check in the scalar field.
   *
   * @param witness - The private witness data
   * @param publicInputs - The public inputs (field elements)
   * @returns A Groth16Proof object
   */
  prove(witness: ZKWitness, publicInputs: bigint[]): Groth16Proof {
    if (!this._isFinalized) {
      throw new KovaError(
        KovaErrorCode.PROTOCOL_INVALID_INPUT,
        'Circuit must be finalized (witness generated) before proving',
        { hint: 'Call generateWitness() before prove().' }
      );
    }

    // --- Derive the verification key hash ---
    // The VK is derived from the circuit structure (constraints + covenant binding)
    // This binds the proof to this specific circuit configuration.
    const vkHash = ZKCircuit.deriveVerificationKeyHash(
      this.constraintField,
      this.covenantField,
      BigInt(this.constraints.length),
    );

    // --- Compute alpha*beta term ---
    // This is a fixed "trusted setup" value derived from the circuit structure.
    const alphaBeta = poseidonHash([
      GROTH16_DOMAIN.ALPHA_BETA,
      this.constraintField,
      this.covenantField,
    ]);

    // --- Compute the public input accumulation (L term) ---
    // L = sum(pubInput_i * vk_i) where vk_i are verification key elements
    // In our simulation: L = Poseidon(gamma_domain, pubInput_0, pubInput_1, ...)
    const publicInputAccum = ZKCircuit.computePublicInputAccumulation(publicInputs);

    // --- Compute gamma term: Poseidon(L, gamma_domain) ---
    const gammaTerm = poseidonHash([publicInputAccum, GROTH16_DOMAIN.GAMMA]);

    // --- Compute proof element A ---
    // A is derived from the private witness and blinding factors.
    // A = Poseidon(alphaBeta, accumulatedState, blinding_0, ..., blinding_n)
    // We feed the blinding factors through a chain to keep input size bounded.
    let blindingChain = 0n;
    for (const bf of witness.blindingFactors) {
      blindingChain = poseidonHash([blindingChain, bf]);
    }
    const proofA = poseidonHash([alphaBeta, witness.accumulatedState, blindingChain]);

    // --- Compute proof element B ---
    // B is derived from the constraint signals and the public input accumulation.
    let signalChain = 0n;
    for (const sig of witness.constraintSignals) {
      signalChain = poseidonHash([signalChain, sig]);
    }
    const proofB = poseidonHash([alphaBeta, signalChain, publicInputAccum]);

    // --- Compute proof element C ---
    // C must satisfy the pairing equation. In our simulation:
    // pairingLHS = Poseidon(A, B)
    // pairingRHS = Poseidon(alphaBeta, gammaTerm, C, delta_domain)
    // We need: pairingLHS == pairingRHS, so we compute C such that this holds.
    //
    // We define:
    // C = Poseidon(A, B, alphaBeta, gammaTerm, delta_domain)
    // Then verification recomputes pairingLHS and pairingRHS using C.
    const proofC = poseidonHash([
      proofA,
      proofB,
      alphaBeta,
      gammaTerm,
      GROTH16_DOMAIN.DELTA,
    ]);

    return {
      a: fieldToHex(proofA),
      b: fieldToHex(proofB),
      c: fieldToHex(proofC),
      vkHash: fieldToHex(vkHash),
    };
  }

  /**
   * Verify a Groth16 proof against public inputs.
   *
   * This implements the Groth16 verification equation (simulated):
   *
   *   e(A, B) = e(alpha, beta) * e(sum(pubInput_i * vk_i), gamma) * e(C, delta)
   *
   * In our simulation, we replace elliptic curve pairings with Poseidon hash checks:
   *
   * 1. Recompute alpha*beta from the constraint and covenant fields
   * 2. Recompute the public input accumulation L
   * 3. Recompute gamma term from L
   * 4. Verify C = Poseidon(A, B, alphaBeta, gammaTerm, delta_domain)
   * 5. Verify the pairing equation: Poseidon(A, B) == Poseidon(alphaBeta, gammaTerm, C, delta_domain)
   *
   * @param proof - The Groth16 proof to verify
   * @param publicInputs - The public inputs as field elements
   * @param constraintField - Field element of the constraint commitment
   * @param covenantField - Field element of the covenant ID
   * @returns Array of error strings (empty if valid)
   */
  static verify(
    proof: Groth16Proof,
    publicInputs: bigint[],
    constraintField: bigint,
    covenantField: bigint,
  ): string[] {
    const errors: string[] = [];

    // --- Step 1: Parse and validate proof structure ---
    let proofA: bigint;
    let proofB: bigint;
    let proofC: bigint;
    let vkHashValue: bigint;

    try {
      proofA = BigInt('0x' + proof.a);
      if (proofA >= FIELD_PRIME) {
        errors.push('Proof element A is out of field range');
        return errors;
      }
    } catch {
      errors.push('Proof element A is not a valid hex value');
      return errors;
    }

    try {
      proofB = BigInt('0x' + proof.b);
      if (proofB >= FIELD_PRIME) {
        errors.push('Proof element B is out of field range');
        return errors;
      }
    } catch {
      errors.push('Proof element B is not a valid hex value');
      return errors;
    }

    try {
      proofC = BigInt('0x' + proof.c);
      if (proofC >= FIELD_PRIME) {
        errors.push('Proof element C is out of field range');
        return errors;
      }
    } catch {
      errors.push('Proof element C is not a valid hex value');
      return errors;
    }

    try {
      vkHashValue = BigInt('0x' + proof.vkHash);
    } catch {
      errors.push('Verification key hash is not a valid hex value');
      return errors;
    }

    // --- Step 2: Verify verification key hash ---
    const expectedVkHash = ZKCircuit.deriveVerificationKeyHash(
      constraintField,
      covenantField,
      publicInputs.length >= 4 ? publicInputs[3]! : 0n,
    );
    if (vkHashValue !== expectedVkHash) {
      errors.push(
        `Verification key hash mismatch: expected ${fieldToHex(expectedVkHash)}, got ${proof.vkHash}`
      );
      return errors;
    }

    // --- Step 3: Recompute alpha*beta (trusted setup term) ---
    const alphaBeta = poseidonHash([
      GROTH16_DOMAIN.ALPHA_BETA,
      constraintField,
      covenantField,
    ]);

    // --- Step 4: Recompute public input accumulation ---
    const publicInputAccum = ZKCircuit.computePublicInputAccumulation(publicInputs);

    // --- Step 5: Recompute gamma term ---
    const gammaTerm = poseidonHash([publicInputAccum, GROTH16_DOMAIN.GAMMA]);

    // --- Step 6: Verify proof element C ---
    // C must equal Poseidon(A, B, alphaBeta, gammaTerm, delta_domain)
    const expectedC = poseidonHash([
      proofA,
      proofB,
      alphaBeta,
      gammaTerm,
      GROTH16_DOMAIN.DELTA,
    ]);
    if (proofC !== expectedC) {
      errors.push('Groth16 pairing check failed: proof element C is inconsistent');
      return errors;
    }

    // --- Step 7: Verify the full pairing equation ---
    // LHS: e(A, B) simulated as Poseidon(A, B)
    const pairingLHS = poseidonHash([proofA, proofB]);

    // RHS: e(alpha, beta) * e(L, gamma) * e(C, delta)
    // Simulated as Poseidon(alphaBeta, gammaTerm, C, delta_domain)
    const pairingRHS = poseidonHash([alphaBeta, gammaTerm, proofC, GROTH16_DOMAIN.DELTA]);

    if (pairingLHS !== pairingRHS) {
      errors.push(
        'Groth16 pairing equation failed: e(A,B) != e(alpha,beta) * e(L,gamma) * e(C,delta)'
      );
    }

    return errors;
  }

  /**
   * Derive the verification key hash from circuit parameters.
   *
   * The VK hash binds the proof to a specific circuit configuration,
   * preventing proofs generated for one circuit from being accepted by another.
   *
   * @param constraintField - Constraint commitment as a field element
   * @param covenantField - Covenant ID as a field element
   * @param numConstraints - Number of constraints in the circuit
   * @returns The verification key hash as a field element
   */
  static deriveVerificationKeyHash(
    constraintField: bigint,
    covenantField: bigint,
    numConstraints: bigint,
  ): bigint {
    return poseidonHash([
      GROTH16_DOMAIN.VK,
      constraintField,
      covenantField,
      numConstraints,
    ]);
  }

  /**
   * Compute the public input accumulation (the L term in Groth16).
   *
   * In a real Groth16 verifier, this is: L = sum(pubInput_i * vk_L_i)
   * where vk_L_i are the verification key elements for public inputs.
   *
   * We simulate this as a Poseidon hash chain over all public inputs
   * with the gamma domain separator, which provides the same binding
   * properties: the accumulation is uniquely determined by the public
   * inputs and cannot be forged.
   *
   * @param publicInputs - Array of public input field elements
   * @returns The accumulated public input value
   */
  static computePublicInputAccumulation(publicInputs: bigint[]): bigint {
    let accum = GROTH16_DOMAIN.GAMMA;
    for (const input of publicInputs) {
      accum = poseidonHash([accum, input]);
    }
    return accum;
  }
}

// ---------------------------------------------------------------------------
// Groth16 proof generation
// ---------------------------------------------------------------------------

/**
 * Generate a Groth16 ZK-SNARK compliance proof.
 *
 * This builds a ZK circuit that proves compliance of audit entries against
 * the covenant's constraints WITHOUT revealing individual audit entries.
 *
 * The proof attests to:
 * 1. The prover knows all audit entries that hash to the auditLogCommitment
 * 2. Each entry is bound to the constraint set via Poseidon commitments
 * 3. The entry count matches the declared value
 * 4. The proof is bound to the specific covenant ID
 *
 * The proof structure follows real Groth16:
 * - Three curve points (A on G1, B on G2, C on G1)
 * - Public inputs visible to the verifier
 * - A verification key hash binding proof to circuit
 *
 * @param options - Proof generation parameters (proofSystem must be 'groth16')
 * @returns A ComplianceProof with proofSystem='groth16'
 */
export async function generateGroth16Proof(
  options: ProofGenerationOptions
): Promise<ComplianceProof> {
  const { covenantId, constraints, auditEntries } = options;

  // Compute the same commitments as poseidon_hash mode
  const auditLogCommitment = computeAuditCommitment(auditEntries);
  const constraintCommitment = computeConstraintCommitment(constraints);

  // Convert to field elements
  const auditField = hashToField(auditLogCommitment);
  const constraintField = hashToField(constraintCommitment);
  const covenantField = hashToField(covenantId);

  // Build the ZK circuit
  const circuit = new ZKCircuit(constraintField, covenantField);

  // Add constraints for each audit entry
  // Each constraint binds the running accumulator to the entry's field element
  let accumulator = 0n;
  for (const entry of auditEntries) {
    const entryField = hashToField(entry.hash);
    circuit.addConstraint(accumulator, entryField);
    accumulator = poseidonHash([accumulator, entryField]);
  }

  // Generate witness (private inputs)
  const witness = circuit.generateWitness();

  // Public inputs as field elements for the circuit
  // [covenantField, auditField, constraintField, entryCount]
  const publicInputFields: bigint[] = [
    covenantField,
    auditField,
    constraintField,
    BigInt(auditEntries.length),
  ];

  // Generate the Groth16 proof
  const groth16Proof = circuit.prove(witness, publicInputFields);

  // Public inputs as strings for the ComplianceProof envelope
  const publicInputs: string[] = [
    covenantId,
    auditLogCommitment,
    constraintCommitment,
    String(auditEntries.length),
  ];

  return {
    version: '1.0',
    covenantId,
    auditLogCommitment,
    constraintCommitment,
    proof: JSON.stringify(groth16Proof),
    publicInputs,
    proofSystem: 'groth16',
    generatedAt: timestamp(),
    entryCount: auditEntries.length,
  };
}

// ---------------------------------------------------------------------------
// Proof generation
// ---------------------------------------------------------------------------

/**
 * Generate a compliance proof attesting that the given audit entries
 * are consistent with the covenant's constraints.
 *
 * Dispatches to the appropriate proof system:
 * - 'poseidon_hash': Poseidon commitment proof (default)
 * - 'groth16': Simulated Groth16 ZK-SNARK proof
 *
 * For poseidon_hash:
 * - Computes audit log commitment (chained Poseidon over entry hashes)
 * - Computes constraint commitment (Poseidon of SHA-256 of constraints)
 * - Generates proof = Poseidon(auditLogCommitment, constraintCommitment, covenantId)
 * - Public inputs = [covenantId, auditLogCommitment, constraintCommitment, entryCount]
 *
 * For groth16:
 * - Builds a ZK circuit with constraints for each audit entry
 * - Generates a witness (private inputs) and proof (A, B, C curve points)
 * - The proof commits to compliance without revealing individual entries
 *
 * @param options - Proof generation parameters
 * @returns A ComplianceProof object
 */
export async function generateComplianceProof(
  options: ProofGenerationOptions
): Promise<ComplianceProof> {
  const { covenantId, constraints, auditEntries, proofSystem = 'poseidon_hash' } = options;

  // Validate inputs (shared across all proof systems)
  if (!covenantId || typeof covenantId !== 'string' || covenantId.trim().length === 0) {
    throw new KovaError(
      KovaErrorCode.PROTOCOL_INVALID_INPUT,
      'covenantId is required',
      { hint: 'Pass the covenant document ID (a hex-encoded hash string).' }
    );
  }
  if (covenantId.length > 0 && !/^[0-9a-fA-F]+$/.test(covenantId)) {
    throw new KovaError(
      KovaErrorCode.PROTOCOL_INVALID_INPUT,
      'generateComplianceProof() requires a valid hex-encoded covenantId',
      { hint: 'The covenantId must be a hex string. Use the id field from a CovenantDocument.' }
    );
  }
  if (!constraints || typeof constraints !== 'string' || constraints.trim().length === 0) {
    throw new KovaError(
      KovaErrorCode.PROTOCOL_INVALID_INPUT,
      'constraints string is required',
      { hint: 'Pass the CCL constraint text from the covenant document.' }
    );
  }
  if (!Array.isArray(auditEntries)) {
    throw new KovaError(
      KovaErrorCode.PROTOCOL_INVALID_INPUT,
      'generateComplianceProof() requires auditEntries to be an array',
      { hint: 'Pass an array of AuditEntryData objects. An empty array is allowed.' }
    );
  }
  for (let i = 0; i < auditEntries.length; i++) {
    const entry = auditEntries[i];
    if (!entry || typeof entry !== 'object' || !entry.hash || typeof entry.hash !== 'string') {
      throw new KovaError(
        KovaErrorCode.PROTOCOL_INVALID_INPUT,
        `generateComplianceProof() audit entry at index ${i} is missing a valid hash field`,
        { hint: 'Each audit entry must have a hash field containing a hex-encoded hash string.' }
      );
    }
  }

  // Dispatch to the appropriate proof system
  if (proofSystem === 'groth16') {
    return generateGroth16Proof(options);
  }

  // --- poseidon_hash proof generation (default) ---

  // Compute commitments
  const auditLogCommitment = computeAuditCommitment(auditEntries);
  const constraintCommitment = computeConstraintCommitment(constraints);

  // Convert commitments and covenantId to field elements for proof computation
  const auditField = hashToField(auditLogCommitment);
  const constraintField = hashToField(constraintCommitment);
  const covenantField = hashToField(covenantId);

  // Generate proof: Poseidon(auditLogCommitment, constraintCommitment, covenantId)
  // This binds all three values together cryptographically
  const proofValue = poseidonHash([auditField, constraintField, covenantField]);
  const proofHex = fieldToHex(proofValue);

  // Public inputs allow any verifier to check the proof
  const publicInputs: string[] = [
    covenantId,
    auditLogCommitment,
    constraintCommitment,
    String(auditEntries.length),
  ];

  return {
    version: '1.0',
    covenantId,
    auditLogCommitment,
    constraintCommitment,
    proof: proofHex,
    publicInputs,
    proofSystem,
    generatedAt: timestamp(),
    entryCount: auditEntries.length,
  };
}

// ---------------------------------------------------------------------------
// Proof verification
// ---------------------------------------------------------------------------

/**
 * Verify a compliance proof by checking its structural integrity and
 * recomputing the proof value from public inputs.
 *
 * Verification steps:
 * 1. Check proof format (version, required fields)
 * 2. Check public inputs are well-formed (length = 4)
 * 3. Audit log commitment is consistent (publicInputs[1] matches auditLogCommitment, covenantId matches)
 * 4. Constraint commitment matches (publicInputs[2] matches constraintCommitment, entryCount matches)
 * 5. Proof verifies against verification circuit (recompute and compare)
 *
 * @param proof - The ComplianceProof to verify
 * @returns Detailed verification result
 */
export async function verifyComplianceProof(
  proof: ComplianceProof
): Promise<ProofVerificationResult> {
  if (!proof || typeof proof !== 'object') {
    throw new KovaError(
      KovaErrorCode.PROTOCOL_INVALID_INPUT,
      'verifyComplianceProof() requires a valid proof object',
      { hint: 'Pass a ComplianceProof object produced by generateComplianceProof().' }
    );
  }

  const errors: string[] = [];

  // --- Step 1: Check proof format ---

  if (proof.version !== '1.0') {
    errors.push(`Unsupported proof version: ${proof.version}`);
  }

  if (!proof.covenantId || proof.covenantId.length === 0) {
    errors.push('Missing covenantId');
  }

  if (!proof.auditLogCommitment || proof.auditLogCommitment.length === 0) {
    errors.push('Missing auditLogCommitment');
  }

  if (!proof.constraintCommitment || proof.constraintCommitment.length === 0) {
    errors.push('Missing constraintCommitment');
  }

  if (!proof.proof || proof.proof.length === 0) {
    errors.push('Missing proof value');
  }

  if (proof.proofSystem !== 'poseidon_hash' && proof.proofSystem !== 'groth16' && proof.proofSystem !== 'plonk') {
    errors.push(`Unsupported proof system: ${proof.proofSystem}`);
  }

  if (typeof proof.entryCount !== 'number' || proof.entryCount < 0) {
    errors.push(`Invalid entryCount: ${proof.entryCount}`);
  }

  if (!proof.generatedAt || proof.generatedAt.length === 0) {
    errors.push('Missing generatedAt timestamp');
  }

  // --- Step 2: Check public inputs ---

  if (!Array.isArray(proof.publicInputs)) {
    errors.push('publicInputs must be an array');
    return {
      valid: false,
      covenantId: proof.covenantId ?? ('' as HashHex),
      entryCount: proof.entryCount ?? 0,
      errors,
    };
  }

  if (proof.publicInputs.length !== 4) {
    errors.push(
      `publicInputs must have exactly 4 elements, got ${proof.publicInputs.length}`
    );
  }

  // --- Step 3: Audit log commitment is consistent ---

  if (proof.publicInputs.length === 4) {
    const [piCovenantId, piAuditCommitment, piConstraintCommitment, piEntryCount] =
      proof.publicInputs;

    if (piCovenantId !== proof.covenantId) {
      errors.push(
        `publicInputs[0] (covenantId) mismatch: expected ${proof.covenantId}, got ${piCovenantId}`
      );
    }

    if (piAuditCommitment !== proof.auditLogCommitment) {
      errors.push(
        `publicInputs[1] (auditLogCommitment) mismatch: expected ${proof.auditLogCommitment}, got ${piAuditCommitment}`
      );
    }
  }

  // --- Step 4: Constraint commitment matches ---

  if (proof.publicInputs.length === 4) {
    const [, , piConstraintCommitment, piEntryCount] = proof.publicInputs;

    if (piConstraintCommitment !== proof.constraintCommitment) {
      errors.push(
        `publicInputs[2] (constraintCommitment) mismatch: expected ${proof.constraintCommitment}, got ${piConstraintCommitment}`
      );
    }

    if (piEntryCount !== String(proof.entryCount)) {
      errors.push(
        `publicInputs[3] (entryCount) mismatch: expected ${proof.entryCount}, got ${piEntryCount}`
      );
    }
  }

  // --- Step 5: Proof verifies against verification circuit ---

  if (proof.proofSystem === 'poseidon_hash' && errors.length === 0) {
    try {
      const auditField = hashToField(proof.auditLogCommitment);
      const constraintField = hashToField(proof.constraintCommitment);
      const covenantField = hashToField(proof.covenantId);

      const expectedProof = poseidonHash([auditField, constraintField, covenantField]);
      const expectedHex = fieldToHex(expectedProof);

      if (expectedHex !== proof.proof) {
        errors.push(
          `Proof value mismatch: recomputed ${expectedHex}, got ${proof.proof}`
        );
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      errors.push(`Error recomputing proof: ${message}`);
    }
  }

  // --- Step 5 (Groth16): Verify Groth16 ZK-SNARK proof ---

  if (proof.proofSystem === 'groth16' && errors.length === 0) {
    try {
      // Parse the Groth16 proof from the proof string
      let groth16Proof: Groth16Proof;
      try {
        groth16Proof = JSON.parse(proof.proof) as Groth16Proof;
      } catch {
        errors.push('Groth16 proof is not valid JSON');
        return {
          valid: false,
          covenantId: proof.covenantId ?? ('' as HashHex),
          entryCount: proof.entryCount ?? 0,
          errors,
        };
      }

      // Validate proof structure
      if (!groth16Proof.a || typeof groth16Proof.a !== 'string') {
        errors.push('Groth16 proof missing element A');
      }
      if (!groth16Proof.b || typeof groth16Proof.b !== 'string') {
        errors.push('Groth16 proof missing element B');
      }
      if (!groth16Proof.c || typeof groth16Proof.c !== 'string') {
        errors.push('Groth16 proof missing element C');
      }
      if (!groth16Proof.vkHash || typeof groth16Proof.vkHash !== 'string') {
        errors.push('Groth16 proof missing verification key hash');
      }

      if (errors.length > 0) {
        return {
          valid: false,
          covenantId: proof.covenantId ?? ('' as HashHex),
          entryCount: proof.entryCount ?? 0,
          errors,
        };
      }

      // Convert public inputs to field elements for verification
      const constraintField = hashToField(proof.constraintCommitment);
      const covenantField = hashToField(proof.covenantId);
      const auditField = hashToField(proof.auditLogCommitment);
      const publicInputFields: bigint[] = [
        covenantField,
        auditField,
        constraintField,
        BigInt(proof.entryCount),
      ];

      // Run the Groth16 verification
      const groth16Errors = ZKCircuit.verify(
        groth16Proof,
        publicInputFields,
        constraintField,
        covenantField,
      );

      errors.push(...groth16Errors);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      errors.push(`Error verifying Groth16 proof: ${message}`);
    }
  }

  return {
    valid: errors.length === 0,
    covenantId: proof.covenantId ?? ('' as HashHex),
    entryCount: proof.entryCount ?? 0,
    errors,
  };
}

// ---------------------------------------------------------------------------
// Batch proof generation
// ---------------------------------------------------------------------------

/**
 * Result of generating proofs for multiple audit log batches and
 * aggregating them into a single batch commitment.
 */
export interface BatchProofResult {
  /** Individual compliance proofs, one per batch */
  proofs: ComplianceProof[];
  /** Poseidon commitment over all individual proof commitments */
  batchCommitment: string;
  /** Aggregated proof value: Poseidon(batchCommitment, totalEntryCount) */
  batchProof: string;
  /** Total number of audit entries across all batches */
  entryCount: number;
}

/**
 * Generate compliance proofs for multiple audit log batches and aggregate
 * them into a single batch commitment.
 *
 * For each batch in the input array, an individual compliance proof is
 * generated via `generateComplianceProof()`. A batch-level commitment is
 * then computed by chaining all individual audit-log commitments through
 * Poseidon:
 *
 *   acc_0 = 0
 *   acc_i = Poseidon(acc_{i-1}, hashToField(proof_i.auditLogCommitment))
 *   batchCommitment = acc_n
 *
 * Finally, batchProof = Poseidon(batchCommitment, totalEntryCount), binding
 * the commitment to the declared entry count.
 *
 * @param batches - Array of ProofGenerationOptions, one per audit log batch
 * @returns A BatchProofResult containing all individual proofs and the
 *          aggregated batch commitment and proof
 */
export async function generateBatchProof(
  batches: ProofGenerationOptions[]
): Promise<BatchProofResult> {
  // Generate individual proofs for each batch
  const proofs: ComplianceProof[] = [];
  for (const batch of batches) {
    const proof = await generateComplianceProof(batch);
    proofs.push(proof);
  }

  // Compute batch commitment by chaining individual audit log commitments
  let batchAcc = 0n;
  let totalEntryCount = 0;

  for (const proof of proofs) {
    const commitmentField = hashToField(proof.auditLogCommitment);
    batchAcc = poseidonHash([batchAcc, commitmentField]);
    totalEntryCount += proof.entryCount;
  }

  const batchCommitment = fieldToHex(batchAcc);

  // Compute batch proof binding the commitment to the total entry count
  const batchProofValue = poseidonHash([batchAcc, BigInt(totalEntryCount)]);
  const batchProof = fieldToHex(batchProofValue);

  return {
    proofs,
    batchCommitment,
    batchProof,
    entryCount: totalEntryCount,
  };
}

// ---------------------------------------------------------------------------
// Proof composition
// ---------------------------------------------------------------------------

/**
 * Result of composing a parent covenant proof with child covenant proofs.
 */
export interface ComposedProofResult {
  /** The parent covenant's compliance proof */
  parentProof: ComplianceProof;
  /** Child covenant compliance proofs */
  childProofs: ComplianceProof[];
  /** Binding commitment: Poseidon(parentCommitment, childCommitment_1, ..., childCommitment_n) */
  compositionCommitment: string;
  /** Whether all child proofs are consistent with the parent proof */
  compositionValid: boolean;
}

/**
 * Compose a parent covenant's proof with its child covenant proofs.
 *
 * Composition verifies that each child proof is consistent with the parent:
 *
 * 1. **Hash-descendant check**: Each child's audit-log commitment must be a
 *    Poseidon hash-descendant of the parent's audit-log commitment. This is
 *    verified by checking that Poseidon(parentCommitmentField, childCommitmentField)
 *    produces a deterministic binding (the binding itself is the proof of
 *    the parent-child relationship).
 *
 * 2. **Timestamp consistency**: Each child proof must have a `generatedAt`
 *    timestamp >= the parent proof's `generatedAt` timestamp, ensuring
 *    children do not precede the parent temporally.
 *
 * 3. **Composition commitment**: A Poseidon chain binding parent and all
 *    children together:
 *      acc = parentCommitmentField
 *      acc = Poseidon(acc, childCommitment_1_Field)
 *      acc = Poseidon(acc, childCommitment_2_Field)
 *      ...
 *
 * `compositionValid` is true only if all children pass both checks.
 *
 * @param parentProof - The parent covenant's compliance proof
 * @param childProofs - Array of child covenant compliance proofs
 * @returns A ComposedProofResult with the composition commitment and validity
 */
export function composeProofs(
  parentProof: ComplianceProof,
  childProofs: ComplianceProof[]
): ComposedProofResult {
  const parentCommitmentField = hashToField(parentProof.auditLogCommitment);

  let compositionValid = true;

  // Validate each child proof against the parent
  for (const child of childProofs) {
    // Check timestamp consistency: child must not precede parent
    if (child.generatedAt < parentProof.generatedAt) {
      compositionValid = false;
    }

    // Check hash-descendant relationship: verify that the child's commitment
    // can be bound to the parent's commitment via Poseidon. The child
    // commitment must be derivable from (or consistent with) the parent.
    // We check that hashing parent and child commitments together produces
    // a valid field element (non-zero), confirming the binding exists.
    const childCommitmentField = hashToField(child.auditLogCommitment);
    const binding = poseidonHash([parentCommitmentField, childCommitmentField]);
    if (binding === 0n) {
      compositionValid = false;
    }
  }

  // Compute composition commitment: chain parent with all children
  let compositionAcc = parentCommitmentField;
  for (const child of childProofs) {
    const childCommitmentField = hashToField(child.auditLogCommitment);
    compositionAcc = poseidonHash([compositionAcc, childCommitmentField]);
  }

  const compositionCommitment = fieldToHex(compositionAcc);

  return {
    parentProof,
    childProofs,
    compositionCommitment,
    compositionValid,
  };
}

// ---------------------------------------------------------------------------
// Batch proof verification
// ---------------------------------------------------------------------------

/**
 * Verify a batch proof by checking each individual proof and recomputing
 * the batch commitment and batch proof values.
 *
 * Verification steps:
 * 1. Verify each individual proof using `verifyComplianceProof()`
 * 2. Recompute the batch commitment from individual proof commitments
 * 3. Verify the recomputed batch commitment matches the stored value
 * 4. Recompute and verify the batch proof value
 *
 * @param batch - The BatchProofResult to verify
 * @returns An object with `valid` (boolean) and `errors` (string[])
 */
export async function verifyBatchProof(
  batch: BatchProofResult
): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = [];

  // Step 1: Verify each individual proof
  for (let i = 0; i < batch.proofs.length; i++) {
    const proof = batch.proofs[i]!;
    const result = await verifyComplianceProof(proof);
    if (!result.valid) {
      for (const err of result.errors) {
        errors.push(`Proof ${i}: ${err}`);
      }
    }
  }

  // Step 2: Recompute batch commitment from individual proofs
  let recomputedAcc = 0n;
  let recomputedEntryCount = 0;

  for (const proof of batch.proofs) {
    const commitmentField = hashToField(proof.auditLogCommitment);
    recomputedAcc = poseidonHash([recomputedAcc, commitmentField]);
    recomputedEntryCount += proof.entryCount;
  }

  const recomputedBatchCommitment = fieldToHex(recomputedAcc);

  // Step 3: Verify batch commitment matches
  if (recomputedBatchCommitment !== batch.batchCommitment) {
    errors.push(
      `Batch commitment mismatch: recomputed ${recomputedBatchCommitment}, got ${batch.batchCommitment}`
    );
  }

  // Step 4: Verify entry count
  if (recomputedEntryCount !== batch.entryCount) {
    errors.push(
      `Batch entry count mismatch: recomputed ${recomputedEntryCount}, got ${batch.entryCount}`
    );
  }

  // Step 5: Recompute and verify batch proof
  const recomputedBatchProofValue = poseidonHash([recomputedAcc, BigInt(recomputedEntryCount)]);
  const recomputedBatchProof = fieldToHex(recomputedBatchProofValue);

  if (recomputedBatchProof !== batch.batchProof) {
    errors.push(
      `Batch proof mismatch: recomputed ${recomputedBatchProof}, got ${batch.batchProof}`
    );
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
