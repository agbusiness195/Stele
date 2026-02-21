# Grith Threat Model

Version: 1.0 | Last updated: 2026-02-11

## 1. System Overview

Grith is a cryptographic covenant protocol for governing AI agent behavior. It enables an **issuer** to make binding, verifiable commitments about what an AI agent (the **beneficiary**) is permitted to do. The protocol produces signed, content-addressed documents that can be independently verified by any party without trusting the issuer's infrastructure.

The security goal is **pre-operative commitment**: the issuer cannot silently modify constraints after signing, and the beneficiary can prove exactly what was agreed upon. This differs from post-hoc policy enforcement (ACLs, RBAC) where the authority can change rules without the subject's knowledge.

### Core Security Properties

- **Integrity**: Covenant documents are content-addressed (SHA-256) and signed (Ed25519). Any modification invalidates the ID and signature.
- **Non-repudiation**: Issuers cannot deny having created a covenant. The signature over the canonical form is tied to their public key.
- **Authenticity**: Only the holder of the issuer's private key can produce a valid signature.
- **Replay protection**: Each covenant includes a 256-bit cryptographic nonce.
- **Auditability**: The enforcement layer produces hash-chained, Merkle-rooted audit logs.

## 2. Trust Boundaries

| Boundary | Trust Assumption |
|---|---|
| **Issuer** | Holds private key securely. Constructs honest constraints. May be adversarial after signing (the protocol is designed for this). |
| **Beneficiary** | Verifies the covenant before relying on it. Runtime enforcement is honest (runs the evaluator faithfully, does not bypass it). |
| **Verifier** | Has access to the issuer's public key through an authentic channel. Runs the verification algorithm correctly. |
| **Store** | Persistence layer (MemoryStore, SqliteStore, FileStore). Assumed to be available but NOT trusted for integrity -- documents are verified on retrieval. |
| **Network** | Untrusted. Covenants are self-verifying; tampering in transit is detected by signature and ID checks. |
| **CCL Evaluator** | Trusted component. If the evaluator is compromised or replaced, enforcement is meaningless. |

## 3. Threat Categories (STRIDE)

### 3.1 Spoofing

| Threat | Severity | Description |
|---|---|---|
| S1: Key impersonation | Critical | An attacker obtains or forges the issuer's private key and issues covenants on their behalf. |
| S2: Identity spoofing | High | An attacker creates an AgentIdentity claiming to be a different operator by using a different key pair with the same operator identifier string. |
| S3: Countersignature spoofing | Medium | An attacker adds a countersignature from a key pair they control, claiming the role of "auditor" or "regulator". |

**Mitigations**:
- S1: Ed25519 keys are 256-bit; brute-force is computationally infeasible. Key compromise is mitigated by key rotation (`KeyManager`) and the overlap period that allows graceful transition. The protocol itself does not manage key distribution -- this is explicitly delegated to the operator (see Residual Risks).
- S2: Identity verification (`verifyIdentity()`) checks the operator signature, but operator identifiers are self-asserted strings. A public key directory or out-of-band verification is required for strong identity binding.
- S3: Countersignatures include the signer's public key. Verifiers must check that the public key belongs to a trusted auditor through an external trust registry.

### 3.2 Tampering

| Threat | Severity | Description |
|---|---|---|
| T1: Covenant modification | Critical | An attacker modifies the constraints, parties, or metadata of a signed covenant. |
| T2: Audit log manipulation | High | An attacker inserts, deletes, or reorders entries in the enforcement audit log. |
| T3: CCL constraint injection | Medium | Malformed or adversarial CCL input causes the parser to produce unintended constraint semantics. |
| T4: Chain parent substitution | High | An attacker replaces the parent document in a chain with a more permissive covenant. |

**Mitigations**:
- T1: The document ID is the SHA-256 hash of the canonical form (JCS/RFC 8785). The signature covers this canonical form. Any modification changes the hash and invalidates both the ID and signature. Verification checks both (`id_match` and `signature_valid`).
- T2: Audit entries are hash-chained (each entry includes the hash of the previous entry). The `Monitor` class computes a Merkle root over all entries. Integrity can be verified with `verifyAuditLogIntegrity()` and individual entries can be proven with `generateMerkleProof()`.
- T3: The CCL parser validates syntax strictly. Unknown tokens produce `CCLSyntaxError`. The evaluator uses default-deny semantics, so a parsing failure results in denial, not permission. Constraint count is capped at `MAX_CONSTRAINTS` (1000).
- T4: Chain validation (`validateChain()`) verifies that each child's `chain.parentId` matches the parent's computed ID. The parent ID is a SHA-256 hash, so substitution requires finding a collision.

### 3.3 Repudiation

| Threat | Severity | Description |
|---|---|---|
| R1: Denying covenant issuance | High | An issuer claims they never created a covenant that exists with their valid signature. |
| R2: Denying identity evolution | Medium | An operator denies having evolved an agent identity. |

**Mitigations**:
- R1: The Ed25519 signature is non-repudiable given that the private key was not compromised. The document is content-addressed, so the exact content that was signed is deterministically reproducible. Countersignatures from third-party auditors provide additional witnesses.
- R2: Each lineage entry in an AgentIdentity is individually signed. The lineage chain forms a hash-linked history. Verifiers can walk the chain to prove the sequence of changes.

### 3.4 Information Disclosure

| Threat | Severity | Description |
|---|---|---|
| I1: Private key leakage | Critical | The issuer's or beneficiary's Ed25519 private key is exposed through logs, error messages, or memory dumps. |
| I2: Constraint disclosure | Low | An attacker reads the CCL constraints to understand what actions are permitted, enabling targeted exploitation. |
| I3: Metadata leakage | Low | Covenant metadata (names, tags, descriptions) reveals organizational information. |

**Mitigations**:
- I1: Private keys are `Uint8Array` values and are never serialized to JSON or included in `CovenantDocument`. The `KeyPair` type separates `privateKey` from `publicKeyHex`. Key rotation limits the window of exposure. However, runtime memory protection is outside the protocol's scope (see Residual Risks).
- I2: Covenants are designed to be verifiable by third parties. Constraints are not confidential by design. If confidentiality of constraints is required, the application layer must implement encryption before storage.
- I3: Metadata is optional. Operators should populate metadata fields with awareness that covenants may be shared.

### 3.5 Denial of Service

| Threat | Severity | Description |
|---|---|---|
| D1: Constraint bombing | Medium | An attacker submits a covenant with pathologically complex CCL (deeply nested conditions, thousands of statements) to exhaust parser/evaluator resources. |
| D2: Chain depth exhaustion | Medium | An attacker creates a deeply nested chain of covenants to exhaust verification resources. |
| D3: Document size attack | Medium | An attacker submits an extremely large covenant document. |
| D4: Rate limit exhaustion | Low | An attacker rapidly consumes rate-limited actions to deny service to legitimate operations. |

**Mitigations**:
- D1: `MAX_CONSTRAINTS` (1000) caps the number of statements per covenant. The parser rejects input exceeding this limit during both `buildCovenant()` and `verifyCovenant()`.
- D2: `MAX_CHAIN_DEPTH` (16) limits chain traversal. `resolveChain()` stops at this depth.
- D3: `MAX_DOCUMENT_SIZE` (1 MiB) is enforced during build and verification. Documents exceeding this size are rejected.
- D4: The `Monitor` class implements sliding-window rate limiting per action. Rate limit state is per-instance; distributed rate limiting requires an external store.

### 3.6 Elevation of Privilege

| Threat | Severity | Description |
|---|---|---|
| E1: Chain narrowing bypass | Critical | A child covenant broadens permissions beyond what the parent permits. |
| E2: Evaluator bypass | Critical | Application code skips the CCL evaluator and performs actions directly. |
| E3: Role escalation | Medium | A party with role "beneficiary" forges a document claiming role "issuer". |

**Mitigations**:
- E1: `validateChainNarrowing()` verifies that a child covenant only restricts (never broadens) the parent's CCL constraints. `validateChain()` runs this check on every parent-child pair. The CCL `validateNarrowing()` function performs semantic comparison of permit, deny, and limit statements.
- E2: This is an application-level concern. Grith provides `Monitor` (enforce mode throws `MonitorDeniedError` on violations) and `CapabilityGate` (pre-computes permitted actions and refuses to register handlers for non-permitted actions). However, the application must actually use these enforcement mechanisms.
- E3: The `buildCovenant()` function validates that `issuer.role === 'issuer'` and `beneficiary.role === 'beneficiary'`. Verification checks party roles. However, a forged document with correct roles but wrong keys will fail signature verification.

## 4. Residual Risks

The following threats are acknowledged but NOT mitigated by the protocol:

1. **Key management at rest**: Grith does not prescribe how private keys are stored. If keys are stored in plaintext on disk, in environment variables, or in version control, they can be compromised. Operators must use HSMs, secure enclaves, or encrypted key stores.

2. **Side-channel attacks on the runtime**: Timing attacks against the Ed25519 implementation are mitigated by `@noble/ed25519` (which uses constant-time operations), but other side channels (power analysis, cache timing, speculative execution) are outside scope.

3. **Evaluator integrity**: If the CCL evaluator binary is replaced or its behavior is modified at runtime (e.g., through prototype pollution or memory corruption), enforcement is meaningless. The protocol assumes the evaluator runs in a trustworthy execution environment.

4. **Key distribution**: The protocol does not include a PKI or key discovery mechanism. Verifiers must obtain public keys through an authentic out-of-band channel. Incorrect key association defeats all cryptographic guarantees.

5. **Time source integrity**: Expiry checking (`not_expired`, `active`) relies on the system clock. An attacker who can manipulate the system clock can bypass time-based constraints.

6. **Constraint semantics**: The CCL language is designed to be unambiguous, but complex constraint interactions (many overlapping permit/deny rules with conditions) may produce unexpected effective behavior. The `serializeCCL()` and `mergeCCL()` functions help operators inspect effective constraints, but human review of complex policies is recommended.

7. **Quantum computing**: Ed25519 is not quantum-resistant. A future quantum computer with sufficient qubits could forge signatures. This is a known limitation shared with all elliptic-curve cryptography deployed today.

## 5. Security Assumptions

For the protocol's security properties to hold, the following must be true:

1. The issuer's private key is known only to the issuer at the time of signing.
2. The SHA-256 hash function is collision-resistant and preimage-resistant.
3. The Ed25519 signature scheme is existentially unforgeable under chosen-message attack (EU-CMA).
4. The beneficiary runs the verification algorithm faithfully before relying on a covenant.
5. The CCL evaluator implementation is correct and runs in a trusted environment.
6. System clocks are approximately correct (within the tolerance required by expiry/activation windows).
7. Public keys are distributed through authentic channels.

## 6. Cryptographic Primitives

| Primitive | Implementation | Purpose |
|---|---|---|
| Ed25519 | `@noble/ed25519` | Document signing, identity signing, countersignatures |
| SHA-256 | `@noble/hashes/sha256` | Content addressing (document IDs), audit log chaining, Merkle trees |
| CSPRNG | `@noble/hashes/utils.randomBytes` | Nonce generation, key generation, ID generation |
| JCS (RFC 8785) | Custom `canonicalizeJson()` | Deterministic serialization for signing and hashing |
| Constant-time comparison | Custom `constantTimeEqual()` | Timing-safe comparison of hashes and signatures |
