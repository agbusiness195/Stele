# @grith/proof

Compliance proof generation and verification using Poseidon hash commitments over audit logs and covenant constraints.

## Installation

```bash
npm install @grith/proof
```

## Key APIs

- **generateComplianceProof(options)**: Generate a compliance proof binding audit entries to covenant constraints via chained Poseidon hashing
- **verifyComplianceProof(proof)**: Verify proof integrity with 5-step checks (format, public inputs, audit commitment, constraint commitment, proof recomputation)
- **computeAuditCommitment(entries)**: Compute a chained Poseidon commitment over audit log entries
- **computeConstraintCommitment(constraints)**: Compute a Poseidon commitment over a CCL constraint string
- **poseidonHash(inputs)**: Low-level Poseidon hash over field elements
- **hashToField(hex)**: Convert a hex-encoded hash to a field element
- **fieldToHex(field)**: Convert a field element to hex
- **FIELD_PRIME**: The BN254 scalar field prime

## Usage

```typescript
import {
  generateComplianceProof,
  verifyComplianceProof,
} from '@grith/proof';

// Generate a proof that audit entries comply with constraints
const proof = await generateComplianceProof({
  covenantId: 'ab12cd34ef56',
  constraints: 'permit read on "/data/**"',
  auditEntries: [
    { hash: 'aabbccdd0011' },
    { hash: 'eeff00112233' },
  ],
  proofSystem: 'poseidon_hash',
});

console.log(proof.proof);              // Hex-encoded Poseidon proof
console.log(proof.auditLogCommitment); // Chained commitment over entries
console.log(proof.publicInputs);       // [covenantId, auditCommitment, constraintCommitment, entryCount]

// Verify the proof
const result = await verifyComplianceProof(proof);
console.log(result.valid);   // true
console.log(result.errors);  // []
```

## Docs

See the [Grith SDK root documentation](../../README.md) for the full API reference.
