# @grith/attestation

Multi-party attestation creation, signing, verification, and reconciliation.

## Installation

```bash
npm install @grith/attestation
```

## Key APIs

- **createAttestation(agentId, counterpartyId, endpoint, inputHash, outputHash, interactionHash, timestamp)**: Create an `ExternalAttestation` with a deterministic content-addressed ID
- **signAttestation(attestation, privateKey)**: Sign an attestation with an Ed25519 private key
- **verifyAttestation(attestation, publicKey)**: Verify the counterparty signature against the attestation content
- **isSigned(attestation)**: Check whether an attestation has been signed
- **reconcile(receipt, attestation)**: Compare an agent's receipt against a counterparty attestation, returning match status and discrepancies
- **getDiscrepancies(receipt, attestation)**: Detailed field-by-field comparison (interactionHash, inputHash, outputHash, endpoint, timestamp) with severity levels
- **attestationChainVerify(chain)**: Verify a chain of attestations with signature validation, temporal ordering, and chain continuity checks
- **computeAttestationCoverage(actions, attestations, timeWindowMs?)**: Compute what percentage of an agent's actions are covered by attestations

## Usage

```typescript
import {
  createAttestation,
  signAttestation,
  verifyAttestation,
  reconcile,
  attestationChainVerify,
  computeAttestationCoverage,
} from '@grith/attestation';

// Create and sign an attestation
const attestation = createAttestation(
  'agent-1', 'counterparty-1', '/api/data',
  'inputHash123', 'outputHash456', 'interactionHash789',
  Date.now(),
);
const signed = await signAttestation(attestation, counterpartyPrivateKey);

// Verify the signature
const valid = await verifyAttestation(signed, counterpartyPublicKey);
console.log(valid); // true

// Reconcile agent receipt against counterparty attestation
const result = reconcile(receipt, signed);
console.log(result.match);          // true if all fields agree
console.log(result.discrepancies);  // array of { field, severity, agentClaimed, counterpartyClaimed }

// Verify a multi-party attestation chain
const chainResult = await attestationChainVerify(chain);
console.log(chainResult.valid);         // true if all links verify
console.log(chainResult.verifiedLinks); // number of successfully verified links

// Measure attestation coverage of agent actions
const coverage = computeAttestationCoverage(actions, attestations, 5000);
console.log(coverage.coveragePercentage); // percentage of actions covered
```

## Docs

See the [Grith SDK root documentation](../../README.md) for the full API reference.
