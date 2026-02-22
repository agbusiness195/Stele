# @nobulex/recursive

Recursive covenant structures with self-referential constraints, DAG-based termination proofs, and transitive trust computation.

## Installation

```bash
npm install @nobulex/recursive
```

## Key APIs

- **createMetaCovenant(targetType, constraints, dependsOn?)**: Create a meta-covenant targeting a specific entity type (e.g. `'covenant'`, `'agent'`, `'verifier'`)
- **addLayer(existing, newConstraints)**: Add a constraint layer to an existing meta-covenant, incrementing recursion depth
- **proveTermination(metaCovenants)**: Analyze a chain of meta-covenants for cycles and convergence using DFS-based DAG analysis
- **verifyRecursively(entities, maxDepth)**: Walk a verification chain, producing a `RecursiveVerification` for each layer
- **trustBase()**: Return the irreducible cryptographic trust assumptions (Ed25519, SHA-256)
- **computeTrustTransitivity(edges, source, target, attenuationFactor?)**: Compute effective trust between nodes in a trust graph with per-hop attenuation
- **findMinimalVerificationSet(verifiers, requiredConstraints)**: Greedy set-cover approximation for the smallest set of verifiers covering all constraints

## Usage

```typescript
import {
  createMetaCovenant,
  addLayer,
  proveTermination,
  computeTrustTransitivity,
} from '@nobulex/recursive';

// Build a recursive covenant chain
const base = createMetaCovenant('covenant', ['no-exfiltration']);
const layer1 = addLayer(base, ['rate-limit-enforced']);

// Prove the chain terminates
const proof = proveTermination([base, layer1]);
console.log(proof.converges); // true
console.log(proof.maxDepth);  // 1

// Compute transitive trust through a graph
const trust = computeTrustTransitivity(
  [
    { from: 'alice', to: 'bob', trustScore: 0.9 },
    { from: 'bob', to: 'carol', trustScore: 0.8 },
  ],
  'alice',
  'carol',
  0.9,
);
console.log(trust.effectiveTrust); // ~0.648
console.log(trust.path);          // ['alice', 'bob', 'carol']
```

## Types

- `MetaCovenant`, `MetaTargetType`, `RecursiveVerification`, `TerminationProof`
- `TrustBase`, `TrustEdge`, `TransitiveTrustResult`
- `VerificationEntity`, `VerifierNode`, `MinimalVerificationSetResult`

## Docs

See the [Nobulex SDK root documentation](../../README.md) for the full API reference.
