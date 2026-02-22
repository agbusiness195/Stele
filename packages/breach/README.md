# @kervyx/breach

Breach detection, trust graph propagation, lifecycle tracking, and reputation recovery.

## Installation

```bash
npm install @kervyx/breach
```

## Key APIs

- **createBreachAttestation(covenantId, violatorIdentityHash, violatedConstraint, severity, action, resource, evidenceHash, affectedCovenants, reporterKeyPair)**: Create and cryptographically sign a breach attestation
- **verifyBreachAttestation(attestation)**: Verify a breach attestation's content hash and reporter signature
- **TrustGraph**: Directed dependency graph that tracks trust status per agent, processes breaches with BFS propagation to transitive dependents, and emits breach events
- **ExponentialDegradation**: Computes trust loss that decays exponentially over graph hops (`baseLoss * e^(-lambda * hop)`)
- **BreachStateMachine**: Tracks breach lifecycle through DETECTED -> CONFIRMED -> REMEDIATED -> RECOVERED with evidence, timeouts, and auto-transitions
- **RecoveryModel**: Logistic curve modeling of trust recovery over time, parameterized by severity and historical reliability
- **RepeatOffenderDetector**: Tracks per-agent breach patterns, detects severity escalation, and applies progressive penalties (warning -> restriction -> revocation)

## Usage

```typescript
import {
  createBreachAttestation,
  verifyBreachAttestation,
  TrustGraph,
  ExponentialDegradation,
  BreachStateMachine,
  RecoveryModel,
  RepeatOffenderDetector,
} from '@kervyx/breach';

// Create and verify a breach attestation
const attestation = await createBreachAttestation(
  covenantId, violatorHash, 'deny * on /secrets/**',
  'critical', 'read', '/secrets/key', evidenceHash,
  [covenantId], reporterKeyPair,
);
const valid = await verifyBreachAttestation(attestation);

// Process breach through trust graph with propagation
const graph = new TrustGraph();
graph.registerDependency(parentHash, childHash);
const events = await graph.processBreach(attestation);
console.log(graph.getStatus(violatorHash)); // 'revoked'

// Exponential trust degradation across hops
const degradation = new ExponentialDegradation({ baseLoss: 0.8, lambda: 0.5 });
console.log(degradation.degrade(1.0, 0)); // 0.2 (full loss at origin)
console.log(degradation.degrade(1.0, 3)); // ~0.78 (minimal loss at hop 3)
console.log(degradation.effectiveRadius(0.01)); // max hop where loss >= 0.01

// Track breach lifecycle
const sm = new BreachStateMachine('breach-1', { detectedTimeoutMs: 60000 });
sm.transition('confirmed', 'admin', [{ type: 'log', hash: '...', description: 'Confirmed by admin' }]);
sm.transition('remediated', 'admin', []);
sm.transition('recovered', 'admin', []);
console.log(sm.isResolved()); // true

// Detect repeat offenders
const detector = new RepeatOffenderDetector({ warningThreshold: 2 });
detector.recordBreach('agent-1', breachRecord);
const profile = detector.analyze('agent-1');
console.log(profile.penalty);         // 'none' | 'warning' | 'restriction' | 'revocation'
console.log(profile.dominantPattern); // most common resource:action pattern
```

## Docs

See the [Kervyx SDK root documentation](../../README.md) for the full API reference.
