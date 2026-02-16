# @stele/protocols

Unified facade for all 20 [Stele](https://stele.dev) protocol modules. One import for breach detection, reputation, game theory, consensus, and more.

## Install

```bash
npm install @stele/protocols
```

## Quick Start

```typescript
import {
  proveHonesty,
  computeReputationScore,
  generateCanary,
  byzantineFaultTolerance,
} from '@stele/protocols';

// Prove an agent's honesty given game-theoretic parameters
const proof = proveHonesty({ stake: 1000, reward: 50, penalty: 500, detection: 0.95 });

// Compute reputation from execution receipts
const score = computeReputationScore(receipts);

// Generate a canary token for covenant monitoring
const canary = generateCanary({ covenantId, challenge: payload, keyPair });

// Verify Byzantine fault tolerance properties
const bft = byzantineFaultTolerance({ nodes: 10, maxFaulty: 3 });
```

## Protocol Modules

| Module | Focus | Key Exports |
|--------|-------|-------------|
| **Breach** | Violation detection and response | `BreachStateMachine`, `TrustGraph`, `createPlaybook` |
| **Reputation** | Stake-weighted trust scoring | `computeReputationScore`, `createReceipt`, `ReceiptDAG` |
| **Game Theory** | Mechanism design and Nash equilibria | `proveHonesty`, `mechanismDesign`, `coalitionStability` |
| **Consensus** | Byzantine fault tolerance | `StreamlinedBFT`, `DynamicQuorum`, `byzantineFaultTolerance` |
| **Attestation** | Multi-party attestation | `createAttestation`, `verifyAttestation`, `buildEntanglementNetwork` |
| **Canary** | Dead-man's-switch monitoring | `generateCanary`, `evaluateCanary`, `isCanaryExpired` |
| **Proof** | Zero-knowledge compliance | `generateComplianceProof`, `verifyComplianceProof`, `poseidonHash` |
| **Composition** | Covenant composition algebra | `compose`, `trustCompose`, `defineSafetyEnvelope` |
| **Alignment** | Value alignment verification | `defineAlignment`, `assessAlignment`, `AlignmentSurface` |
| **Negotiation** | Multi-party bargaining | `initiateNegotiation`, `computeNashBargainingSolution`, `ConcessionProtocol` |
| **Temporal** | Time-based constraints | `defineEvolution`, `DecayModel`, `ViolationForecaster` |
| **Robustness** | Fuzzing and formal verification | `fuzz`, `formalVerification`, `robustnessScore` |
| **Recursive** | Meta-covenants | `createMetaCovenant`, `verifyRecursively`, `proveTermination` |
| **Discovery** | `.well-known/stele/` protocol | `DiscoveryServer`, `DiscoveryClient`, `createFederationConfig` |
| **Schema** | JSON Schema validation | `validateCovenantSchema`, `COVENANT_SCHEMA`, `AGENT_KEY_SCHEMA` |
| **Antifragile** | Stress testing | `stressTest`, `generateAntibody`, `PhaseTransitionDetector` |
| **Norms** | Social norm modeling | `analyzeNorms`, `discoverNorms`, `normConflictDetection` |
| **Substrate** | Cross-platform translation | `createAdapter`, `physicalCovenant`, `substrateCompatibility` |
| **Derivatives** | Trust futures and insurance | `assessRisk`, `priceInsurance`, `blackScholesPrice` |
| **Legal** | Jurisdiction and compliance | `exportLegalPackage`, `crossJurisdictionCompliance`, `ComplianceSurface` |

## Examples

### Breach Detection

```typescript
import { BreachStateMachine, TrustGraph, createPlaybook } from '@stele/protocols';

const sm = new BreachStateMachine(covenantId);
sm.transition('detected', 'monitor');
sm.transition('confirmed', 'analyst');

const graph = new TrustGraph();
graph.addNode({ agentId: 'agent-1', trustScore: 0.8, status: 'active' });
```

### Reputation

```typescript
import { createReceipt, verifyReceipt, computeProfile, assignTier } from '@stele/protocols';

const receipt = createReceipt({ agentId, covenantId, outcome: 'success', keyPair });
const verified = await verifyReceipt(receipt);
const tier = assignTier(computeProfile(agent)); // 'bronze' | 'silver' | 'gold' | 'platinum'
```

### Game Theory

```typescript
import { proveHonesty, mechanismDesign } from '@stele/protocols';

const proof = proveHonesty({ stake: 1000, reward: 50, penalty: 500, detection: 0.95 });
console.log(proof.isHonest); // true — honest behavior is the dominant strategy
```

### Consensus

```typescript
import { StreamlinedBFT, byzantineFaultTolerance } from '@stele/protocols';

const bft = new StreamlinedBFT({ nodeCount: 7, faultyNodes: 2 });
const result = byzantineFaultTolerance({ nodes: 10, maxFaulty: 3 });
```

### Discovery

```typescript
import { DiscoveryClient, buildDiscoveryDocument, WELL_KNOWN_PATH } from '@stele/protocols';

const client = new DiscoveryClient({ baseUrl: 'https://agent.example.com' });
const doc = buildDiscoveryDocument({ agentId: 'agent-1', keys: [keyEntry] });
// Serves at .well-known/stele/discovery.json
```

## Related Packages

| Package | Use case |
|---------|----------|
| [`@stele/sdk`](../sdk) | Core client, crypto, CCL, middleware, adapters |
| [`@stele/enterprise`](../enterprise) | Enterprise features (analytics, payments, governance, certification) |

## License

MIT
