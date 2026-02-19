# @usekova/reputation

Reputation scoring, stake management, endorsements, and receipt-chain verification for Stele covenant agents.

## Installation

```bash
npm install @usekova/reputation
```

## Key APIs

### Execution Receipts
- **createReceipt(...)**: Create a signed execution receipt recording a covenant outcome
- **verifyReceipt(receipt)**: Verify receipt integrity and agent signature
- **countersignReceipt(receipt, principalKeyPair)**: Add a principal countersignature
- **verifyReceiptChain(receipts)**: Validate that receipts form a valid hash chain
- **computeReceiptsMerkleRoot(receipts)**: Compute a Merkle root over receipt hashes

### Reputation Scoring
- **computeReputationScore(agentIdentityHash, receipts, endorsements?, config?)**: Compute a weighted reputation score with recency decay, breach penalties, and endorsement blending
- **DEFAULT_SCORING_CONFIG**: Default scoring parameters (decay rate, breach penalties, etc.)

### Stakes & Delegation
- **createStake(agentIdentityHash, covenantId, amount, keyPair)**: Create a signed reputation stake
- **releaseStake(stake, outcome)** / **burnStake(stake)**: Resolve a stake after execution
- **createDelegation(...)**: Create a dual-signed reputation delegation between sponsor and protege
- **burnDelegation(delegation)** / **coBurnDelegation(delegation, sponsorScore)**: Burn delegation on breach with sponsor impact

### Endorsements
- **createEndorsement(...)**: Create a signed peer endorsement with empirical basis
- **verifyEndorsement(endorsement)**: Verify endorsement integrity and signature

### Advanced
- **ReceiptDAG**: DAG structure for concurrent execution paths with `addNode`, `findCommonAncestors`, and `computeDAGReputation`
- **ReputationDecayModel**: Multi-model decay (exponential, Weibull, gamma distributions)
- **GraduatedBurner**: Proportional stake burning based on severity and agent history
- **ReputationAggregator**: Byzantine-tolerant weighted median aggregation across multiple sources

## Usage

```typescript
import { createReceipt, computeReputationScore, createStake } from '@usekova/reputation';
import { generateKeyPair } from '@usekova/crypto';

const keys = await generateKeyPair();

// Record an execution receipt
const receipt = await createReceipt(
  covenantId, agentIdentityHash, principalPubKey,
  'fulfilled', proofHash, 150, keys,
);

// Compute reputation from receipts
const score = computeReputationScore(agentIdentityHash, [receipt]);
console.log(score.weightedScore); // 0.0 - 1.0
console.log(score.successRate);   // 1.0

// Stake reputation on a covenant
const stake = await createStake(agentIdentityHash, covenantId, 0.5, keys);
```

## Types

- `ExecutionReceipt`, `ReputationScore`, `ReputationStake`
- `ReputationDelegation`, `Endorsement`, `ScoringConfig`
- `ReceiptDAGNode`, `DecayModelConfig`, `GraduatedBurnConfig`
- `ReputationSource`, `DecayModelType`

## Docs

See the [Stele SDK root documentation](../../README.md) for the full API reference.
