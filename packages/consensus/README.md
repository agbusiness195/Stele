# @nobulex/consensus

Byzantine fault-tolerant consensus protocols for the Nobulex covenant framework. Includes accountability scoring, BFT analysis, quorum computation, latency estimation, a HotStuff-inspired pipelined BFT implementation, dynamic quorum reconfiguration, pipeline simulation, and quorum intersection verification.

## Installation

```bash
npm install @nobulex/consensus
```

## Key APIs

- **computeAccountability(agentId, data, config?)**: Compute a weighted accountability score from protocol data
- **evaluateCounterparty(policy, counterparty)**: Check if an agent meets an interaction policy's requirements
- **byzantineFaultTolerance(totalNodes, requestedFaults?)**: Compute BFT properties (n >= 3f + 1)
- **quorumSize(totalNodes, protocol)**: Minimum quorum for `simple_majority`, `bft`, `two_thirds`, or `unanimous`
- **consensusLatency(params)**: Estimate time to reach consensus given network parameters
- **StreamlinedBFT**: HotStuff-inspired three-phase BFT with leader rotation and pipelining
- **DynamicQuorum**: Epoch-based node join/leave with overlap quorum safety
- **PipelineSimulator**: Simulate message-passing latency/throughput under configurable network conditions
- **QuorumIntersectionVerifier**: Formally verify that all quorum pairs intersect in at least one honest node

## Usage

```typescript
import {
  computeAccountability,
  byzantineFaultTolerance,
  quorumSize,
  StreamlinedBFT,
  DynamicQuorum,
} from '@nobulex/consensus';

// Compute accountability score
const score = computeAccountability('agent-1', {
  covenantCount: 5,
  totalInteractions: 100,
  compliantInteractions: 95,
  stakeAmount: 0.8,
  maxStake: 1.0,
  attestedInteractions: 80,
  canaryTests: 20,
  canaryPasses: 19,
});
console.log(`${score.tier}: ${score.score}`);

// BFT analysis
const bft = byzantineFaultTolerance(10);
console.log(`Max faults: ${bft.maxFaultyNodes}`); // 3

// Quorum size
const q = quorumSize(10, 'bft');
console.log(`BFT quorum: ${q.quorumSize}`); // 7

// Pipelined BFT consensus
const nodes = ['n1', 'n2', 'n3', 'n4'];
const sbft = new StreamlinedBFT(nodes);
const block = sbft.propose('n1', { tx: 'data' }, '0x00');

// Dynamic quorum reconfiguration
const dq = new DynamicQuorum(['n1', 'n2', 'n3']);
dq.requestJoin('n4');
dq.transition(['n1', 'n2', 'n3']);
```

## Types

- `AccountabilityScore` -- Score, tier, and component breakdown
- `AccountabilityTier` -- `'unaccountable' | 'basic' | 'verified' | 'trusted' | 'exemplary'`
- `InteractionPolicy` / `AccessDecision` -- Policy evaluation for counterparties
- `BFTResult` / `QuorumResult` / `ConsensusLatencyResult` -- Analysis results with formula derivations
- `ConsensusProtocol` -- `'simple_majority' | 'bft' | 'two_thirds' | 'unanimous'`
- `Epoch` / `ReconfigRequest` -- Dynamic quorum reconfiguration state

## Docs

See the [Nobulex SDK root documentation](../../README.md) for the full API reference.
