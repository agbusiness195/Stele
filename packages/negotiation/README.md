# @nobulex/negotiation

Multi-party covenant negotiation with Nash bargaining, Zeuthen strategies, Pareto frontier analysis, and concession protocols.

## Installation

```bash
npm install @nobulex/negotiation
```

## Key APIs

- **initiate(initiatorId, responderId, policy)**: Start a new negotiation session
- **propose(session, proposal)**: Add a proposal to an existing session
- **counter(session, counterProposal)**: Submit a counter-proposal (enforces max rounds)
- **agree(session)**: Finalize a session with deny-wins constraint intersection
- **evaluate(proposal, policy)**: Evaluate a proposal against a policy (`'accept' | 'reject' | 'counter'`)
- **fail(session, reason)**: Mark a session as failed
- **computeNashBargainingSolution(outcomes, utilityA, utilityB)**: 2-party Nash bargaining solution
- **computeNPartyNash(outcomes, utilities, powers?, config?)**: Generalized N-party Nash bargaining with configurable bargaining powers
- **paretoFrontier(outcomes, utilityFunctions)**: Compute Pareto-optimal outcomes
- **zeuthenStrategy(proposalA, proposalB, utilityA, utilityB)**: Determine which party should concede based on risk of conflict
- **runZeuthenNegotiation(outcomes, utilityA, utilityB, maxRounds?)**: Run a full Zeuthen negotiation to convergence
- **ConcessionProtocol**: State machine with deadline pressure, configurable concession rates, and linear/exponential pressure functions
- **IncrementalParetoFrontier**: Incrementally maintained Pareto frontier with efficient dominance checking

## Usage

```typescript
import { initiate, propose, evaluate, agree } from '@nobulex/negotiation';
import type { NegotiationPolicy, Proposal } from '@nobulex/negotiation';

const policy: NegotiationPolicy = {
  requiredConstraints: ['deny:exfiltrate-data'],
  preferredConstraints: ['require:audit-logging'],
  dealbreakers: ['permit:unrestricted-access'],
  maxRounds: 5,
  timeoutMs: 30_000,
};

// Start negotiation
let session = initiate('agent-a', 'agent-b', policy);

// Responder submits a counter-proposal
const counterProposal: Proposal = {
  from: 'agent-b',
  constraints: ['deny:exfiltrate-data', 'permit:read-public'],
  requirements: ['deny:exfiltrate-data'],
  timestamp: Date.now(),
};

// Evaluate against our policy
const decision = evaluate(counterProposal, policy); // 'accept' | 'reject' | 'counter'

if (decision === 'accept') {
  session = propose(session, counterProposal);
  session = agree(session);
  console.log(session.resultingConstraints);
}
```

## Docs

See the [Nobulex SDK root documentation](../../README.md) for the full API reference.
