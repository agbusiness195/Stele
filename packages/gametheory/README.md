# @usekova/gametheory

Game-theoretic analysis for covenant systems, including Nash equilibria, mechanism design, and coalition stability.

## Installation

```bash
npm install @usekova/gametheory
```

## Key APIs

- **proveHonesty()**: Proves whether honesty is the dominant strategy given stake, detection probability, reputation, and violation gain parameters. Returns a structured proof with step-by-step derivation.
- **minimumStake()**: Computes the minimum stake required for honesty to dominate.
- **minimumDetection()**: Computes the minimum detection probability required for honesty to dominate.
- **expectedCostOfBreach()**: Computes the expected cost an agent incurs from a breach.
- **honestyMargin()**: Computes the margin by which honesty dominates (positive = dominant).
- **repeatedGameEquilibrium()**: Folk Theorem analysis for infinitely repeated games -- determines whether cooperation is sustainable as a subgame-perfect Nash equilibrium.
- **coalitionStability()**: Checks whether an allocation is in the core of a cooperative game by enumerating all coalitions for blocking.
- **mechanismDesign()**: Computes the minimum penalty for incentive-compatible honest behavior using the Revelation Principle.
- **validateParameters()**: Validates honesty parameter ranges.

## Usage

```typescript
import { proveHonesty, repeatedGameEquilibrium, mechanismDesign } from '@usekova/gametheory';

// Prove honesty is the dominant strategy
const proof = proveHonesty({
  stakeAmount: 1000,
  detectionProbability: 0.8,
  reputationValue: 200,
  maxViolationGain: 500,
  coburn: 100,
});
console.log(proof.isDominantStrategy); // true
console.log(proof.margin);            // 600

// Folk Theorem: can cooperation be sustained?
const game = repeatedGameEquilibrium({
  cooperatePayoff: 3,
  defectPayoff: 1,
  temptationPayoff: 5,
  suckerPayoff: 0,
  discountFactor: 0.9,
});
console.log(game.cooperationSustainable); // true

// Mechanism design: minimum penalty for honesty
const mechanism = mechanismDesign({
  dishonestGain: 100,
  detectionProbability: 0.5,
});
console.log(mechanism.minimumPenalty); // 200
```

## Docs

See the [Kova SDK root documentation](../../README.md) for the full API reference.
