# @usekova/temporal

Temporal constraint modeling -- decay functions, evolution policies, continuous trigger scoring, violation forecasting, and temporal constraint algebra.

## Installation

```bash
npm install @usekova/temporal
```

## Key APIs

- **defineEvolution(covenantId, triggers, transitions, governanceApproval?)**: Create an `EvolutionPolicy` with validated triggers and transition functions.
- **evaluateTriggers(covenant, agentState)**: Evaluate all policy triggers against current agent state. Returns fired triggers.
- **canEvolve(covenant, trigger)**: Check whether a trigger can fire, respecting cooldowns and governance requirements.
- **evolve(covenant, trigger)**: Apply a trigger action (tighten/relax/add/remove constraint). Returns updated state and event.
- **evolutionHistory(covenant)**: Retrieve the full evolution event log.
- **computeDecaySchedule(initialWeight, decayRate, lifetimeMs, steps)**: Generate an exponential decay schedule as `DecayPoint[]`.
- **expirationForecast(initialWeight, decayRate, violations, currentTime, ...)**: Predict when a covenant will functionally expire based on violation patterns.
- **DecayModel**: Multi-model decay (exponential, linear, step, seasonal) with composition, scheduling, and threshold detection.
- **ContinuousTrigger**: Sigmoid-based soft trigger scoring instead of hard boolean thresholds. Weighted multi-trigger evaluation.
- **ViolationForecaster**: Holt-Winters double exponential smoothing to forecast future violation rates with confidence bands.
- **TemporalConstraintAlgebra**: Set operations (intersection, union, difference) on weighted temporal constraint intervals.

## Usage

### Decay modeling

```typescript
import { DecayModel, computeDecaySchedule } from '@usekova/temporal';

// Simple exponential decay schedule
const schedule = computeDecaySchedule(1.0, 2.0, 86_400_000, 10);

// Composed decay: exponential with seasonal overlay
const model = new DecayModel([
  { type: 'exponential', rate: 1.5 },
  { type: 'seasonal', rate: 4, amplitude: 0.1 },
]);
const weight = model.evaluate(0.5); // value at midpoint
const threshold = model.findThresholdTime(1.0, 0.1); // when weight drops below 0.1
```

### Evolution policies

```typescript
import { defineEvolution, evaluateTriggers, evolve } from '@usekova/temporal';

const policy = defineEvolution('cov-123', [
  { type: 'breach_event', action: 'tighten', condition: 'any', constraintId: 'strict-mode' },
  { type: 'reputation_threshold', action: 'relax', condition: '>90', constraintId: 'relaxed' },
], [
  { fromConstraint: 'default', toConstraint: 'strict-mode', cooldown: 60_000 },
]);

const fired = evaluateTriggers(covenantState, agentState);
if (fired.length > 0) {
  const { covenant: updated, event } = evolve(covenantState, fired[0]!);
}
```

### Violation forecasting

```typescript
import { ViolationForecaster } from '@usekova/temporal';

const forecaster = new ViolationForecaster({
  alpha: 0.3,
  beta: 0.1,
  forecastPeriods: 5,
});

const result = forecaster.forecast([2, 3, 5, 4, 7, 6, 9]);
// result.direction => 'increasing'
// result.forecasts => [{period, rate, upperBound, lowerBound}, ...]
```

### Temporal constraint algebra

```typescript
import { TemporalConstraintAlgebra } from '@usekova/temporal';

const algebra = new TemporalConstraintAlgebra();
const result = algebra.intersection(
  [{ id: 'a', start: 0, end: 0.6, weight: 0.8, constraintRef: 'rule-A' }],
  [{ id: 'b', start: 0.3, end: 1, weight: 0.5, constraintRef: 'rule-B' }],
);
// result.constraints => overlap [0.3, 0.6] with weight 0.8
```

## Docs

See the [Kova SDK root documentation](../../README.md) for the full API reference.
