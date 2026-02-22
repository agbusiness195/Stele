# @nobulex/canary

Canary token generation, tripwire evaluation, scheduling, and breach correlation analysis.

## Installation

```bash
npm install @nobulex/canary
```

## Key APIs

- **generateCanary(targetCovenantId, constraintTested, challenge?, expectedBehavior?, ttlMs?)**: Generate a canary test from a CCL constraint, auto-deriving the challenge payload and expected behavior
- **evaluateCanary(canary, agentResponse)**: Evaluate an agent's response against a canary using CCL evaluation, returning pass/fail with breach evidence
- **isExpired(canary)**: Check whether a canary has exceeded its TTL
- **detectionProbability(canaryFrequency, coverageRatio)**: Compute the probability of detecting a violation given canary count and per-canary coverage
- **canarySchedule(covenants, totalDurationMs?, maxCanaries?)**: Generate a prioritized deployment schedule across covenants, ordering by constraint type (deny > require > limit > permit)
- **canaryCorrelation(canaryResults, actualBreaches)**: Measure Pearson correlation between canary failure rates and actual breach rates per covenant

## Usage

```typescript
import {
  generateCanary,
  evaluateCanary,
  detectionProbability,
  canarySchedule,
  canaryCorrelation,
} from '@nobulex/canary';

// Generate a canary from a CCL constraint
const canary = generateCanary(
  'covenant-1',
  "deny * on '/secrets/**'",
);
console.log(canary.expectedBehavior); // 'deny'

// Evaluate an agent's response
const result = evaluateCanary(canary, {
  behavior: 'permit',
  action: '*',
  resource: '/secrets/key',
});
console.log(result.passed);          // false - agent permitted what should be denied
console.log(result.breachEvidence);  // description of the failure

// Compute detection probability for 10 canaries at 30% coverage each
const prob = detectionProbability(10, 0.3);
console.log(prob); // ~0.972

// Schedule canaries across multiple covenants
const schedule = canarySchedule([
  { covenantId: 'cov-1', constraints: ["deny * on '/secrets/**'", "permit read on '/public/**'"] },
  { covenantId: 'cov-2', constraints: ["require audit_log on '**'"] },
], 3600000, 10);
console.log(schedule.schedule);           // ordered deployment entries with timing offsets
console.log(schedule.estimatedCoverage);  // fraction of total constraints covered

// Correlate canary results with actual breaches
const correlation = canaryCorrelation(canaryResults, actualBreaches);
console.log(correlation.correlation); // Pearson r between failure rates and breach rates
console.log(correlation.meaningful);  // true if sample size >= 3
```

## Docs

See the [Nobulex SDK root documentation](../../README.md) for the full API reference.
