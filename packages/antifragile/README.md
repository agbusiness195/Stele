# @usekova/antifragile

Antifragility analysis with stress testing, recovery metrics, and evolutionary antibody fitness.

## Installation

```bash
npm install @usekova/antifragile
```

## Key APIs

- **generateAntibody(breach, adoptionThreshold?)**: Analyze a breach and generate a defensive constraint (antibody) to prevent recurrence
- **adoptAntibody(antibody)**: Adopt an antibody after it meets the vote threshold
- **forceAdopt(antibody)**: Governance override to adopt an antibody regardless of votes
- **rejectAntibody(antibody)**: Mark an antibody as rejected
- **voteForAntibody(antibody)**: Increment an antibody's adoption vote count
- **antibodyExists(antibodies, breach)**: Check if a matching antibody already exists
- **proposeToGovernance(antibody)**: Wrap an antibody in a governance proposal
- **networkHealth(antibodies, breaches)**: Compute resistance score and find vulnerable categories
- **stressTest(baseBreaches, rounds?, intensityMultiplier?)**: Simulate escalating attack waves and measure resistance over time
- **antifragilityIndex(breaches, waves?)**: Quantify system antifragility as a normalized index (-1 fragile to +1 antifragile)
- **calibratedAntifragilityIndex(breaches, waves?, confidenceLevel?)**: Statistically calibrated z-score index with confidence intervals and p-values
- **StressResponseCurve**: Nonlinear stress response modeling (logistic, exponential, threshold curves)
- **PhaseTransitionDetector**: Detect tipping points via rolling-window variance and lag-1 autocorrelation
- **FitnessEvolution**: Evolutionary engine with tournament selection, crossover, and mutation for antibody populations

## Usage

```typescript
import {
  generateAntibody,
  forceAdopt,
  networkHealth,
  stressTest,
  antifragilityIndex,
  StressResponseCurve,
} from '@usekova/antifragile';

// Generate an antibody from a detected breach
const antibody = generateAntibody({
  id: 'breach-1',
  violatedConstraint: 'deny:secret-access',
  severity: 'high',
  category: 'secrets',
});

// Force-adopt via governance and check network health
const adopted = forceAdopt(antibody);
const health = networkHealth([adopted], [breach]);
console.log(health.resistanceScore);       // ratio of adopted antibodies to breaches
console.log(health.vulnerableCategories);  // categories lacking adopted antibodies

// Run a stress test simulation
const result = stressTest([breach], 5, 2);
console.log(result.improved);              // true if system got stronger
console.log(result.resistanceOverTime);    // resistance score per round

// Compute antifragility index
const index = antifragilityIndex([breach], 5);
console.log(index.classification); // 'antifragile' | 'robust' | 'fragile'

// Model nonlinear stress response
const curve = new StressResponseCurve({ inflectionPoint: 0.5, steepness: 5, saturation: 1 });
console.log(curve.logistic(0.8)); // S-curve response at stress level 0.8
```

## Docs

See the [Kova SDK root documentation](../../README.md) for the full API reference.
