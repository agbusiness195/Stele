# @stele/robustness

Robustness analysis for Stele covenants: fuzz testing, formal verification, adversarial input generation, and composite scoring.

## Installation

```bash
npm install @stele/robustness
```

## Key APIs

- **proveRobustness(covenant, constraint, bounds, options?)**: Prove a constraint holds across an input space using exhaustive or statistical testing. Returns a `RobustnessProof` with confidence and optional counterexample.
- **fuzz(covenant, iterations, options?)**: Fuzz test all constraints in a covenant with random inputs. Returns a `RobustnessReport` with vulnerabilities and overall robustness score.
- **formalVerification(covenant)**: Symbolic analysis detecting permit/deny contradictions and unreachable rules. Returns `FormalVerificationResult`.
- **generateAdversarialInputs(constraint, count)**: Generate boundary-probing inputs (empty strings, case flips, path traversals, numeric boundaries) for a CCL constraint.
- **robustnessScore(covenant, fuzzIterations?)**: Composite 0-1 score combining consistency, fuzz resilience, type coverage, and specificity with actionable recommendations.
- **assessSeverity(constraint)**: Map a constraint type to a severity level (`critical` | `high` | `medium` | `low`).

## Usage

```typescript
import { fuzz, formalVerification, robustnessScore } from '@stele/robustness';

const covenant = {
  id: 'cov-1',
  constraints: [
    { rule: "deny data.delete on '/secrets' when role = 'reader'", type: 'deny', action: 'data.delete', resource: '/secrets' },
    { rule: "permit data.read on '/public'", type: 'permit', action: 'data.read', resource: '/public' },
  ],
};

// Fuzz test all constraints
const report = fuzz(covenant, 100);
console.log(report.overallRobustness);  // 0.0 - 1.0
console.log(report.vulnerabilities);

// Check for contradictions
const verification = formalVerification(covenant);
console.log(verification.consistent);       // true
console.log(verification.contradictions);    // []

// Get a composite robustness score
const result = robustnessScore(covenant);
console.log(result.score);           // 0.0 - 1.0
console.log(result.classification);  // 'strong' | 'moderate' | 'weak'
console.log(result.recommendations);
```

## Types

- `RobustnessProof`, `RobustnessReport`, `Vulnerability`
- `FormalVerificationResult`, `Contradiction`
- `RobustnessScoreResult`, `RobustnessFactor`
- `CovenantSpec`, `ConstraintSpec`, `InputBound`, `RobustnessOptions`

## Docs

See the [Stele SDK root documentation](../../README.md) for the full API reference.
