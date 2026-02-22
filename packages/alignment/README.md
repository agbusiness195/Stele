# @kervyx/alignment

Value alignment verification and normative constraint enforcement for AI agents.

## Installation

```bash
npm install @kervyx/alignment
```

## Key APIs

- **defineAlignment(agentId, properties, verificationMethod?)**: Create an `AlignmentCovenant` from a set of alignment properties with union of all constraints
- **assessAlignment(agentId, covenant, history)**: Score how well execution history matches alignment properties using real CCL evaluation and severity-weighted breach scoring
- **alignmentGap(desired, actual)**: Find properties whose constraints are missing from an actual constraint set
- **alignmentDrift(agentId, covenant, history, windowCount?, driftThreshold?)**: Detect gradual misalignment by splitting history into time windows and measuring score trends
- **alignmentDecomposition(agentId, covenant, history)**: Break down overall alignment into per-property contributions, identifying weakest and strongest areas
- **AdaptiveAlignmentTracker**: EMA-based learnable weights that shift focus toward frequently violated properties
- **PropertyAnomalyDetector**: Robust outlier detection for alignment scores using modified z-scores (MAD-based)
- **DriftForecaster**: Predict future alignment scores via linear regression or Holt's double exponential smoothing
- **AlignmentSurface**: Multi-dimensional alignment surface analysis with per-dimension gradients and distance-from-ideal metrics
- **AlignmentFeedbackLoop**: Closed-loop controller that auto-adjusts thresholds and weights from observed outcomes
- **STANDARD_ALIGNMENT_PROPERTIES**: Pre-built HHH (Helpful, Honest, Harmless) property definitions

## Usage

```typescript
import {
  defineAlignment,
  assessAlignment,
  alignmentDrift,
  STANDARD_ALIGNMENT_PROPERTIES,
  AdaptiveAlignmentTracker,
} from '@kervyx/alignment';

// Define alignment for an agent using standard HHH properties
const covenant = defineAlignment('agent-1', STANDARD_ALIGNMENT_PROPERTIES, 'behavioral');

// Assess alignment against execution history
const report = assessAlignment('agent-1', covenant, [
  { action: 'read', resource: '/data', outcome: 'fulfilled', timestamp: 1000 },
  { action: '*', resource: '/secrets/key', outcome: 'breached', timestamp: 2000, severity: 'critical' },
]);

console.log(report.overallAlignmentScore); // 0-1 score
console.log(report.gaps);                 // properties below 0.5

// Detect alignment drift over time
const drift = alignmentDrift('agent-1', covenant, history, 5, 0.1);
console.log(drift.trend);         // 'improving' | 'stable' | 'degrading'
console.log(drift.driftDetected); // true if any window drop > threshold

// Adaptive weights that learn from violations
const tracker = new AdaptiveAlignmentTracker(STANDARD_ALIGNMENT_PROPERTIES, 0.3);
tracker.recordObservation({ propertyName: 'harmlessness', severity: 8, timestamp: Date.now() });
console.log(tracker.getWeights()); // weights shifted toward harmlessness
```

## Docs

See the [Kervyx SDK root documentation](../../README.md) for the full API reference.
